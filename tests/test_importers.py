import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from librepost import importers, leakcheck, runner
from librepost.httpfile import Request, dumps, parse
from librepost.importers import ImporterError, curl, detect
from librepost.workspace import Workspace

FAKE_TOKEN = "fake-collection-token-1"
FAKE_PASSWORD = "fake-admin-password"
FAKE_KEY = "fake-api-key-12345"

COLLECTION: dict[str, Any] = {
    "info": {
        "name": "Acme API",
        "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
    },
    "auth": {
        "type": "bearer",
        "bearer": [{"key": "token", "value": "{{token}}", "type": "string"}],
    },
    "variable": [
        {"key": "baseUrl", "value": "https://api.example.invalid"},
        {"key": "token", "value": FAKE_TOKEN},
    ],
    "item": [
        {
            "name": "Health",
            "request": {"method": "GET", "url": "{{baseUrl}}/health", "auth": {"type": "noauth"}},
        },
        {
            "name": "Login",
            "request": {
                "method": "POST",
                "url": {"raw": "{{baseUrl}}/login"},
                "body": {
                    "mode": "urlencoded",
                    "urlencoded": [
                        {"key": "user", "value": "ada lovelace"},
                        {"key": "skip", "value": "x", "disabled": True},
                    ],
                },
            },
        },
        {
            "name": "Users",
            "item": [
                {
                    "name": "List users",
                    "event": [{"listen": "test", "script": {"exec": ["pm.test('ok')"]}}],
                    "request": {
                        "method": "GET",
                        "url": {"raw": "{{baseUrl}}/users?page=1"},
                        "header": [
                            {"key": "Accept", "value": "application/json"},
                            {"key": "X-Off", "value": "1", "disabled": True},
                        ],
                    },
                },
                {
                    "name": "Get user",
                    "request": {
                        "method": "GET",
                        "url": {
                            "raw": "{{baseUrl}}/users/:id/posts/:postId",
                            "variable": [{"key": "id", "value": "42"}, {"key": "postId"}],
                        },
                    },
                },
                {
                    "name": "Create user",
                    "request": {
                        "method": "POST",
                        "url": "{{baseUrl}}/users",
                        "body": {
                            "mode": "raw",
                            "raw": '{"name": "{{$randomFirstName}}"}',
                            "options": {"raw": {"language": "json"}},
                        },
                    },
                },
                {
                    "name": "Admin",
                    "auth": {
                        "type": "basic",
                        "basic": {"username": "admin", "password": FAKE_PASSWORD},
                    },
                    "item": [
                        {
                            "name": "Stats",
                            "request": {"method": "GET", "url": "{{baseUrl}}/admin/stats"},
                        },
                        {
                            "name": "Search",
                            "request": {
                                "method": "GET",
                                "url": "{{baseUrl}}/search",
                                "auth": {
                                    "type": "apikey",
                                    "apikey": [
                                        {"key": "key", "value": "api_key"},
                                        {"key": "value", "value": FAKE_KEY},
                                        {"key": "in", "value": "query"},
                                    ],
                                },
                            },
                        },
                    ],
                },
            ],
        },
        {
            "name": "Upload",
            "request": {
                "method": "POST",
                "url": "{{baseUrl}}/upload",
                "body": {
                    "mode": "formdata",
                    "formdata": [
                        {"key": "title", "value": "report", "type": "text"},
                        {"key": "file", "src": "/tmp/x.pdf", "type": "file"},
                    ],
                },
            },
        },
        {
            "name": "GraphQL",
            "request": {
                "method": "POST",
                "url": "{{baseUrl}}/graphql",
                "body": {
                    "mode": "graphql",
                    "graphql": {"query": "{ me { id } }", "variables": '{"a": 1}'},
                },
            },
        },
    ],
}


def by_name(result: importers.ImportResult) -> dict[str, Request]:
    return {r.name: r for requests in result.files.values() for r in requests}


def all_text(result: importers.ImportResult) -> str:
    files = "".join(dumps(_as_file(rs)) for rs in result.files.values())
    return files + json.dumps(result.environments)


def _as_file(requests: list[Request]) -> Any:
    from librepost.httpfile import HttpFile

    return HttpFile(list(requests))


def test_detect() -> None:
    assert detect(json.dumps(COLLECTION)) == "postman"
    assert detect(json.dumps({"collection": COLLECTION})) == "postman"
    assert detect('{"name": "Dev", "values": []}') == "postman-env"
    assert detect('{"log": {"entries": []}}') == "har"
    assert detect("  curl https://example.invalid") == "curl"
    with pytest.raises(ImporterError):
        detect("{}")
    with pytest.raises(ImporterError):
        detect("not json")


def test_postman_layout_and_requests() -> None:
    result = importers.convert(json.dumps(COLLECTION))
    assert sorted(result.files) == [
        "acme-api.http",
        "acme-api/users.http",
        "acme-api/users/admin.http",
    ]
    reqs = by_name(result)

    assert reqs["Health"].headers == []  # noauth overrides the collection's bearer
    assert ("Authorization", "Bearer {{token}}") in reqs["List users"].headers
    assert ("X-Off", "1") not in reqs["List users"].headers
    assert reqs["Login"].body == "user=ada%20lovelace"
    assert ("Content-Type", "application/x-www-form-urlencoded") in reqs["Login"].headers
    assert reqs["Get user"].url == "{{baseUrl}}/users/42/posts/{{postId}}"
    assert ("Content-Type", "application/json") in reqs["Create user"].headers
    assert json.loads(reqs["GraphQL"].body) == {"query": "{ me { id } }", "variables": {"a": 1}}
    assert (
        'name="title"' in reqs["Upload"].body
        and "file" not in reqs["Upload"].body.split("title")[1]
    )

    # Folder auth is inherited; request auth overrides it.
    stats_auth = dict(reqs["Stats"].headers)["Authorization"]
    assert stats_auth.startswith("Basic admin {{secret:keychain/acme-api-password}}")
    assert reqs["Search"].url == "{{baseUrl}}/search?api_key={{secret:keychain/acme-api-api-key}}"

    warnings = " ".join(result.warnings)
    assert "1 pre-request/test script" in warnings
    assert "$randomFirstName" in warnings
    assert "file field 'file' skipped" in warnings


def test_postman_never_writes_literal_credentials() -> None:
    result = importers.convert(json.dumps(COLLECTION))
    text = all_text(result)
    for value in (FAKE_TOKEN, FAKE_PASSWORD, FAKE_KEY):
        assert value not in text
    assert {s.value for s in result.secrets} == {FAKE_TOKEN, FAKE_PASSWORD, FAKE_KEY}
    assert result.environments["$shared"] == {
        "baseUrl": "https://api.example.invalid",
        "token": "{{secret:keychain/acme-api-token}}",
    }


def test_postman_v20_auth_and_string_request() -> None:
    data = {
        "info": {"name": "Old", "schema": "https://schema.getpostman.com/json/collection/v2.0.0/"},
        "item": [
            {
                "name": "r",
                "request": {
                    "url": "https://example.invalid/a",
                    "method": "get",
                    "auth": {"type": "bearer", "bearer": {"token": "{{t}}"}},
                },
            },
            {"name": "s", "request": "https://example.invalid/b"},
        ],
    }
    reqs = by_name(importers.convert(json.dumps(data)))
    assert reqs["r"].headers == [("Authorization", "Bearer {{t}}")]
    assert reqs["s"].method == "GET" and reqs["s"].url == "https://example.invalid/b"


def test_postman_environment() -> None:
    env = {
        "name": "Staging EU",
        "_postman_variable_scope": "environment",
        "values": [
            {"key": "baseUrl", "value": "https://staging.example.invalid", "enabled": True},
            {"key": "apiKey", "value": FAKE_KEY, "enabled": True},
            {"key": "clientSecret", "value": "", "type": "secret", "enabled": True},
            {"key": "old", "value": "x", "enabled": False},
        ],
    }
    result = importers.convert(json.dumps(env))
    assert result.environments == {
        "staging-eu": {
            "baseUrl": "https://staging.example.invalid",
            "apiKey": "{{secret:keychain/staging-eu-apikey}}",
            "clientSecret": "{{secret:keychain/staging-eu-clientsecret}}",
        }
    }
    assert [(s.name.split("-")[-1], s.value) for s in result.secrets] == [
        ("apikey", FAKE_KEY),
        ("clientsecret", ""),
    ]


def test_curl_chrome_copy() -> None:
    # Fake credentials on purpose: the importer must replace them with secret references.
    command = (
        "curl 'https://api.example.invalid/v1/items?limit=5' \\\n"  # gitleaks:allow
        "  -H 'accept: application/json' \\\n"
        "  -H 'authorization: Bearer fake-bearer-value-9' \\\n"
        "  -H 'cookie: session=fake-session-cookie' \\\n"
        '  --data-raw $\'{"note":"it\\\'s ok\\\\n"}\' \\\n'
        "  --compressed"
    )
    result = curl.convert(command)
    (request,) = result.files["imported.http"]
    assert request.method == "POST"
    assert request.url == "https://api.example.invalid/v1/items?limit=5"
    assert request.body == '{"note":"it\'s ok\\n"}'
    headers = dict(request.headers)
    assert headers["authorization"] == "Bearer {{secret:keychain/api-example-invalid-token}}"
    assert headers["cookie"] == "{{secret:keychain/api-example-invalid-cookie}}"
    assert {s.value for s in result.secrets} == {
        "fake-bearer-value-9",
        "session=fake-session-cookie",
    }


@pytest.mark.parametrize(
    ("command", "method", "url", "body", "header"),
    [
        ("curl -sSL https://a.invalid/x", "GET", "https://a.invalid/x", "", None),
        ("curl -XDELETE https://a.invalid/x/1", "DELETE", "https://a.invalid/x/1", "", None),
        ("curl -I https://a.invalid", "HEAD", "https://a.invalid", "", None),
        (
            "curl -G -d q=1 -d page=2 https://a.invalid/s",
            "GET",
            "https://a.invalid/s?q=1&page=2",
            "",
            None,
        ),
        (
            "curl --json '{\"a\":1}' https://a.invalid",
            "POST",
            "https://a.invalid",
            '{"a":1}',
            ("Content-Type", "application/json"),
        ),
        (
            "curl --data-urlencode 'q=a b&c' https://a.invalid",
            "POST",
            "https://a.invalid",
            "q=a%20b%26c",
            ("Content-Type", "application/x-www-form-urlencoded"),
        ),
        (
            "curl -u alice https://a.invalid",
            "GET",
            "https://a.invalid",
            "",
            ("Authorization", "Basic alice"),
        ),
        (
            "curl --request=PUT --url=https://a.invalid -H 'X-Empty;'",
            "PUT",
            "https://a.invalid",
            "",
            ("X-Empty", ""),
        ),
    ],
)
def test_curl_options(
    command: str, method: str, url: str, body: str, header: tuple[str, str] | None
) -> None:
    request = curl.parse(command, [])
    assert (request.method, request.url, request.body) == (method, url, body)
    if header:
        assert header in request.headers


def test_curl_basic_auth_becomes_secret() -> None:
    command = "curl -u alice:fake-pass-word https://a.invalid"  # gitleaks:allow
    (request,) = curl.convert(command).files["imported.http"]
    assert request.headers == [
        ("Authorization", "Basic alice {{secret:keychain/a-invalid-password}}")
    ]


def test_curl_warnings_and_errors() -> None:
    warnings: list[str] = []
    curl.parse("curl -d @body.json --proxy http://p.invalid -Z https://a.invalid", warnings)
    joined = " ".join(warnings)
    assert "body.json" in joined and "Proxy" in joined and "-Z" in joined
    with pytest.raises(ImporterError, match="No URL"):
        curl.parse("curl -H 'a: b'", [])
    with pytest.raises(ImporterError):
        curl.parse("wget https://a.invalid", [])


def test_curl_several_commands() -> None:
    text = "curl https://a.invalid/one\ncurl -X POST https://a.invalid/two \\\n  -d x=1\n"
    requests = curl.convert(text).files["imported.http"]
    assert [(r.method, r.name) for r in requests] == [("GET", "get-one"), ("POST", "post-two")]


def har_entry(url: str, method: str = "GET", rtype: str = "fetch", **extra: Any) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "_resourceType": rtype,
        "request": {
            "method": method,
            "url": url,
            "headers": [
                {"name": ":authority", "value": "api.example.invalid"},
                {"name": "sec-fetch-mode", "value": "cors"},
                {"name": "Accept", "value": "application/json"},
                {"name": "Authorization", "value": "Bearer fake-har-token-77"},
            ],
        },
        "response": {"content": {"mimeType": "application/json"}},
    }
    entry["request"].update(extra)
    return entry


def test_har() -> None:
    har = {
        "log": {
            "entries": [
                har_entry("https://api.example.invalid/v1/users"),
                har_entry("https://api.example.invalid/v1/users"),  # duplicate
                har_entry(
                    "https://api.example.invalid/v1/users",
                    "POST",
                    postData={"mimeType": "application/json", "text": '{"a":1}'},
                ),
                har_entry("https://cdn.example.invalid/logo.png", rtype="image"),
                har_entry("https://api.example.invalid/v1/users", "OPTIONS", rtype="preflight"),
                har_entry("data:text/plain,hi", rtype="other"),
            ]
        }
    }
    result = importers.convert(json.dumps(har))
    assert list(result.files) == ["api-example-invalid.http"]
    get, post = result.files["api-example-invalid.http"]
    assert (get.name, post.name) == ("get-users", "post-users")
    assert get.headers == [
        ("Accept", "application/json"),
        ("Authorization", "Bearer {{secret:keychain/api-example-invalid-token}}"),
    ]
    assert post.body == '{"a":1}'
    assert "fake-har-token-77" not in all_text(result)
    assert any("non-API" in w for w in result.warnings)
    assert any("repeated" in w for w in result.warnings)

    everything = importers.convert(json.dumps(har), everything=True)
    assert "cdn-example-invalid.http" in everything.files


def test_write_never_overwrites(tmp_path: Path) -> None:
    (tmp_path / "http-client.env.json").write_text(
        '{"$shared": {"baseUrl": "https://mine.invalid"}}'
    )
    result = importers.convert(json.dumps(COLLECTION))
    first = importers.write(result, tmp_path)
    assert sorted(first.created) == sorted(result.files)
    assert first.env_kept == ["$shared.baseUrl"]
    env = json.loads((tmp_path / "http-client.env.json").read_text())
    assert env["$shared"]["baseUrl"] == "https://mine.invalid"
    assert env["$shared"]["token"].startswith("{{secret:")

    second = importers.write(importers.convert(json.dumps(COLLECTION)), tmp_path)
    assert "acme-api-2.http" in second.created
    # Everything written parses back and passes the leak check.
    for rel in Workspace(tmp_path).files():
        parse((tmp_path / rel).read_text())
    assert leakcheck.scan([tmp_path]) == []


def test_write_curl_appends(tmp_path: Path) -> None:
    importers.write(curl.convert("curl https://a.invalid/1"), tmp_path, append=True)
    importers.write(curl.convert("curl https://a.invalid/2"), tmp_path, append=True)
    requests = Workspace(tmp_path).load("imported.http").requests
    assert [r.url for r in requests] == ["https://a.invalid/1", "https://a.invalid/2"]


def test_runner_basic_auth_and_multipart() -> None:
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        seen["body"] = request.content
        return httpx.Response(200)

    request = Request(
        "POST",
        "https://a.invalid",
        [
            ("Authorization", "Basic alice {{secret:keychain/pw}}"),
            ("Content-Type", "multipart/form-data; boundary=b"),
        ],
        '--b\nContent-Disposition: form-data; name="x"\n\n1\n--b--',
    )
    prepared = runner.prepare(request, {}, lambda ref: "fake-pw")
    runner.send(prepared, transport=httpx.MockTransport(handler))
    assert seen["auth"] == "Basic YWxpY2U6ZmFrZS1wdw=="  # alice:fake-pw
    assert seen["body"] == b'--b\r\nContent-Disposition: form-data; name="x"\r\n\r\n1\r\n--b--'
    assert "YWxpY2U6ZmFrZS1wdw==" not in prepared.masked()


def test_cli_import(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from librepost.cli import app

    source = tmp_path / "acme.postman_collection.json"
    source.write_text(json.dumps(COLLECTION))
    workspace = tmp_path / "ws"
    cli = CliRunner()
    dry = cli.invoke(app, ["import", str(source), "--into", str(workspace), "--dry-run"])
    assert dry.exit_code == 0, dry.output
    assert not workspace.exists()

    result = cli.invoke(app, ["import", str(source), "--into", str(workspace)])
    assert result.exit_code == 0, result.output
    assert "librepost secret set acme-api-password" in result.output
    assert FAKE_PASSWORD not in result.output
    assert (workspace / "acme-api/users.http").exists()

    pasted = cli.invoke(
        app, ["import", "curl -X POST https://a.invalid/x -d a=1", "--into", str(workspace)]
    )
    assert pasted.exit_code == 0, pasted.output
    assert (workspace / "imported.http").exists()


def test_placeholder_values_are_not_secrets() -> None:
    env = {
        "name": "Dev",
        "values": [
            {"key": "consumer_secret", "value": "Your consumer secret"},
            {"key": "token", "value": "fake-real-looking-token"},
        ],
    }
    result = importers.convert(json.dumps(env))
    assert (
        result.environments["dev"]["consumer_secret"] == "{{secret:keychain/dev-consumer-secret}}"
    )
    assert [s.value for s in result.secrets] == ["", "fake-real-looking-token"]
    assert leakcheck.literal_credential("Basic alice fake-pass-word")
    assert not leakcheck.literal_credential("Basic alice {{secret:keychain/pw}}")
    assert leakcheck.literal_credential("session=fake-session; theme=dark")


def test_unsupported_auth_warnings_are_grouped() -> None:
    items = [
        {"name": f"r{i}", "request": {"url": "https://a.invalid", "auth": {"type": "oauth1"}}}
        for i in range(5)
    ]
    result = importers.convert(json.dumps({"info": {"name": "x"}, "item": items}))
    assert result.warnings == [
        "oauth1 auth isn't supported; add the header yourself in 5 request(s): 'r0', 'r1', 'r2', …"
    ]
