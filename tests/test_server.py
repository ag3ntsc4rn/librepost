import json
from pathlib import Path

import httpx
from starlette.testclient import TestClient

from librepost.secretstore import SecretError
from librepost.server import create_app

PORT = 8765
TOKEN = "test-token"
BASE = f"http://127.0.0.1:{PORT}"
ORIGIN = {"origin": BASE, "hx-request": "true"}


def echo(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "method": request.method,
            "url": str(request.url),
            "auth": request.headers.get("authorization"),
            "body": request.content.decode(),
        },
    )


def lookup(ref: str) -> str:
    # Like the real keychain: stored values, a fixed test token, else "not found".
    key = ref.removeprefix("keychain/")
    if key in STORED:
        return STORED[key]
    if ref == "keychain/token":
        return "s3cr3t-value"
    raise SecretError(f"Secret {key!r} is not in the keychain.")


STORED: dict[str, str] = {}


def make_client(root: Path, *, login: bool = True) -> TestClient:
    app = create_app(
        root,
        port=PORT,
        token=TOKEN,
        transport=httpx.MockTransport(echo),
        secret_lookup=lookup,
        secret_store=STORED.__setitem__,
        secret_exists=lambda ref: ref.removeprefix("keychain/") in STORED,
        secret_delete=STORED.__delitem__,
        secret_names=lambda: sorted(STORED),
    )
    client = TestClient(app, base_url=BASE)
    if login:
        response = client.get(f"/?token={TOKEN}", follow_redirects=False)
        assert response.status_code == 303
        assert "httponly" in response.headers["set-cookie"].lower()
        assert "samesite=strict" in response.headers["set-cookie"].lower()
    return client


def test_requires_token(workspace: Path) -> None:
    client = make_client(workspace, login=False)
    assert client.get("/").status_code == 403
    assert client.get("/?token=wrong").status_code == 403
    assert client.get("/tree").status_code == 403


def test_rejects_foreign_host(workspace: Path) -> None:
    client = make_client(workspace)
    response = client.get("/", headers={"host": f"evil.example:{PORT}"})
    assert response.status_code == 421


def test_rejects_cross_origin_post(workspace: Path) -> None:
    client = make_client(workspace)
    data = {"method": "GET", "url": "http://internal.invalid"}
    assert client.post("/send", data=data).status_code == 403
    assert (
        client.post(
            "/send", data=data, headers={"origin": "https://evil.example", "hx-request": "true"}
        ).status_code
        == 403
    )
    assert client.post("/send", data=data, headers={"origin": BASE}).status_code == 403


def test_security_headers(workspace: Path) -> None:
    client = make_client(workspace)
    for response in (client.get("/"), client.get("/static/app.css"), client.get("/nope")):
        assert "script-src 'self'" in response.headers["content-security-policy"]
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["cache-control"] == "no-store"


def test_index_lists_requests(workspace: Path) -> None:
    html = make_client(workspace).get("/").text
    assert "api.http" in html and ">me<" in html and '<option value="dev">' in html


def test_send_resolves_and_masks_secrets(workspace: Path) -> None:
    client = make_client(workspace)
    response = client.post(
        "/send",
        data={
            "file": "api.http",
            "env": "dev",
            "method": "GET",
            "url": "{{base}}/me",
            "headers": "Authorization: Bearer {{auth}}",
        },
        headers=ORIGIN,
    )
    assert response.status_code == 200
    assert "200 OK" in response.text
    assert "https://api.example.invalid/me" in response.text
    # The echo endpoint returned the token, but the UI never shows it.
    assert "s3cr3t-value" not in response.text
    assert "Bearer ••••••" in response.text


def test_send_reports_missing_variables(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/send", data={"method": "GET", "url": "{{nope}}/x"}, headers=ORIGIN
    )
    assert "Undefined variable(s): nope" in response.text


def test_response_body_is_escaped(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/send",
        data={"method": "POST", "url": "https://x.invalid", "body": "<script>alert(1)</script>"},
        headers=ORIGIN,
    )
    assert "<script>alert(1)" not in response.text
    assert "&lt;script&gt;" in response.text


def test_save_create_delete(workspace: Path) -> None:
    client = make_client(workspace)
    response = client.post("/files", data={"path": "users/list"}, headers=ORIGIN)
    assert response.headers["hx-trigger"] == "tree-changed"
    assert (workspace / "users/list.http").exists()

    response = client.post(
        "/save",
        data={
            "file": "users/list.http",
            "index": "0",
            "name": "list",
            "method": "POST",
            "url": "{{base}}/users",
            "headers": "A: 1",
            "body": "{}",
        },
        headers=ORIGIN,
    )
    assert "Saved" in response.text
    assert (
        workspace / "users/list.http"
    ).read_text() == "# @name list\nPOST {{base}}/users\nA: 1\n\n{}\n"

    client.post("/delete", data={"file": "users/list.http", "index": "0"}, headers=ORIGIN)
    assert not (workspace / "users/list.http").exists()


def test_save_refuses_traversal(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/files", data={"path": "../escape.http"}, headers=ORIGIN
    )
    assert "Invalid file path" in response.text
    assert not (workspace.parent / "escape.http").exists()


def test_open_request(workspace: Path) -> None:
    html = make_client(workspace).get("/request?file=api.http&index=0").text
    assert 'value="me"' in html and "{{base}}/me" in html


def test_import_form(workspace: Path) -> None:
    html = make_client(workspace).get("/import").text
    assert 'hx-encoding="multipart/form-data"' in html and 'name="save_secrets"' in html


def test_import_pasted_curl_saves_secret(workspace: Path) -> None:
    STORED.clear()
    command = "curl https://api.example.invalid/x -H 'Authorization: Bearer fake-ui-token-123'"  # gitleaks:allow
    response = make_client(workspace).post(
        "/import",
        data={"text": command, "file": "pasted", "save_secrets": "1"},
        headers=ORIGIN,
    )
    assert response.headers["hx-trigger"] == "tree-changed"
    assert "Imported 1 request(s)" in response.text and "saved to keychain" in response.text
    assert STORED == {"api-example-invalid-token": "fake-ui-token-123"}
    text = (workspace / "pasted.http").read_text()
    assert "{{secret:keychain/api-example-invalid-token}}" in text
    assert "fake-ui-token-123" not in text and "fake-ui-token-123" not in response.text


def test_import_upload_without_saving(workspace: Path) -> None:
    STORED.clear()
    collection = {
        "info": {"name": "Shop"},
        "item": [{"name": "list", "request": {"url": "https://shop.example.invalid/items"}}],
    }
    response = make_client(workspace).post(
        "/import",
        files={
            "upload": ("shop.postman_collection.json", json.dumps(collection), "application/json")
        },
        headers=ORIGIN,
    )
    assert "Created <code>shop.http</code>" in response.text
    assert (workspace / "shop.http").exists() and STORED == {}


def test_import_errors(workspace: Path) -> None:
    client = make_client(workspace)
    assert "Paste something" in client.post("/import", data={"text": ""}, headers=ORIGIN).text
    assert "Unrecognised JSON" in client.post("/import", data={"text": "{}"}, headers=ORIGIN).text
    # Like every state-changing endpoint, import refuses cross-origin requests.
    assert client.post("/import", data={"text": "curl https://a.invalid"}).status_code == 403


def test_environments_page_and_save(workspace: Path) -> None:
    STORED.clear()
    client = make_client(workspace)
    html = client.get("/environments?env=dev").text
    assert 'value="base"' in html and "keychain/token" in html and "missing" in html

    response = client.post(
        "/environments/save",
        data={
            "env": "dev",
            "rows-0-key": "base",
            "rows-0-value": "https://api.example.invalid",
            "rows-0-location": "shared",
            "rows-1-key": "auth",
            "rows-1-value": "{{secret:keychain/token}}",
            "rows-1-location": "shared",
            "rows-1000-key": "apiKey",
            "rows-1000-value": "fake-ui-api-key",
            "rows-1000-location": "shared",
            "rows-1000-secret": "1",
        },
        headers=ORIGIN,
    )
    assert response.headers["hx-trigger"] == "envs-changed"
    assert "Stored 1 value(s) in your keychain" in response.text
    assert STORED == {"dev-apikey": "fake-ui-api-key"}
    assert "fake-ui-api-key" not in (workspace / "http-client.env.json").read_text()
    assert "fake-ui-api-key" not in response.text


def test_environments_refuse_shared_credential(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/environments/save",
        data={
            "env": "dev",
            "rows-0-key": "password",
            "rows-0-value": "hunter2hunter2",
            "rows-0-location": "shared",
        },
        headers=ORIGIN,
    )
    assert "looks like a credential" in response.text
    assert "hunter2" not in (workspace / "http-client.env.json").read_text()
    assert 'value="hunter2hunter2"' in response.text  # what was typed is kept on screen


def test_environments_create_delete_and_options(workspace: Path) -> None:
    client = make_client(workspace)
    client.post("/environments/create", data={"name": "prod"}, headers=ORIGIN)
    assert '<option value="prod">' in client.get("/env-options").text
    client.post("/environments/delete", data={"env": "prod"}, headers=ORIGIN)
    assert "prod" not in client.get("/env-options").text


def test_secrets_page(workspace: Path) -> None:
    STORED.clear()
    client = make_client(workspace)
    html = client.get("/secrets").text
    assert "keychain/token" in html and "missing" in html and "http-client.env.json" in html

    html = client.post(
        "/secrets/set", data={"name": "token", "value": "fake-v"}, headers=ORIGIN
    ).text
    assert "Stored token" in html and STORED == {"token": "fake-v"} and "fake-v" not in html
    assert ">set<" in html

    html = client.post("/secrets/delete", data={"name": "token"}, headers=ORIGIN).text
    assert "Deleted token" in html and STORED == {}
    assert (
        "Invalid secret name"
        in client.post("/secrets/set", data={"name": "../x", "value": "v"}, headers=ORIGIN).text
    )
    assert client.post("/secrets/set", data={"name": "t", "value": "v"}).status_code == 403


def test_secrets_page_lists_unreferenced_secrets(workspace: Path) -> None:
    STORED.clear()
    client = make_client(workspace)
    html = client.post(
        "/secrets/set", data={"name": "github", "value": "fake-gh"}, headers=ORIGIN
    ).text
    assert "Not used in this workspace" in html
    assert "{{secret:keychain/github}}" in html and "fake-gh" not in html
    # A referenced secret is listed once, in the main table.
    client.post("/secrets/set", data={"name": "token", "value": "fake-t"}, headers=ORIGIN)
    html = client.get("/secrets").text
    assert html.count("<code>keychain/token</code>") == 1
    assert html.count("<code>keychain/github</code>") == 1


def test_scratch_request_save_as_new_file(workspace: Path) -> None:
    client = make_client(workspace)
    html = client.get("/scratch").text
    assert "Not saved yet" in html and 'name="target"' in html
    assert '<option value="api.http">' in html  # existing files are suggested
    # A scratch request can be sent before it's saved.
    sent = client.post(
        "/send", data={"method": "GET", "url": "https://x.invalid/ping"}, headers=ORIGIN
    )
    assert "200 OK" in sent.text

    response = client.post(
        "/save-as",
        data={
            "target": "scratch/ping",
            "name": "ping",
            "method": "GET",
            "url": "https://x.invalid/ping",
        },
        headers=ORIGIN,
    )
    assert response.headers["hx-trigger"] == "tree-changed"
    assert "Saved to scratch/ping.http" in response.text
    assert (
        'hx-swap-oob="true"' in response.text
        and 'name="file" value="scratch/ping.http"' in response.text
    )
    assert (
        workspace / "scratch/ping.http"
    ).read_text() == "# @name ping\nGET https://x.invalid/ping\n"


def test_scratch_request_save_as_appends(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/save-as",
        data={"target": "api.http", "method": "POST", "url": "https://x.invalid/new"},
        headers=ORIGIN,
    )
    assert 'name="index" value="1"' in response.text
    text = (workspace / "api.http").read_text()
    assert "# @name me" in text and "POST https://x.invalid/new" in text


def test_save_as_validates(workspace: Path) -> None:
    client = make_client(workspace)
    assert (
        "The URL is empty"
        in client.post(
            "/save-as", data={"target": "a.http", "method": "GET", "url": ""}, headers=ORIGIN
        ).text
    )
    assert (
        "Invalid file path"
        in client.post(
            "/save-as",
            data={"target": "../a.http", "method": "GET", "url": "https://x.invalid"},
            headers=ORIGIN,
        ).text
    )
    assert not (workspace.parent / "a.http").exists()


def test_tree_has_add_button_per_file(workspace: Path) -> None:
    client = make_client(workspace)
    html = client.get("/tree").text
    assert 'hx-vals=\'{"file": "api.http"}\'' in html
    response = client.post("/requests", data={"file": "api.http"}, headers=ORIGIN)
    assert 'name="index" value="1"' in response.text


def test_checks_and_captures_flow(workspace: Path) -> None:
    client = make_client(workspace)
    # Save a request with checks; they're written to the file.
    client.post(
        "/save",
        data={
            "file": "api.http",
            "index": "0",
            "name": "me",
            "method": "GET",
            "url": "{{base}}/me",
            "checks": "expect status == 200\n@capture method = $.method\n@capture-secret echoed = $.url\n@expect $.method == POST",
        },
        headers=ORIGIN,
    )
    text = (workspace / "api.http").read_text()
    assert "# @expect status == 200\n# @capture method = $.method" in text

    response = client.post(
        "/send",
        data={
            "file": "api.http",
            "env": "dev",
            "method": "GET",
            "url": "{{base}}/me",
            "checks": "@expect status == 200\n@capture method = $.method\n@capture-secret echoed = $.url\n@expect $.method == POST",
        },
        headers=ORIGIN,
    )
    html = response.text
    assert html.count('class="pass"') == 1 and html.count('class="fail"') == 1
    assert "got GET" in html
    assert "<code>method</code> = <code>GET</code>" in html
    # The secret capture is masked, including in the body it came from.
    assert "<code>echoed</code> = <code>••••••</code>" in html
    assert "https://api.example.invalid/me" not in html.split("Request sent")[0]

    # A later request can use the captured value.
    response = client.post(
        "/send", data={"method": "POST", "url": "https://x.invalid/{{method}}"}, headers=ORIGIN
    )
    assert "https://x.invalid/GET" in response.text

    client.post("/captured/clear", headers=ORIGIN)
    response = client.post(
        "/send", data={"method": "POST", "url": "https://x.invalid/{{method}}"}, headers=ORIGIN
    )
    assert "Undefined variable(s): method" in response.text


def test_bad_check_line_is_reported(workspace: Path) -> None:
    response = make_client(workspace).post(
        "/send",
        data={"method": "GET", "url": "https://x.invalid", "checks": "@expect nonsense == 1"},
        headers=ORIGIN,
    )
    assert "unknown subject" in response.text


def test_environment_connection_form(workspace: Path) -> None:
    STORED.clear()
    client = make_client(workspace)
    html = client.get("/environments?env=dev").text
    assert 'hx-post="/environments/connection"' in html and 'name="client_cert"' in html

    cert = workspace / "me.pem"
    response = client.post(
        "/environments/connection",
        data={
            "env": "dev",
            "client_cert": "me.pem",
            "passphrase": "fake-pass",
            "proxy": "http://proxy.invalid:3128",
        },
        headers=ORIGIN,
    )
    # Saved, but the certificate file doesn't exist yet, and the page says so.
    assert (
        "Saved, but it won&#39;t work yet" in response.text and "doesn&#39;t exist" in response.text
    )
    assert STORED == {"dev-cert-passphrase": "fake-pass"}
    private = json.loads((workspace / "http-client.private.env.json").read_text())
    assert private["dev"]["SSLConfiguration"]["clientCertificate"] == "me.pem"
    assert "SSLConfiguration" not in (workspace / "http-client.env.json").read_text()
    assert not cert.exists()

    response = client.post(
        "/environments/connection",
        data={"env": "dev", "proxy": "proxy.invalid:3128"},
        headers=ORIGIN,
    )
    assert "must start with http://" in response.text
