import json
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

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
    return {"keychain/token": "s3cr3t-value"}[ref]


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    (tmp_path / "http-client.env.json").write_text(
        json.dumps(
            {"dev": {"base": "https://api.example.invalid", "auth": "{{secret:keychain/token}}"}}
        )
    )
    (tmp_path / "api.http").write_text(
        "# @name me\nGET {{base}}/me\nAuthorization: Bearer {{auth}}\n"
    )
    return tmp_path


STORED: dict[str, str] = {}


def make_client(root: Path, *, login: bool = True) -> TestClient:
    app = create_app(
        root,
        port=PORT,
        token=TOKEN,
        transport=httpx.MockTransport(echo),
        secret_lookup=lookup,
        secret_store=STORED.__setitem__,
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
