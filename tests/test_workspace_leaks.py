import os
import subprocess
from pathlib import Path

import pytest

from librepost import leakcheck
from librepost.httpfile import Request
from librepost.workspace import Workspace, WorkspaceError


def test_files_skip_hidden_and_vendor_dirs(tmp_path: Path) -> None:
    for rel in ["a.http", "sub/b.rest", "node_modules/x.http", ".git/y.http", "c.txt"]:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("GET https://example.invalid\n")
    assert Workspace(tmp_path).files() == ["a.http", "sub/b.rest"]


@pytest.mark.parametrize(
    "rel",
    [
        "",
        "../x.http",
        "/etc/x.http",
        "a/../../x.http",
        "C:/x.http",
        "x.txt",
        ".git/x.http",
        "..\\x.http",
    ],
)
def test_path_traversal_refused(tmp_path: Path, rel: str) -> None:
    with pytest.raises(WorkspaceError):
        Workspace(tmp_path).path(rel)


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_symlink_escape_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(WorkspaceError, match="outside"):
        Workspace(root).path("link/x.http")


def test_crud(tmp_path: Path) -> None:
    ws = Workspace(tmp_path)
    ws.create("api/users.http", Request("GET", "https://example.invalid", name="one"))
    with pytest.raises(WorkspaceError, match="exists"):
        ws.create("api/users.http", Request("GET", "https://example.invalid"))
    assert ws.append("api/users.http", Request("POST", "https://example.invalid", name="two")) == 1
    ws.update("api/users.http", 0, Request("PUT", "https://example.invalid/1", name="one"))
    assert [(r.method, r.name) for r in ws.load("api/users.http").requests] == [
        ("PUT", "one"),
        ("POST", "two"),
    ]
    ws.remove("api/users.http", 0)
    ws.remove("api/users.http", 0)
    assert not (tmp_path / "api/users.http").exists()


def test_update_keeps_comments_and_trailer(tmp_path: Path) -> None:
    (tmp_path / "a.http").write_text("# keep me\nGET https://example.invalid\n\n> {% x %}\n")
    ws = Workspace(tmp_path)
    ws.update("a.http", 0, Request("GET", "https://example.invalid/2"))
    text = (tmp_path / "a.http").read_text()
    assert "# keep me" in text and "> {% x %}" in text and "/2" in text


def test_leaks_found(tmp_path: Path) -> None:
    (tmp_path / "a.http").write_text(
        "GET https://example.invalid\n"
        "Authorization: Bearer abcdefgh12345678\n"
        "X-Ok: {{secret:keychain/fine}}\n"
        "X-Gh: ghp_" + "a" * 36 + "\n"
    )
    (tmp_path / "http-client.env.json").write_text(
        '{"dev": {"password": "hunter2hunter2", "token": "{{secret:keychain/t}}", "apiKey": "<your key>"}}'
    )
    leaks = leakcheck.scan([tmp_path], display_root=tmp_path)
    assert sorted((leak.path, leak.rule) for leak in leaks) == [
        ("a.http", "github-token"),
        ("a.http", "literal-header"),
        ("http-client.env.json", "literal-env-secret"),
    ]


def test_clean_files_pass(tmp_path: Path) -> None:
    (tmp_path / "a.http").write_text(
        "GET https://example.invalid\nAuthorization: Bearer {{token}}\nCookie: <paste>\n"
    )
    assert leakcheck.scan([tmp_path]) == []


def test_private_env_must_be_gitignored(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    private = tmp_path / "http-client.private.env.json"
    private.write_text('{"dev": {"token": "real-secret-value"}}')
    assert [leak.rule for leak in leakcheck.scan([tmp_path])] == ["private-env-tracked"]
    (tmp_path / ".gitignore").write_text("http-client.private.env.json\n")
    assert leakcheck.scan([tmp_path]) == []
