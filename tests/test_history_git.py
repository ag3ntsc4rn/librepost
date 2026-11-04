import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from test_server import ORIGIN, TOKEN, make_client

from librepost import gitstatus
from librepost.history import Entry, History, matches

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git isn't installed")


def git(root: Path, *args: str) -> None:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A repository whose workspace is the `api` subfolder."""
    git(tmp_path, "init", "-q", "-b", "main")
    api = tmp_path / "api"
    api.mkdir()
    (api / "users.http").write_text("GET https://example.invalid/users\n", newline="\n")
    (api / "gone.http").write_text("GET https://example.invalid/gone\n", newline="\n")
    (api / "old.http").write_text("GET https://example.invalid/old\n", newline="\n")
    (tmp_path / "outside.txt").write_text("not in the workspace\n", newline="\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "first")
    (api / "users.http").write_text("GET https://example.invalid/users?page=2\n", newline="\n")
    (api / "gone.http").unlink()
    (api / "new.http").write_text("GET https://example.invalid/new\n", newline="\n")
    git(tmp_path, "mv", "api/old.http", "api/renamed.http")
    (tmp_path / "outside.txt").write_text("changed\n", newline="\n")
    return api


@needs_git
def test_status_and_diff(repo: Path) -> None:
    status = gitstatus.status(repo)
    assert status is not None
    assert status.branch == "main" and len(status.commit) == 7
    codes = {c.path: (c.code, c.staged) for c in status.changes}
    # Paths are relative to the workspace, and files outside it aren't listed.
    assert codes == {
        "gone.http": ("D", False),
        "new.http": ("U", False),
        "renamed.http": ("R", True),
        "users.http": ("M", False),
    }
    users = status.by_path["users.http"]
    assert users.label == "modified"
    diff = gitstatus.diff(repo, users)
    assert "-GET https://example.invalid/users\n+GET https://example.invalid/users?page=2" in diff
    assert gitstatus.diff(repo, status.by_path["new.http"]) == (
        "new file new.http\n+GET https://example.invalid/new"
    )
    assert "-GET https://example.invalid/gone" in gitstatus.diff(repo, status.by_path["gone.http"])


@needs_git
def test_status_outside_a_repository_and_before_first_commit(tmp_path: Path) -> None:
    assert gitstatus.status(tmp_path) is None
    git(tmp_path, "init", "-q", "-b", "trunk")
    (tmp_path / "a.http").write_text("GET https://example.invalid\n")
    git(tmp_path, "add", "a.http")
    status = gitstatus.status(tmp_path)
    assert status is not None and status.branch == "trunk" and status.commit == ""
    (change,) = status.changes
    assert change.code == "A" and change.label == "added (staged)"
    assert gitstatus.diff(tmp_path, change).startswith("new file a.http")


def entry(n: int, **kw: object) -> Entry:
    return Entry(time=1_700_000_000 + n, method="GET", url=f"https://example.invalid/{n}", **kw)  # type: ignore[arg-type]


def test_history_store(tmp_path: Path) -> None:
    store = History(tmp_path / "ws", directory=tmp_path / "state", limit=5)
    assert store.entries() == []
    ids = [store.add(entry(n, body="x" * 100_000 if n == 0 else "")) for n in range(20)]
    kept = store.entries()
    # Trimmed now and then, so a few more than the limit may remain; newest first.
    assert 5 <= len(kept) <= 15
    assert kept[0].id == ids[-1] and kept[0].url.endswith("/19")
    assert store.get(ids[-2]) is not None and store.get("nope") is None
    if sys.platform != "win32":
        assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    # A damaged line doesn't hide the rest.
    with store.path.open("a") as f:
        f.write("{not json\n")
    assert len(store.entries()) == len(kept)
    store.clear()
    assert store.entries() == [] and not store.path.exists()

    big = History(tmp_path / "ws2", directory=tmp_path / "state")
    big.add(entry(1, body="y" * 100_000))
    assert big.entries()[0].body.endswith("(cut short in history)")


def test_matches() -> None:
    e = entry(1, name="login", file="auth.http", env="dev", status=401)
    assert matches(e, "") and matches(e, "LOGIN dev") and matches(e, "401")
    assert not matches(e, "login prod")


def test_ui_history(workspace: Path, state_dir: Path) -> None:
    client = make_client(workspace)
    sent = client.post(
        "/send",
        data={
            "file": "api.http",
            "index": "0",
            "env": "dev",
            "method": "GET",
            "url": "{{base}}/me",
            "headers": "Authorization: Bearer {{auth}}",
            "name": "me",
            "checks": "@expect status == 200",
        },
        headers=ORIGIN,
    )
    assert sent.status_code == 200
    # History is stored outside the workspace, with the secret masked.
    (stored,) = (state_dir / "history").glob("*.jsonl")
    raw = stored.read_text(encoding="utf-8")
    assert "s3cr3t-value" not in raw and "••••••" in raw
    assert not list(workspace.rglob("*.jsonl"))

    page = client.get("/history")
    assert "api.example.invalid/me" in page.text and "1/1 checks" in page.text
    (line,) = raw.splitlines()
    entry_id = json.loads(line)["id"]
    detail = client.get(f"/history/entry?id={entry_id}")
    assert "200 OK" in detail.text and "s3cr3t-value" not in detail.text
    assert "Bearer ••••••" in detail.text  # the request sent, masked

    # Opening it again gives the request as written, placeholders and all.
    opened = client.get(f"/history/open?id={entry_id}")
    assert "{{base}}/me" in opened.text and "Bearer {{auth}}" in opened.text
    assert "Copied from history" in opened.text and 'value="api.http"' in opened.text

    assert "api.example.invalid" in client.get("/history/list?q=me").text
    assert "Nothing here yet" in client.get("/history/list?q=nomatch").text
    assert "for me · api.http" in client.get("/history?file=api.http&name=me").text

    cleared = client.post("/history/clear", headers=ORIGIN)
    assert "History cleared" in cleared.text and not stored.exists()
    assert "gone" in client.get(f"/history/entry?id={entry_id}").text


def test_ui_history_off(workspace: Path, state_dir: Path) -> None:
    from starlette.testclient import TestClient

    from librepost.server import create_app

    app = create_app(
        workspace,
        port=8765,
        token=TOKEN,
        transport=httpx.MockTransport(lambda r: httpx.Response(204)),
        keep_history=False,
    )
    client = TestClient(app, base_url="http://127.0.0.1:8765")
    client.get(f"/?token={TOKEN}")
    client.post("/send", data={"method": "GET", "url": "https://x.invalid"}, headers=ORIGIN)
    assert not (state_dir / "history").exists()
    assert "History is off" in client.get("/history").text


@needs_git
def test_ui_git(repo: Path) -> None:
    client = make_client(repo)
    home = client.get("/")
    assert "⎇ main" in home.text and "4 changed" in home.text
    assert 'title="modified">M</span>' in home.text  # badge in the sidebar
    changes = client.get("/git")
    assert "renamed.http" in changes.text and "outside.txt" not in changes.text
    diff = client.get("/git/diff?path=users.http")
    assert 'class="d-line d-add">+GET https://example.invalid/users?page=2' in diff.text
    # Only changed files can be shown.
    assert "has no changes" in client.get("/git/diff?path=../outside.txt").text


def test_ui_git_without_repository(workspace: Path) -> None:
    client = make_client(workspace)
    assert "⎇" not in client.get("/").text
    assert "isn't in a git repository" in client.get("/git").text
