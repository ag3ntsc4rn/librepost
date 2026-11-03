import json
import os
import stat
import subprocess
from pathlib import Path

import pytest

from librepost import manage
from librepost.environments import PRIVATE_FILE, PUBLIC_FILE
from librepost.manage import ManageError, Row


def read(path: Path) -> dict[str, object]:
    data: dict[str, object] = json.loads(path.read_text())
    return data


@pytest.fixture
def root(tmp_path: Path) -> Path:
    (tmp_path / PUBLIC_FILE).write_text(
        json.dumps({"$shared": {"v": "1"}, "dev": {"base": "https://dev.invalid", "n": 3}})
    )
    (tmp_path / PRIVATE_FILE).write_text(json.dumps({"dev": {"base": "https://me.invalid"}}))
    return tmp_path


def test_rows_and_names(root: Path) -> None:
    assert manage.env_names(root) == ["$shared", "dev"]
    assert manage.rows(root, "dev") == [
        Row("base", "https://dev.invalid", "shared"),
        Row("n", "3", "shared"),
        Row("base", "https://me.invalid", "private"),
    ]


def test_save_splits_files_and_stores_secrets(root: Path) -> None:
    stored: dict[str, str] = {}
    names = manage.save(
        root,
        "dev",
        [
            Row("base", "https://dev.invalid", "shared"),
            Row("apiKey", "fake-dev-key-123", "shared", secret=True),
            Row("user", "me", "private"),
        ],
        stored.__setitem__,
    )
    assert names == ["dev-apikey"] and stored == {"dev-apikey": "fake-dev-key-123"}
    assert read(root / PUBLIC_FILE)["dev"] == {
        "base": "https://dev.invalid",
        "apiKey": "{{secret:keychain/dev-apikey}}",
    }
    assert read(root / PUBLIC_FILE)["$shared"] == {"v": "1"}  # other environments untouched
    assert read(root / PRIVATE_FILE) == {"dev": {"user": "me"}}
    assert "fake-dev-key-123" not in (root / PUBLIC_FILE).read_text()


def test_shared_credentials_refused(root: Path) -> None:
    before = (root / PUBLIC_FILE).read_text()
    with pytest.raises(ManageError, match="looks like a credential"):
        manage.save(root, "dev", [Row("password", "hunter2hunter2", "shared")], dict().__setitem__)
    with pytest.raises(ManageError, match="looks like a credential"):
        manage.save(root, "dev", [Row("x", "ghp_" + "a" * 36, "shared")], dict().__setitem__)
    assert (root / PUBLIC_FILE).read_text() == before
    # The same value is fine as private.
    manage.save(root, "dev", [Row("password", "hunter2hunter2", "private")], dict().__setitem__)


@pytest.mark.parametrize(
    "rows",
    [
        [Row("bad name", "x")],
        [Row("a", "1"), Row("a", "2")],
        [Row("a", "1", "elsewhere")],
        [Row("token", "", "shared", secret=True)],
    ],
)
def test_save_validation(root: Path, rows: list[Row]) -> None:
    with pytest.raises(ManageError):
        manage.save(root, "dev", rows, dict().__setitem__)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_private_file_is_owner_only(tmp_path: Path) -> None:
    manage.create(tmp_path, "dev")
    manage.save(tmp_path, "dev", [Row("a", "1", "private")], dict().__setitem__)
    assert stat.S_IMODE((tmp_path / PRIVATE_FILE).stat().st_mode) == 0o600


def test_create_delete(root: Path) -> None:
    manage.create(root, "prod")
    assert manage.env_names(root) == ["$shared", "dev", "prod"]
    with pytest.raises(ManageError, match="exists"):
        manage.create(root, "prod")
    with pytest.raises(ManageError):
        manage.create(root, "no spaces")
    manage.delete(root, "dev")
    assert manage.env_names(root) == ["$shared", "prod"]
    assert "dev" not in read(root / PRIVATE_FILE)


def test_empty_environment_stays_listed(root: Path) -> None:
    manage.save(root, "dev", [], dict().__setitem__)
    assert manage.env_names(root) == ["$shared", "dev"]
    assert "dev" not in read(root / PRIVATE_FILE)


def test_gitignore(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / PRIVATE_FILE).write_text("{}")
    assert manage.private_file_tracked(tmp_path)
    manage.ignore_private_file(tmp_path)
    manage.ignore_private_file(tmp_path)
    assert (tmp_path / ".gitignore").read_text().count(PRIVATE_FILE) == 1
    assert not manage.private_file_tracked(tmp_path)


def test_secret_refs(root: Path) -> None:
    (root / "a.http").write_text(
        "GET https://x.invalid\nAuthorization: Bearer {{secret:keychain/tok}}\n"
        "X-Env: {{ secret:env/CI_TOKEN }}\n"
    )
    (root / PRIVATE_FILE).write_text('{"dev": {"t": "{{secret:keychain/tok}}"}}')
    refs = manage.secret_refs(root)
    assert [(r.ref, r.used_in) for r in refs] == [
        ("env/CI_TOKEN", ["a.http"]),
        ("keychain/tok", ["a.http", PRIVATE_FILE]),
    ]
