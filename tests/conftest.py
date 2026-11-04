import json
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def state_dir(tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep history out of the real per-user folder."""
    path = tmp_path_factory.mktemp("state")
    monkeypatch.setenv("LIBREPOST_STATE_DIR", str(path))
    return path


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
