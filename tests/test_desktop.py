import socket
import sys
import types
from pathlib import Path
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from librepost import desktop
from librepost.cli import _bind, app
from librepost.server import create_app


def test_window_without_pywebview(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "webview", None)  # import fails
    result = CliRunner().invoke(app, ["ui", str(tmp_path), "--window"])
    assert result.exit_code == 1
    assert "librepost-app[desktop]" in result.output


def test_window_runs_the_server_until_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def create_window(title: str, url: str, **options: Any) -> None:
        seen.update(title=title, url=url, options=options)

    def start(**options: Any) -> None:
        # While the window is open the UI answers, behind the usual token check.
        seen["start"] = options
        seen["status"] = httpx.get(seen["url"], follow_redirects=False).status_code

    fake = types.SimpleNamespace(create_window=create_window, start=start)
    monkeypatch.setitem(sys.modules, "webview", fake)
    monkeypatch.setattr(desktop, "_mac_branding", lambda: None)

    sock = _bind(0)
    port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}/?token=t"
    desktop.run(create_app(tmp_path, port=port, token="t"), sock, url, "librepost · demo")

    assert seen["title"] == "librepost · demo" and seen["url"] == url
    assert seen["status"] == 303  # token swapped for the session cookie
    assert seen["start"] == {"private_mode": True}  # nothing kept after closing
    # Closing the window stops the server.
    with pytest.raises(OSError), socket.create_connection(("127.0.0.1", port), timeout=1):
        pass
