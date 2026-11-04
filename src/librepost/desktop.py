"""The UI in its own window instead of a browser tab (`librepost ui --window`).

Needs the optional pywebview dependency (`pip install "librepost-app[desktop]"`), which uses
the system's web view: WebKit on macOS, Edge WebView2 on Windows, WebKitGTK or Qt on Linux.
The same local server runs in a background thread; the window is just another client, so all
of its protections still apply. Unlike a browser tab, no extensions can read the page, and
nothing (cookies, storage) is kept after the window closes.
"""

from __future__ import annotations

import contextlib
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

import uvicorn
from starlette.types import ASGIApp

INSTALL_HINT = (
    "The desktop window needs an extra package. Install it with:\n"
    '  uv tool install --force "librepost-app[desktop]"\n'
    "or, with pip:\n"
    '  pip install "librepost-app[desktop]"'
)
LINUX_HINT = (
    "\nOn Linux, pywebview also needs GTK or Qt. The simplest is Qt:\n"
    '  uv tool install --force "librepost-app[desktop]" --with "pywebview[qt]"'
)


class DesktopUnavailable(RuntimeError):
    pass


def check() -> None:
    """Raise DesktopUnavailable, with install instructions, if pywebview is missing."""
    _webview()


def _webview() -> Any:
    try:
        import webview
    except ImportError:
        raise DesktopUnavailable(
            INSTALL_HINT + (LINUX_HINT if sys.platform.startswith("linux") else "")
        ) from None
    return webview


def _mac_branding() -> None:
    """Show "librepost" and its icon in the Dock and menu bar instead of "Python"."""
    with contextlib.suppress(Exception):
        from AppKit import NSApplication, NSImage
        from Foundation import NSBundle

        info = NSBundle.mainBundle().infoDictionary()
        info["CFBundleName"] = "librepost"
        icon = Path(__file__).parent / "static" / "icon.svg"
        image = NSImage.alloc().initWithContentsOfFile_(str(icon))
        if image is not None:
            NSApplication.sharedApplication().setApplicationIconImage_(image)


def run(app: ASGIApp, sock: socket.socket, url: str, title: str) -> None:
    """Serve `app` on `sock` and show `url` in a window; returns when the window closes."""
    webview = _webview()
    config = uvicorn.Config(app, log_level="warning", access_log=False, server_header=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started:
        if not thread.is_alive() or time.monotonic() > deadline:
            raise DesktopUnavailable("The local server didn't start.")
        time.sleep(0.02)
    try:
        webview.create_window(
            title, url, width=1280, height=860, min_size=(720, 480), text_select=True
        )
        if sys.platform == "darwin":
            _mac_branding()
        webview.start(private_mode=True)
    finally:
        server.should_exit = True
        thread.join(timeout=5)
