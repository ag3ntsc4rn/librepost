"""Requests sent from the UI, kept so you can look back at them and send them again.

History lives outside the workspace, so it can never be committed:

    macOS    ~/Library/Application Support/librepost/history/
    Windows  %LOCALAPPDATA%\\librepost\\history\\
    others   $XDG_STATE_HOME/librepost/history/  (default ~/.local/state)

One owner-only JSON Lines file per workspace keeps the newest LIMIT entries. Entries hold
what the UI showed: secret values are masked before anything is written, and large
response bodies are cut short.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as dt
import hashlib
import json
import os
import secrets
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LIMIT = 200
MAX_BODY = 64 * 1024


def state_dir() -> Path:
    override = os.environ.get("LIBREPOST_STATE_DIR")
    if override:
        return Path(override)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "librepost"
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA")
        return Path(base) / "librepost" if base else Path.home() / "AppData" / "Local" / "librepost"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "librepost"


@dataclass
class Entry:
    time: float
    method: str
    url: str  # as sent, masked
    id: str = ""
    env: str = ""
    file: str = ""
    name: str = ""
    # The request as written (placeholders kept), to open it in the editor again.
    request: dict[str, Any] = field(default_factory=dict)
    sent: str = ""
    error: str = ""
    status: int = 0
    reason: str = ""
    http_version: str = ""
    final_url: str = ""
    elapsed_ms: float = 0.0
    size: int = 0
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    tls: dict[str, str] = field(default_factory=dict)
    redirects: list[str] = field(default_factory=list)
    results: list[tuple[str, bool, str]] = field(default_factory=list)

    @property
    def when(self) -> str:
        moment = dt.datetime.fromtimestamp(self.time)
        if moment.date() == dt.date.today():
            return moment.strftime("%H:%M:%S")
        return moment.strftime("%Y-%m-%d %H:%M")

    @property
    def failed_checks(self) -> int:
        return sum(1 for _, passed, _ in self.results if not passed)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        names = {f.name for f in dataclasses.fields(cls)}
        entry = cls(**{k: v for k, v in data.items() if k in names})
        entry.headers = [(str(k), str(v)) for k, v in entry.headers]
        entry.results = [(str(t), bool(p), str(a)) for t, p, a in entry.results]
        return entry


class History:
    def __init__(self, root: Path, directory: Path | None = None, limit: int = LIMIT) -> None:
        digest = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:16]
        self.path = (directory or state_dir() / "history") / f"{digest}.jsonl"
        self.limit = limit
        self._lock = threading.Lock()
        self._count: int | None = None

    def add(self, entry: Entry) -> str:
        entry.id = entry.id or f"{int(entry.time * 1000):x}{secrets.token_hex(3)}"
        if len(entry.body) > MAX_BODY:
            entry.body = entry.body[:MAX_BODY] + "\n\n… (cut short in history)"
        line = json.dumps(dataclasses.asdict(entry), ensure_ascii=False) + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line)
            if self._count is None:
                self._count = len(self._lines())
            else:
                self._count += 1
            # Trim now and then rather than rewriting the file on every request.
            if self._count > self.limit + max(10, self.limit // 4):
                self._rewrite(self._lines()[-self.limit :])
        return entry.id

    def entries(self) -> list[Entry]:
        """Newest first. Unreadable lines are skipped."""
        with self._lock:
            lines = self._lines()
        result = []
        for line in reversed(lines):
            with contextlib.suppress(ValueError, TypeError):
                result.append(Entry.from_dict(json.loads(line)))
        return result

    def get(self, entry_id: str) -> Entry | None:
        return next((e for e in self.entries() if e.id == entry_id), None)

    def clear(self) -> None:
        with self._lock:
            self.path.unlink(missing_ok=True)
            self._count = 0

    def _lines(self) -> list[str]:
        try:
            text = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        return [line for line in text.splitlines() if line.strip()]

    def _rewrite(self, lines: list[str]) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".history-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.writelines(line + "\n" for line in lines)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
        self._count = len(lines)


def matches(entry: Entry, query: str) -> bool:
    query = query.strip().lower()
    if not query:
        return True
    haystack = " ".join(
        [entry.method, entry.url, entry.name, entry.file, entry.env, str(entry.status or "")]
    ).lower()
    return all(word in haystack for word in query.split())
