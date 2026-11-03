"""A folder of `.http` files. Every path from the UI goes through `Workspace.path()`,
which refuses anything outside the folder."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .httpfile import HttpFile, Request, dumps, parse

EXTENSIONS = (".http", ".rest")
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "dist",
    "build",
}


class WorkspaceError(ValueError):
    pass


@dataclass
class Entry:
    path: str
    # (method, name or URL) for each request in the file.
    requests: list[tuple[str, str]]
    error: str = ""


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def files(self) -> list[str]:
        found = []
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for filename in filenames:
                if filename.endswith(EXTENSIONS):
                    found.append(Path(dirpath, filename).relative_to(self.root).as_posix())
        return sorted(found)

    def entries(self) -> list[Entry]:
        result = []
        for rel in self.files():
            try:
                requests = [(r.method, r.name or r.url) for r in self.load(rel).requests]
                result.append(Entry(rel, requests))
            except (OSError, UnicodeDecodeError, WorkspaceError) as exc:
                result.append(Entry(rel, [], str(exc)))
        return result

    def path(self, rel: str) -> Path:
        pure = PurePosixPath(rel.replace("\\", "/"))
        if not rel or pure.is_absolute() or ".." in pure.parts or ":" in rel:
            raise WorkspaceError(f"Invalid file path: {rel!r}")
        if not pure.name.endswith(EXTENSIONS):
            raise WorkspaceError("Request files must end in .http or .rest.")
        if any(part in SKIP_DIRS or part.startswith(".") for part in pure.parts):
            raise WorkspaceError(f"Invalid file path: {rel!r}")
        full = self.root.joinpath(*pure.parts)
        # Symlinks must not lead out of the workspace either.
        if not full.resolve().is_relative_to(self.root):
            raise WorkspaceError(f"{rel} points outside the workspace.")
        return full

    def load(self, rel: str) -> HttpFile:
        path = self.path(rel)
        if not path.is_file():
            raise WorkspaceError(f"{rel} does not exist.")
        return parse(path.read_text(encoding="utf-8"))

    def request(self, rel: str, index: int) -> Request:
        requests = self.load(rel).requests
        if not 0 <= index < len(requests):
            raise WorkspaceError(f"{rel} has no request #{index + 1}.")
        return requests[index]

    def save(self, rel: str, httpfile: HttpFile) -> None:
        path = self.path(rel)
        text = dumps(httpfile)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".librepost-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def create(self, rel: str, request: Request) -> None:
        if self.path(rel).exists():
            raise WorkspaceError(f"{rel} already exists.")
        self.save(rel, HttpFile([request]))

    def update(self, rel: str, index: int, request: Request) -> None:
        httpfile = self.load(rel)
        if not 0 <= index < len(httpfile.requests):
            raise WorkspaceError(f"{rel} has no request #{index + 1}.")
        old = httpfile.requests[index]
        request.comments, request.trailer = old.comments, old.trailer
        httpfile.requests[index] = request
        self.save(rel, httpfile)

    def append(self, rel: str, request: Request) -> int:
        httpfile = self.load(rel)
        httpfile.requests.append(request)
        self.save(rel, httpfile)
        return len(httpfile.requests) - 1

    def remove(self, rel: str, index: int) -> None:
        """Remove one request; the file is deleted when nothing is left in it."""
        httpfile = self.load(rel)
        if not 0 <= index < len(httpfile.requests):
            raise WorkspaceError(f"{rel} has no request #{index + 1}.")
        del httpfile.requests[index]
        if httpfile.requests or httpfile.variables:
            self.save(rel, httpfile)
        else:
            self.path(rel).unlink()
