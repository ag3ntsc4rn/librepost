"""What git says about the workspace: the branch, which files changed, and their diffs.

Read-only: librepost never stages, commits or pushes. Git runs with optional locks off (so
it never competes with your own git commands for the index lock), with fsmonitor and
external diff tools disabled (a repository's config can name programs to run), and with a
timeout. Without git, or outside a repository, everything here returns None.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

TIMEOUT = 5
MAX_DIFF = 512 * 1024

# Letter shown next to a file, and what it means.
LABELS = {
    "M": "modified",
    "A": "added",
    "D": "deleted",
    "R": "renamed",
    "U": "untracked: not in git yet",
    "!": "merge conflict",
}


class GitError(RuntimeError):
    pass


@dataclass
class Change:
    path: str  # relative to the workspace, with forward slashes
    code: str  # a key of LABELS
    staged: bool = False  # all of the change is staged

    @property
    def label(self) -> str:
        text = LABELS[self.code]
        return f"{text} (staged)" if self.staged and self.code in "MADR" else text


@dataclass
class Status:
    branch: str  # "" when detached
    commit: str  # short hash, "" before the first commit
    upstream: str = ""
    ahead: int = 0
    behind: int = 0
    changes: list[Change] = field(default_factory=list)

    @property
    def by_path(self) -> dict[str, Change]:
        return {change.path: change for change in self.changes}


def _git(root: Path, *args: str, strict: bool = False) -> str | None:
    """Git's output; None without git or on failure, unless `strict` asks for GitError."""
    git = shutil.which("git")
    if git is None:
        return None
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"}
    try:
        result = subprocess.run(
            [git, "-c", "core.fsmonitor=false", "-c", "core.quotepath=off", *args],
            cwd=root,
            capture_output=True,
            timeout=TIMEOUT,
            env=env,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        if not strict:
            return None
        raise GitError(result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout.decode("utf-8", errors="replace")


def _change(xy: str, path: str) -> Change:
    index, worktree = xy[0], xy[1]
    if "D" in xy:
        code = "D"
    elif "R" in xy:
        code = "R"
    elif index == "A":
        code = "A"
    else:
        code = "M"
    return Change(path, code, staged=worktree == ".")


def status(root: Path) -> Status | None:
    prefix = _git(root, "rev-parse", "--show-prefix")
    if prefix is None:
        return None
    prefix = prefix.strip()
    out = _git(
        root, "status", "--porcelain=v2", "--branch", "-z", "--untracked-files=all", "--", "."
    )
    if out is None:
        return None
    result = Status(branch="", commit="")
    records = iter(out.split("\0"))
    for record in records:
        if not record:
            continue
        kind = record[0]
        if record.startswith("# branch.oid "):
            oid = record.split()[2]
            result.commit = "" if oid == "(initial)" else oid[:7]
        elif record.startswith("# branch.head "):
            head = record.split(" ", 2)[2]
            result.branch = "" if head == "(detached)" else head
        elif record.startswith("# branch.upstream "):
            result.upstream = record.split(" ", 2)[2]
        elif record.startswith("# branch.ab "):
            ahead, behind = record.split()[2:4]
            result.ahead, result.behind = int(ahead), -int(behind)
        elif kind in "12u?":
            fields = record.split(" ", {"1": 8, "2": 9, "u": 10, "?": 1}[kind])
            path = fields[-1]
            if kind == "2":
                next(records, None)  # the original path of a rename
            if not path.startswith(prefix):
                continue
            path = path[len(prefix) :]
            if kind == "?":
                result.changes.append(Change(path, "U"))
            elif kind == "u":
                result.changes.append(Change(path, "!"))
            else:
                result.changes.append(_change(fields[1], path))
    result.changes.sort(key=lambda change: change.path)
    return result


def diff(root: Path, change: Change) -> str:
    """The change as a unified diff against the last commit. Untracked files show in full."""
    if change.code == "U" or (change.code == "A" and _git(root, "rev-parse", "HEAD") is None):
        return _new_file(root, change.path)
    out = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--no-color",
        "HEAD",
        "--",
        change.path,
        strict=True,
    )
    text = out or ""
    if len(text) > MAX_DIFF:
        text = text[:MAX_DIFF] + "\n… (diff truncated)"
    return text


def _new_file(root: Path, rel: str) -> str:
    path = root / rel
    try:
        with path.open("rb") as f:
            data = f.read(MAX_DIFF + 1)
    except OSError as exc:
        raise GitError(f"Can't read {rel}: {exc.strerror}") from None
    if b"\0" in data[:8000]:
        return f"new file {rel} (binary)"
    text = data[:MAX_DIFF].decode("utf-8", errors="replace")
    lines = [f"new file {rel}", *("+" + line for line in text.splitlines())]
    if len(data) > MAX_DIFF:
        lines.append("… (truncated)")
    return "\n".join(lines)
