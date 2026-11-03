"""Find literal secrets in request and environment files before they are committed.

Secrets belong in `{{secret:...}}` references or in the gitignored
`http-client.private.env.json`; this check flags anything that looks like a real
credential written straight into a file git will track.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .environments import PRIVATE_FILE, PUBLIC_FILE
from .workspace import EXTENSIONS, SKIP_DIRS

TOKEN_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe-key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{16,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

SENSITIVE_HEADER = re.compile(
    r"^(authorization|proxy-authorization|cookie|x-api-key|api-key|x-auth-token|x-access-token)$",
    re.IGNORECASE,
)
SENSITIVE_NAME = re.compile(
    r"(password|passwd|secret|token|api[-_]?key|apikey|credential|private[-_]?key)",
    re.IGNORECASE,
)
PLACEHOLDER_VALUE = re.compile(
    r"^(|<[^>]*>|x+|\*+|\.\.\.|changeme|change-me|example|dummy|redacted|todo|none|null|true|false)$",
    re.IGNORECASE,
)


@dataclass
class Leak:
    path: str
    line: int
    rule: str
    message: str


def _templated(value: str) -> bool:
    return "{{" in value


def literal_credential(value: str) -> bool:
    value = value.strip()
    if _templated(value):
        return False
    # "Bearer abc" -> "abc"; "Basic" alone is a placeholder.
    parts = value.split(None, 1)
    if len(parts) == 2 and parts[0].lower() in ("bearer", "basic", "token", "digest", "apikey"):
        value = parts[1].strip()
        if parts[0].lower() == "basic" and " " in value:
            # JetBrains form "Basic user password": the password is what matters.
            value = value.split(None, 1)[1]
            if _templated(value):
                return False
    # Prose such as "Your consumer secret" is a placeholder; real tokens have no spaces.
    # Cookie headers ("a=1; b=2") do, so only words without = or ; count as prose.
    if " " in value and not re.search(r"[=;]", value):
        return False
    return not PLACEHOLDER_VALUE.match(value) and len(value) >= 8


def _scan_text(rel: str, text: str, is_http: bool) -> list[Leak]:
    leaks = []
    for number, line in enumerate(text.splitlines(), start=1):
        reported = False
        for rule, pattern in TOKEN_PATTERNS:
            if pattern.search(line):
                leaks.append(Leak(rel, number, rule, f"Looks like a {rule.replace('-', ' ')}."))
                reported = True
                break
        if reported or not is_http:
            continue
        key, sep, value = line.partition(":")
        if sep and SENSITIVE_HEADER.match(key.strip()) and literal_credential(value):
            leaks.append(
                Leak(
                    rel,
                    number,
                    "literal-header",
                    f"{key.strip()} has a literal value; use {{{{secret:keychain/<name>}}}} instead.",
                )
            )
    return leaks


def _scan_env(rel: str, text: str) -> list[Leak]:
    leaks = _scan_text(rel, text, is_http=False)
    if leaks:
        return leaks
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []
    lines = text.splitlines()
    for env, values in data.items():
        if not isinstance(values, dict):
            continue
        for key, value in values.items():
            if isinstance(value, str) and SENSITIVE_NAME.search(key) and literal_credential(value):
                number = next((i for i, line in enumerate(lines, start=1) if f'"{key}"' in line), 1)
                leaks.append(
                    Leak(
                        rel,
                        number,
                        "literal-env-secret",
                        f"{env}.{key} has a literal value; move it to {PRIVATE_FILE} or use {{{{secret:...}}}}.",
                    )
                )
    return leaks


def _candidates(paths: list[Path]) -> list[Path]:
    found = []
    for path in paths:
        if path.is_dir():
            for child in sorted(path.rglob("*")):
                rel_parts = child.relative_to(path).parts
                if any(part in SKIP_DIRS for part in rel_parts):
                    continue
                if child.is_file() and (
                    child.name.endswith(EXTENSIONS) or child.name in (PUBLIC_FILE, PRIVATE_FILE)
                ):
                    found.append(child)
        elif path.is_file():
            found.append(path)
    return found


def _git_ignored(path: Path) -> bool | None:
    """True/False if git says whether the file is ignored; None outside a repo or without git."""
    git = shutil.which("git")
    if git is None:
        return None
    try:
        result = subprocess.run(
            [git, "check-ignore", "-q", "--", path.name],
            cwd=path.parent,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None  # 128: not a git repository


def scan(paths: list[Path], display_root: Path | None = None) -> list[Leak]:
    leaks: list[Leak] = []
    for path in _candidates(paths):
        try:
            rel = str(path.relative_to(display_root)) if display_root else str(path)
        except ValueError:
            rel = str(path)
        if path.name == PRIVATE_FILE:
            # The private file is supposed to hold secrets, but must never be committed.
            if _git_ignored(path) is False:
                leaks.append(
                    Leak(rel, 1, "private-env-tracked", f"{PRIVATE_FILE} is not gitignored.")
                )
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if path.name.endswith(EXTENSIONS):
            leaks.extend(_scan_text(rel, text, is_http=True))
        elif path.suffix == ".json":
            leaks.extend(_scan_env(rel, text))
    return leaks
