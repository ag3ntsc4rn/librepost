"""Import requests from Postman, HAR files and curl commands.

Each importer returns an ImportResult; `write()` puts it into a workspace without
overwriting anything, and literal credentials have already been replaced with secret
references by then (see sanitize.py).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..environments import PUBLIC_FILE
from ..httpfile import HttpFile, Request
from ..workspace import Workspace
from .sanitize import Secret

FORMATS = ("postman", "postman-env", "har", "curl")


class ImporterError(ValueError):
    pass


@dataclass
class ImportResult:
    # Workspace-relative path -> requests for that file.
    files: dict[str, list[Request]] = field(default_factory=dict)
    # Environment name -> variables, merged into http-client.env.json.
    environments: dict[str, dict[str, str]] = field(default_factory=dict)
    secrets: list[Secret] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def request_count(self) -> int:
        return sum(len(requests) for requests in self.files.values())


@dataclass
class WriteReport:
    created: list[str] = field(default_factory=list)
    appended: list[str] = field(default_factory=list)
    env_added: list[str] = field(default_factory=list)
    env_kept: list[str] = field(default_factory=list)


def detect(text: str) -> str:
    stripped = text.lstrip()
    if stripped.startswith("curl ") or stripped.startswith("curl\t"):
        return "curl"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        raise ImporterError(
            "Not a Postman export, HAR file or curl command (expected JSON or text starting with 'curl')."
        ) from None
    if isinstance(data, dict):
        if isinstance(data.get("log"), dict) and "entries" in data["log"]:
            return "har"
        if "collection" in data and isinstance(data["collection"], dict):
            return "postman"  # Postman API export wraps the collection
        if "item" in data and isinstance(data.get("info"), dict):
            return "postman"
        if "values" in data and (
            data.get("_postman_variable_scope") in ("environment", "globals") or "name" in data
        ):
            return "postman-env"
    raise ImporterError(
        "Unrecognised JSON: expected a Postman collection or environment, or a HAR file."
    )


def convert(
    text: str, fmt: str | None = None, *, name: str = "", everything: bool = False
) -> ImportResult:
    fmt = fmt or detect(text)
    if fmt == "curl":
        from . import curl

        return curl.convert(text, target=name or "imported.http")
    if fmt == "har":
        from . import har

        return har.convert(_load(text), everything=everything)
    if fmt == "postman":
        from . import postman

        return postman.convert_collection(_load(text))
    if fmt == "postman-env":
        from . import postman

        return postman.convert_environment(_load(text))
    raise ImporterError(f"Unknown format {fmt!r}; use one of: {', '.join(FORMATS)}.")


def _load(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImporterError(f"Invalid JSON: {exc}") from None


def write(result: ImportResult, root: Path, *, append: bool = False) -> WriteReport:
    """Write the result into the workspace at `root`.

    New files never replace existing ones: a clash gets a numbered name, or, with
    `append=True`, the requests are added to the end of the existing file.
    """
    workspace = Workspace(root)
    report = WriteReport()
    for rel, requests in result.files.items():
        if not requests:
            continue
        if workspace.path(rel).exists():
            if append:
                for request in requests:
                    workspace.append(rel, request)
                report.appended.append(rel)
                continue
            rel = _free_name(workspace, rel)
        workspace.save(rel, HttpFile(list(requests)))
        report.created.append(rel)
    if result.environments:
        _merge_environments(workspace.root / PUBLIC_FILE, result.environments, report)
    return report


def _free_name(workspace: Workspace, rel: str) -> str:
    stem, dot, ext = rel.rpartition(".")
    n = 2
    while workspace.path(f"{stem}-{n}{dot}{ext}").exists():
        n += 1
    return f"{stem}-{n}{dot}{ext}"


def _merge_environments(
    path: Path, incoming: dict[str, dict[str, str]], report: WriteReport
) -> None:
    data: dict[str, dict[str, str]] = {}
    if path.exists():
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ImporterError(f"{path.name} is not a JSON object; not changing it.")
        data = loaded
    for env, values in incoming.items():
        target = data.setdefault(env, {})
        for key, value in values.items():
            if key in target and target[key] != value:
                report.env_kept.append(f"{env}.{key}")
            elif key not in target:
                target[key] = value
                report.env_added.append(f"{env}.{key}")
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
