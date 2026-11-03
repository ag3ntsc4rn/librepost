"""Run every request in a set of files, in order, carrying captured values along.

This is what `librepost test` uses in CI: each request's checks decide whether it
passes, and the results can be written as JUnit XML.
"""

from __future__ import annotations

import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from . import checks, connection, environments, runner, secretstore
from .checks import CheckResult
from .httpfile import HttpFileError
from .secretstore import SecretError
from .template import TemplateError
from .workspace import Workspace, WorkspaceError


@dataclass
class Step:
    file: str
    name: str
    method: str
    url: str = ""  # as sent, secrets masked
    status: int | None = None
    elapsed_ms: float = 0.0
    results: list[CheckResult] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def passed(self) -> bool:
        return not self.error and all(r.passed for r in self.results)


@dataclass
class Run:
    steps: list[Step] = field(default_factory=list)
    seconds: float = 0.0
    warnings: list[str] = field(default_factory=list)

    @property
    def failed(self) -> list[Step]:
        return [s for s in self.steps if not s.passed]

    @property
    def check_count(self) -> int:
        return sum(len(s.results) for s in self.steps)

    @property
    def checks_failed(self) -> int:
        return sum(1 for s in self.steps for r in s.results if not r.passed)


def files_in(paths: list[Path]) -> list[tuple[Path, str]]:
    """(workspace root, relative path) for each .http file, in a stable order."""
    found: list[tuple[Path, str]] = []
    for path in paths:
        if path.is_dir():
            workspace = Workspace(path)
            found.extend((workspace.root, rel) for rel in workspace.files())
        elif path.is_file():
            found.append((path.resolve().parent, path.name))
        else:
            raise WorkspaceError(f"{path} does not exist.")
    return found


def run(
    paths: list[Path],
    root: Path,
    env: str | None,
    *,
    bail: bool = False,
    timeout: float = 30.0,
    verify: bool = True,
    transport: httpx.BaseTransport | None = None,
    secret_lookup: Callable[[str], str] = secretstore.lookup,
    on_step: Callable[[Step], None] | None = None,
) -> Run:
    started = time.perf_counter()
    result = Run()
    env_vars = environments.variables(root, env)
    conn = connection.load(root, env)
    result.warnings = conn.warnings
    captured: dict[str, str] = {}
    secret: set[str] = set()

    for base, rel in files_in(paths):
        workspace = Workspace(base)
        httpfile = workspace.load(rel)
        label = str((base / rel).relative_to(root)) if (base / rel).is_relative_to(root) else rel
        for request in httpfile.requests:
            step = Step(file=label, name=request.label, method=request.method)
            result.steps.append(step)
            try:
                variables = {**httpfile.variables, **env_vars, **captured}
                prepared = runner.prepare(
                    request, variables, secret_lookup, mask={captured[n] for n in secret}
                )
                plan = checks.parse(prepared.checks)
                net = connection.settings(conn, prepared.renderer, insecure=not verify)
                step.url = prepared.renderer.mask(prepared.url)
                response = runner.send(
                    prepared,
                    timeout=timeout,
                    verify=net.verify,
                    proxy=net.proxy,
                    transport=transport,
                )
            except (
                checks.CheckError,
                TemplateError,
                SecretError,
                HttpFileError,
                connection.ConnectionError_,
            ) as exc:
                step.error = str(exc)
            except httpx.HTTPError as exc:
                step.error = f"{type(exc).__name__}: {exc}"
            else:
                step.status = response.status
                step.elapsed_ms = response.elapsed_ms
                outcome = checks.run(plan, response)
                for name, val in outcome.values.items():
                    captured[name] = val
                    if name in outcome.secret:
                        secret.add(name)
                    else:
                        secret.discard(name)
                prepared.renderer.secret_values.update(captured[n] for n in secret if captured[n])
                step.results = [
                    CheckResult(
                        prepared.renderer.mask(r.text), r.passed, prepared.renderer.mask(r.actual)
                    )
                    for r in outcome.results
                ]
                step.missing = outcome.missing
            if step.error:
                masked = {captured[n] for n in secret if captured[n]}
                for val in sorted(masked, key=len, reverse=True):
                    step.error = step.error.replace(val, "••••••")
            if on_step:
                on_step(step)
            if bail and not step.passed:
                result.seconds = time.perf_counter() - started
                return result
    result.seconds = time.perf_counter() - started
    return result


def junit(result: Run) -> str:
    """JUnit XML, as read by GitHub Actions, GitLab, Jenkins and most CI systems."""
    suites = ET.Element(
        "testsuites",
        name="librepost",
        tests=str(len(result.steps)),
        failures=str(sum(1 for s in result.steps if not s.error and not s.passed)),
        errors=str(sum(1 for s in result.steps if s.error)),
        time=f"{result.seconds:.3f}",
    )
    by_file: dict[str, list[Step]] = {}
    for step in result.steps:
        by_file.setdefault(step.file, []).append(step)
    for file, steps in by_file.items():
        suite = ET.SubElement(
            suites,
            "testsuite",
            name=file,
            tests=str(len(steps)),
            failures=str(sum(1 for s in steps if not s.error and not s.passed)),
            errors=str(sum(1 for s in steps if s.error)),
            time=f"{sum(s.elapsed_ms for s in steps) / 1000:.3f}",
        )
        for step in steps:
            case = ET.SubElement(
                suite,
                "testcase",
                classname=file,
                name=step.name,
                time=f"{step.elapsed_ms / 1000:.3f}",
            )
            if step.error:
                ET.SubElement(case, "error", message=step.error).text = step.error
            elif not step.passed:
                failed = [r for r in step.results if not r.passed]
                lines = [f"{r.text.removeprefix('@expect ')} (got {r.actual})" for r in failed]
                ET.SubElement(
                    case, "failure", message=f"{len(failed)} check(s) failed"
                ).text = "\n".join(lines)
            out = [f"{step.method} {step.url}"]
            if step.status is not None:
                out.append(f"status {step.status}, {step.elapsed_ms:.0f} ms")
            out.extend(f"{'PASS' if r.passed else 'FAIL'} {r.text}" for r in step.results)
            ET.SubElement(case, "system-out").text = "\n".join(out)
    ET.indent(suites)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(suites, encoding="unicode") + "\n"
    )
