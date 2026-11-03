from __future__ import annotations

import contextlib
import getpass
import secrets
import socket
import sys
import webbrowser
from pathlib import Path
from typing import Annotated

import httpx
import typer
from rich.console import Console

from . import __version__, environments, leakcheck, runner, secretstore
from .environments import EnvFileError
from .httpfile import HttpFileError, parse
from .importers.sanitize import Secret
from .secretstore import SecretError
from .template import TemplateError

app = typer.Typer(
    help="A free, local-first API client. Requests are .http files; secrets stay in your keychain.",
    no_args_is_help=True,
    add_completion=False,
)
secret_app = typer.Typer(help="Store secrets in the OS keychain for {{secret:keychain/<name>}}.")
app.add_typer(secret_app, name="secret")

out = Console(highlight=False)
err = Console(stderr=True, highlight=False)

DEFAULT_PORT = 8765


def _version(value: bool) -> None:
    if value:
        out.print(f"librepost {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    pass


def _bind(port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sys.platform != "win32":
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        if port == 0:
            raise
        sock.bind(("127.0.0.1", 0))
    return sock


@app.command()
def ui(
    directory: Annotated[
        Path, typer.Argument(help="Folder holding your .http files.", file_okay=False)
    ] = Path("."),
    port: Annotated[
        int, typer.Option(help="Port on 127.0.0.1 (a free one is picked if it's taken).")
    ] = DEFAULT_PORT,
    open_browser: Annotated[
        bool, typer.Option("--open/--no-open", help="Open the UI in your browser.")
    ] = True,
) -> None:
    """Start the UI on 127.0.0.1 and open it in your browser."""
    import uvicorn

    from .server import create_app

    if not directory.is_dir():
        err.print(f"[red]Not a folder:[/] {directory}")
        raise typer.Exit(2)
    sock = _bind(port)
    port = sock.getsockname()[1]
    token = secrets.token_urlsafe(32)
    url = f"http://127.0.0.1:{port}/?token={token}"
    application = create_app(directory, port=port, token=token)

    out.print(f"[bold green]librepost {__version__}[/] serving [bold]{directory.resolve()}[/]")
    out.print(f"Open: [link={url}]{url}[/link]")
    out.print(
        "[dim]Only this machine can connect, and only with the link above. Ctrl+C stops it.[/]"
    )
    if open_browser:
        webbrowser.open(url)
    config = uvicorn.Config(application, log_level="warning", access_log=False, server_header=False)
    with contextlib.suppress(KeyboardInterrupt):
        uvicorn.Server(config).run(sockets=[sock])


@app.command()
def run(
    file: Annotated[Path, typer.Argument(help="An .http file.", exists=True, dir_okay=False)],
    name: Annotated[
        str | None, typer.Option("--name", "-n", help="Request name (default: the first one).")
    ] = None,
    env: Annotated[str | None, typer.Option("--env", "-e", help="Environment to use.")] = None,
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Show the request and response headers.")
    ] = False,
    fail: Annotated[
        bool, typer.Option("--fail", "-f", help="Exit with status 22 on HTTP 4xx/5xx.")
    ] = False,
    insecure: Annotated[
        bool, typer.Option("--insecure", "-k", help="Don't verify TLS certificates.")
    ] = False,
    timeout: Annotated[float, typer.Option(help="Timeout in seconds.")] = 30.0,
) -> None:
    """Send a request from an .http file and print the response."""
    try:
        httpfile = parse(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        err.print(f"[red]Can't read {file}:[/] {exc}")
        raise typer.Exit(2) from None
    if not httpfile.requests:
        err.print(f"[red]No requests in {file}.[/]")
        raise typer.Exit(2)
    if name is None:
        request = httpfile.requests[0]
    else:
        matches = [r for r in httpfile.requests if r.name == name]
        if not matches:
            names = ", ".join(r.name for r in httpfile.requests if r.name) or "(none)"
            err.print(f"[red]No request named {name!r}.[/] Names in this file: {names}")
            raise typer.Exit(2)
        request = matches[0]

    root = _workspace_root(file)
    try:
        variables = dict(httpfile.variables)
        variables.update(environments.variables(root, env))
        prepared = runner.prepare(request, variables)
    except (EnvFileError, TemplateError, SecretError, HttpFileError) as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from None

    if verbose:
        for line in prepared.masked().split("\n\n", 1)[0].splitlines():
            err.print(f"[dim]> {line}[/]")
        err.print()
    try:
        result = runner.send(prepared, timeout=timeout, verify=not insecure)
    except httpx.HTTPError as exc:
        err.print(f"[red]{type(exc).__name__}:[/] {prepared.renderer.mask(str(exc))}")
        raise typer.Exit(1) from None

    colour = "green" if result.status < 400 else "red"
    err.print(
        f"[bold {colour}]{result.status} {result.reason}[/] "
        f"[dim]{result.elapsed_ms:.0f} ms, {len(result.body)} bytes[/]"
    )
    if verbose:
        for key, value in result.headers:
            err.print(f"[dim]< {key}: {value}[/]")
        err.print()
    sys.stdout.buffer.write(result.body)
    if result.body and not result.body.endswith(b"\n") and sys.stdout.isatty():
        sys.stdout.write("\n")
    sys.stdout.flush()
    if fail and result.status >= 400:
        raise typer.Exit(22)


def _workspace_root(file: Path) -> Path:
    """The nearest folder above the file that has an environment file, else the file's folder."""
    start = file.resolve().parent
    for folder in (start, *start.parents):
        if (folder / environments.PUBLIC_FILE).is_file() or (
            folder / environments.PRIVATE_FILE
        ).is_file():
            return folder
        if (folder / ".git").exists():
            break
    return start


@app.command()
def check(
    paths: Annotated[
        list[Path] | None, typer.Argument(help="Files or folders (default: current folder).")
    ] = None,
) -> None:
    """Find literal secrets in .http and environment files. Exits 1 if any are found."""
    targets = paths or [Path(".")]
    leaks = leakcheck.scan(targets, display_root=Path.cwd())
    for leak in leaks:
        out.print(f"[bold]{leak.path}:{leak.line}[/] [red]{leak.rule}[/] {leak.message}")
    if leaks:
        out.print(
            f"\n[red]{len(leaks)} possible secret(s).[/] Use {{{{secret:...}}}} references instead."
        )
        raise typer.Exit(1)
    out.print("[green]No literal secrets found.[/]")


@app.command("import")
def import_(
    source: Annotated[
        str,
        typer.Argument(
            help="A Postman collection or environment export, a HAR file, a file holding curl "
            "commands, '-' for stdin, or a curl command in quotes."
        ),
    ],
    into: Annotated[
        Path, typer.Option("--into", "-o", help="Workspace folder to import into.", file_okay=False)
    ] = Path("."),
    fmt: Annotated[
        str | None,
        typer.Option("--format", help="postman, postman-env, har or curl (default: detect)."),
    ] = None,
    file: Annotated[
        str, typer.Option("--file", help="Target .http file for curl imports (appended to).")
    ] = "imported.http",
    everything: Annotated[
        bool, typer.Option("--all", help="HAR: keep images, scripts and other non-API requests.")
    ] = False,
    save_secrets: Annotated[
        bool,
        typer.Option(
            "--save-secrets", help="Store credentials found in the import in the OS keychain."
        ),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Show what would be imported; write nothing.")
    ] = False,
) -> None:
    """Import requests from Postman, a HAR file or curl. Credentials never land in files."""
    from . import importers

    text = _read_source(source)
    try:
        result = importers.convert(text, fmt, name=file, everything=everything)
    except importers.ImporterError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from None

    for rel, requests in result.files.items():
        out.print(f"[bold]{rel}[/] [dim]({len(requests)} request(s))[/]")
    for env, values in result.environments.items():
        out.print(f"[bold]{environments.PUBLIC_FILE}[/] [dim]{env}: {len(values)} variable(s)[/]")
    for warning in result.warnings:
        out.print(f"[yellow]![/] {warning}")

    if dry_run:
        out.print("\n[dim]Dry run: nothing written.[/]")
    else:
        into.mkdir(parents=True, exist_ok=True)
        try:
            report = importers.write(result, into, append=result.files.keys() == {file})
        except (importers.ImporterError, OSError, ValueError) as exc:
            err.print(f"[red]{exc}[/]")
            raise typer.Exit(1) from None
        for rel in report.created:
            out.print(f"[green]Created[/] {rel}")
        for rel in report.appended:
            out.print(f"[green]Appended to[/] {rel}")
        if report.env_added:
            out.print(
                f"[green]Added[/] {len(report.env_added)} variable(s) to {environments.PUBLIC_FILE}"
            )
        for key in report.env_kept:
            out.print(f"[yellow]![/] Kept your existing value for {key}")

    _handle_secrets(result.secrets, save=save_secrets and not dry_run)


def _read_source(source: str) -> str:
    if source == "-":
        return sys.stdin.read()
    if source.lstrip().startswith("curl ") and not Path(source).exists():
        return source
    try:
        return Path(source).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        err.print(f"[red]Can't read {source}:[/] {exc}")
        raise typer.Exit(2) from None


def _handle_secrets(found: list[Secret], *, save: bool) -> None:
    if not found:
        return
    out.print(f"\n{len(found)} credential(s) were replaced with keychain references:")
    missing = []
    for secret in found:
        status = ""
        if save and secret.value:
            try:
                secretstore.store(secret.name, secret.value)
                status = "[green]saved to keychain[/]"
            except SecretError as exc:
                status = f"[red]not saved: {exc}[/]"
                missing.append(secret.name)
        else:
            missing.append(secret.name)
            status = "[dim]empty in the export[/]" if not secret.value else ""
        out.print(f"  {secret.name} [dim]({secret.source})[/] {status}")
    if missing:
        out.print("\nAdd the values with:")
        for name in missing:
            out.print(f"  librepost secret set {name}")
        if not save and any(s.value for s in found):
            out.print(
                "[dim]Or re-run with --save-secrets to store the values found in the import.[/]"
            )


EXAMPLE_ENV = """{
  "dev": {
    "baseUrl": "https://httpbin.org",
    "token": "{{secret:keychain/demo-token}}"
  }
}
"""

EXAMPLE_HTTP = """# Requests are plain text: commit them, review them in pull requests, share them.
# @name get-example
GET {{baseUrl}}/get?hello=world
Accept: application/json

###

# The token comes from your OS keychain. Add it with: librepost secret set demo-token
# @name bearer-example
GET {{baseUrl}}/bearer
Authorization: Bearer {{token}}

###

# @name post-example
POST {{baseUrl}}/post
Content-Type: application/json

{
  "id": "{{$uuid}}",
  "sentAt": "{{$isoTimestamp}}"
}
"""


@app.command()
def init(
    directory: Annotated[Path, typer.Argument(file_okay=False)] = Path("."),
) -> None:
    """Create an example environment file and requests, and gitignore the private env file."""
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for rel, text in (
        (environments.PUBLIC_FILE, EXAMPLE_ENV),
        ("requests/example.http", EXAMPLE_HTTP),
    ):
        path = directory / rel
        if path.exists():
            out.print(f"[dim]Kept existing {rel}[/]")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(rel)

    gitignore = directory / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    if environments.PRIVATE_FILE not in existing.splitlines():
        prefix = "" if not existing or existing.endswith("\n") else "\n"
        with gitignore.open("a", encoding="utf-8", newline="\n") as f:
            f.write(
                f"{prefix}# librepost: per-machine values, never committed\n{environments.PRIVATE_FILE}\n"
            )
        written.append(".gitignore")

    for rel in written:
        out.print(f"[green]Wrote[/] {rel}")
    out.print("\nNext: [bold]librepost ui[/]  (and optionally: librepost secret set demo-token)")


@secret_app.command("set")
def secret_set(name: Annotated[str, typer.Argument(help="Secret name.")]) -> None:
    """Store a secret in the OS keychain. The value is read without echoing it."""
    value = (
        getpass.getpass(f"Value for {name}: ")
        if sys.stdin.isatty()
        else sys.stdin.readline().rstrip("\n")
    )
    if not value:
        err.print("[red]Empty value; nothing stored.[/]")
        raise typer.Exit(2)
    try:
        secretstore.store(name, value)
    except SecretError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    out.print(f"[green]Stored[/] {name}. Use it as {{{{secret:keychain/{name}}}}}")


@secret_app.command("delete")
def secret_delete(name: Annotated[str, typer.Argument(help="Secret name.")]) -> None:
    """Remove a secret from the OS keychain."""
    try:
        secretstore.delete(name)
    except SecretError as exc:
        err.print(f"[red]{exc}[/]")
        raise typer.Exit(1) from None
    out.print(f"[green]Deleted[/] {name}.")
