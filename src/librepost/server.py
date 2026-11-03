"""The local web UI.

The server listens on 127.0.0.1 only. A web server that sends HTTP requests on your behalf
is an open proxy into your network for any website you visit, unless it is locked down, so
every request must pass all of these:

1. Host header is 127.0.0.1:<port> or localhost:<port> (blocks DNS rebinding).
2. A session cookie matching the random token printed at startup. The launch URL carries the
   token once; it is swapped for an HttpOnly, SameSite=Strict cookie scoped to this port.
3. State-changing requests carry a same-origin Origin header and the HX-Request header,
   which cross-site pages can't send without a CORS preflight we never answer.

Responses carry a strict Content-Security-Policy (no inline or third-party scripts) and
Cache-Control: no-store. Response bodies are only ever shown as escaped text.
"""

from __future__ import annotations

import contextlib
import json
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

import httpx
from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import FormData
from starlette.requests import Request as HttpRequest
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from . import __version__, environments, importers, manage, runner, secretstore
from .environments import EnvFileError
from .httpfile import METHODS, HttpFileError, Request, format_headers, parse_headers, validate
from .secretstore import SecretError
from .template import TemplateError
from .workspace import Workspace, WorkspaceError

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'"
)
SECURITY_HEADERS = {
    "content-security-policy": CSP,
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
}
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MAX_DISPLAY = 2 * 1024 * 1024
MAX_IMPORT = 50 * 1024 * 1024

NEW_REQUEST = Request(method="GET", url="https://example.com", name="new-request")


class Guard:
    """ASGI middleware enforcing the checks in the module docstring."""

    def __init__(self, app: ASGIApp, *, port: int, token: str) -> None:
        self.app = app
        self.token = token
        self.cookie = f"librepost_{port}"
        self.hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        self.origins = {f"http://{host}" for host in self.hosts}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = HttpRequest(scope)
        response = self.check(request)
        if response is None:

            async def send_with_headers(message: Message) -> None:
                if message["type"] == "http.response.start":
                    headers = list(message.get("headers", []))
                    headers.extend((k.encode(), v.encode()) for k, v in SECURITY_HEADERS.items())
                    message["headers"] = headers
                await send(message)

            await self.app(scope, receive, send_with_headers)
            return
        response.headers.update(SECURITY_HEADERS)
        await response(scope, receive, send)

    def check(self, request: HttpRequest) -> Response | None:
        if request.headers.get("host") not in self.hosts:
            return PlainTextResponse("Invalid Host header.", status_code=421)
        query_token = request.query_params.get("token")
        if request.method == "GET" and request.url.path == "/" and query_token:
            if not secrets.compare_digest(query_token, self.token):
                return PlainTextResponse("Invalid token.", status_code=403)
            redirect = RedirectResponse("/", status_code=303)
            redirect.set_cookie(self.cookie, self.token, httponly=True, samesite="strict", path="/")
            return redirect
        if request.url.path.startswith("/static/"):
            return None
        cookie = request.cookies.get(self.cookie, "")
        if not secrets.compare_digest(cookie, self.token):
            return PlainTextResponse(
                "Not authorised. Open the link printed in the terminal where librepost is running.",
                status_code=403,
            )
        if request.method in UNSAFE_METHODS and (
            request.headers.get("origin") not in self.origins
            or request.headers.get("hx-request") != "true"
        ):
            return PlainTextResponse("Cross-origin request refused.", status_code=403)
        return None


def create_app(
    root: Path,
    *,
    port: int,
    token: str,
    transport: httpx.BaseTransport | None = None,
    secret_lookup: Callable[[str], str] = secretstore.lookup,
    secret_store: Callable[[str, str], None] = secretstore.store,
    secret_exists: Callable[[str], bool] = secretstore.exists,
    secret_delete: Callable[[str], None] = secretstore.delete,
    secret_names: Callable[[], list[str]] = secretstore.names,
) -> ASGIApp:
    workspace = Workspace(root)
    jinja = Environment(
        loader=PackageLoader("librepost", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def render(
        name: str, status_code: int = 200, trigger: str = "", **context: Any
    ) -> HTMLResponse:
        html = jinja.get_template(name).render(version=__version__, methods=METHODS, **context)
        response = HTMLResponse(html, status_code=status_code)
        if trigger:
            response.headers["HX-Trigger"] = trigger
        return response

    def error(message: str) -> HTMLResponse:
        return render("error.html", message=message)

    def editor(rel: str, index: int, request: Request, **extra: Any) -> HTMLResponse:
        return render(
            "editor.html",
            file=rel,
            index=index,
            request=request,
            headers=format_headers(request.headers),
            **extra,
        )

    def form_request(form: FormData) -> Request:
        request = Request(
            method=str(form.get("method", "GET")).strip().upper() or "GET",
            url=str(form.get("url", "")).strip(),
            headers=parse_headers(str(form.get("headers", ""))),
            body=str(form.get("body", "")).replace("\r\n", "\n").strip("\n"),
            name=str(form.get("name", "")).strip(),
        )
        validate(request)
        return request

    def form_index(form: FormData) -> int:
        try:
            return int(str(form.get("index", "")))
        except ValueError:
            raise WorkspaceError("Missing request index.") from None

    def guarded(
        handler: Callable[[HttpRequest], Awaitable[Response]],
    ) -> Callable[[HttpRequest], Awaitable[Response]]:
        async def wrapper(request: HttpRequest) -> Response:
            try:
                return await handler(request)
            except (WorkspaceError, HttpFileError, EnvFileError) as exc:
                return error(str(exc))

        return wrapper

    async def index(request: HttpRequest) -> Response:
        try:
            env_names = environments.names(workspace.root)
            env_error = ""
        except EnvFileError as exc:
            env_names, env_error = [], str(exc)
        return render(
            "index.html",
            root=workspace.root,
            entries=workspace.entries(),
            env_names=env_names,
            env_error=env_error,
        )

    async def tree(request: HttpRequest) -> Response:
        return render("tree.html", entries=workspace.entries())

    @guarded
    async def open_request(request: HttpRequest) -> Response:
        rel = request.query_params.get("file", "")
        try:
            index = int(request.query_params.get("index", "0"))
        except ValueError:
            index = 0
        return editor(rel, index, workspace.request(rel, index))

    @guarded
    async def create_file(request: HttpRequest) -> Response:
        form = await request.form()
        rel = str(form.get("path", "")).strip()
        if rel and not rel.endswith((".http", ".rest")):
            rel += ".http"
        new = Request(NEW_REQUEST.method, NEW_REQUEST.url, name=NEW_REQUEST.name)
        workspace.create(rel, new)
        return editor(rel, 0, new, status="Created " + rel, trigger="tree-changed")

    @guarded
    async def add_request(request: HttpRequest) -> Response:
        form = await request.form()
        rel = str(form.get("file", ""))
        new = Request(NEW_REQUEST.method, NEW_REQUEST.url, name=NEW_REQUEST.name)
        index = workspace.append(rel, new)
        return editor(rel, index, new, status="Added a request to " + rel, trigger="tree-changed")

    @guarded
    async def save(request: HttpRequest) -> Response:
        form = await request.form()
        rel = str(form.get("file", ""))
        workspace.update(rel, form_index(form), form_request(form))
        return render("status.html", message=f"Saved {rel}", trigger="tree-changed")

    @guarded
    async def delete(request: HttpRequest) -> Response:
        form = await request.form()
        rel = str(form.get("file", ""))
        workspace.remove(rel, form_index(form))
        return render("empty.html", message=f"Deleted a request from {rel}", trigger="tree-changed")

    async def send(request: HttpRequest) -> Response:
        form = await request.form()
        try:
            req = form_request(form)
            variables: dict[str, str] = {}
            rel = str(form.get("file", ""))
            if rel:
                variables.update(workspace.load(rel).variables)
            variables.update(
                environments.variables(workspace.root, str(form.get("env", "")) or None)
            )
            prepared = runner.prepare(req, variables, secret_lookup)
        except (HttpFileError, WorkspaceError, EnvFileError, TemplateError, SecretError) as exc:
            return render("response.html", error=str(exc))
        try:
            result = await run_in_threadpool(runner.send, prepared, transport=transport)
        except httpx.HTTPError as exc:
            return render(
                "response.html",
                error=prepared.renderer.mask(f"{type(exc).__name__}: {exc}"),
                sent=prepared.masked(),
            )
        return render(
            "response.html",
            result=result,
            # Responses often echo credentials back (e.g. /headers endpoints).
            body=prepared.renderer.mask(_display_body(result)),
            size=_human_size(len(result.body)),
            sent=prepared.masked(),
            headers=[(k, prepared.renderer.mask(v)) for k, v in result.headers],
        )

    async def import_form(request: HttpRequest) -> Response:
        return render("import.html")

    async def import_(request: HttpRequest) -> Response:
        form = await request.form(max_part_size=MAX_IMPORT)
        text = str(form.get("text", "")).strip()
        upload = form.get("upload")
        if upload is not None and not isinstance(upload, str) and upload.filename:
            data = await upload.read(MAX_IMPORT + 1)
            if len(data) > MAX_IMPORT:
                return render("import_result.html", error="The file is larger than 50 MB.")
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                return render("import_result.html", error="The file isn't UTF-8 text.")
        if not text:
            return render("import_result.html", error="Paste something or choose a file first.")
        target = str(form.get("file", "")).strip() or "imported.http"
        if not target.endswith((".http", ".rest")):
            target += ".http"
        try:
            result = await run_in_threadpool(
                importers.convert, text, None, name=target, everything=bool(form.get("all"))
            )
            report = importers.write(result, workspace.root, append=result.files.keys() == {target})
        except (importers.ImporterError, WorkspaceError, HttpFileError, OSError, ValueError) as exc:
            return render("import_result.html", error=str(exc))

        saved: dict[str, str] = {}
        if form.get("save_secrets"):
            for secret in result.secrets:
                if not secret.value:
                    continue
                try:
                    await run_in_threadpool(secret_store, secret.name, secret.value)
                    saved[secret.name] = ""
                except SecretError as exc:
                    saved[secret.name] = str(exc)
        return render(
            "import_result.html",
            result=result,
            report=report,
            saved=saved,
            trigger="tree-changed",
        )

    def environments_page(
        env: str = "", status: str = "", error: str = "", **extra: Any
    ) -> HTMLResponse:
        try:
            names = manage.env_names(workspace.root)
            current = env if env in names else (names[1] if len(names) > 1 else names[0])
            env_rows = manage.rows(workspace.root, current)
        except manage.ManageError as exc:
            return render("environments.html", names=[], error=str(exc))
        refs = {row.secret_ref for row in env_rows if row.secret_ref}
        secret_set = {ref: secret_exists(ref) for ref in refs}
        return render(
            "environments.html",
            names=names,
            current=current,
            rows=env_rows,
            secret_set=secret_set,
            shared=environments.SHARED,
            tracked=manage.private_file_tracked(workspace.root),
            status=status,
            error=error,
            **extra,
        )

    def form_rows(form: FormData) -> list[manage.Row]:
        indices = sorted(
            {int(k.split("-")[1]) for k in form if k.startswith("rows-") and k.endswith("-key")}
        )
        result = []
        for i in indices:
            key = str(form.get(f"rows-{i}-key", "")).strip()
            value = str(form.get(f"rows-{i}-value", ""))
            if not key and not value:
                continue
            result.append(
                manage.Row(
                    key=key,
                    value=value,
                    location=str(form.get(f"rows-{i}-location", manage.SHARED_LOCATION)),
                    secret=bool(form.get(f"rows-{i}-secret")),
                )
            )
        return result

    async def environments_view(request: HttpRequest) -> Response:
        return environments_page(request.query_params.get("env", ""))

    async def environments_save(request: HttpRequest) -> Response:
        form = await request.form()
        env = str(form.get("env", ""))
        new_rows = form_rows(form)
        try:
            stored = await run_in_threadpool(
                manage.save, workspace.root, env, new_rows, secret_store
            )
        except (manage.ManageError, SecretError, OSError) as exc:
            # Re-show what was typed so nothing is lost; values stay in this local page only.
            return environments_page(env, error=str(exc), draft=new_rows)
        message = f"Saved {env}."
        if stored:
            message += f" Stored {len(stored)} value(s) in your keychain."
        response = environments_page(env, status=message)
        response.headers["HX-Trigger"] = "envs-changed"
        return response

    async def environments_create(request: HttpRequest) -> Response:
        form = await request.form()
        env = str(form.get("name", "")).strip()
        try:
            manage.create(workspace.root, env)
        except (manage.ManageError, OSError) as exc:
            return environments_page(error=str(exc))
        response = environments_page(env, status=f"Created {env}.")
        response.headers["HX-Trigger"] = "envs-changed"
        return response

    async def environments_delete(request: HttpRequest) -> Response:
        form = await request.form()
        env = str(form.get("env", ""))
        try:
            manage.delete(workspace.root, env)
        except (manage.ManageError, OSError) as exc:
            return environments_page(env, error=str(exc))
        response = environments_page(status=f"Deleted {env}.")
        response.headers["HX-Trigger"] = "envs-changed"
        return response

    async def environments_gitignore(request: HttpRequest) -> Response:
        manage.ignore_private_file(workspace.root)
        return environments_page(
            request.query_params.get("env", ""), status="Added the private file to .gitignore."
        )

    async def env_options(request: HttpRequest) -> Response:
        try:
            names = environments.names(workspace.root)
        except EnvFileError:
            names = []
        return render("env_options.html", env_names=names)

    def secrets_page(status: str = "", error: str = "") -> HTMLResponse:
        try:
            refs = manage.secret_refs(workspace.root)
        except OSError as exc:
            refs, error = [], str(exc)
        referenced = {r.key for r in refs if r.provider == "keychain"}
        unused = [n for n in secret_names() if n not in referenced]
        return render(
            "secrets.html",
            refs=refs,
            present={r.ref: secret_exists(r.ref) for r in refs},
            unused=unused,
            status=status,
            error=error,
        )

    async def secrets_view(request: HttpRequest) -> Response:
        return secrets_page()

    async def secrets_set(request: HttpRequest) -> Response:
        form = await request.form()
        name = str(form.get("name", "")).strip()
        value = str(form.get("value", ""))
        if not value:
            return secrets_page(error=f"Enter a value for {name}.")
        try:
            secretstore.check_key(name)
            await run_in_threadpool(secret_store, name, value)
        except SecretError as exc:
            return secrets_page(error=str(exc))
        return secrets_page(
            status=f"Stored {name} in your keychain. Use it as {{{{secret:keychain/{name}}}}}."
        )

    async def secrets_delete(request: HttpRequest) -> Response:
        form = await request.form()
        name = str(form.get("name", "")).strip()
        try:
            secretstore.check_key(name)
            await run_in_threadpool(secret_delete, name)
        except SecretError as exc:
            return secrets_page(error=str(exc))
        return secrets_page(status=f"Deleted {name} from your keychain.")

    static = Path(__file__).parent / "static"
    app = Starlette(
        routes=[
            Route("/", index),
            Route("/tree", tree),
            Route("/request", open_request),
            Route("/files", create_file, methods=["POST"]),
            Route("/requests", add_request, methods=["POST"]),
            Route("/save", save, methods=["POST"]),
            Route("/delete", delete, methods=["POST"]),
            Route("/send", send, methods=["POST"]),
            Route("/import", import_form),
            Route("/import", import_, methods=["POST"]),
            Route("/environments", environments_view),
            Route("/environments/save", environments_save, methods=["POST"]),
            Route("/environments/create", environments_create, methods=["POST"]),
            Route("/environments/delete", environments_delete, methods=["POST"]),
            Route("/environments/gitignore", environments_gitignore, methods=["POST"]),
            Route("/env-options", env_options),
            Route("/secrets", secrets_view),
            Route("/secrets/set", secrets_set, methods=["POST"]),
            Route("/secrets/delete", secrets_delete, methods=["POST"]),
            Mount("/static", StaticFiles(directory=static), name="static"),
        ],
    )
    return Guard(app, port=port, token=token)


def _display_body(result: runner.Result) -> str:
    body = result.body[:MAX_DISPLAY]
    if b"\x00" in body[:1024]:
        return f"(binary content, {_human_size(len(result.body))})"
    text = body.decode("utf-8", errors="replace")
    if "json" in result.content_type.lower():
        with contextlib.suppress(ValueError):
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
    if len(result.body) > MAX_DISPLAY or result.truncated:
        text += "\n\n… (truncated)"
    return text


def _human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB"):
        if value < 1024 or unit == "MB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"
