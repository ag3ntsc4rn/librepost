"""Turn a Request into an HTTP call."""

from __future__ import annotations

import base64
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from . import __version__, secretstore
from .httpfile import Request
from .template import Renderer

USER_AGENT = f"librepost/{__version__}"
MAX_BODY = 50 * 1024 * 1024


@dataclass
class Prepared:
    method: str
    url: str
    headers: list[tuple[str, str]]
    body: str
    renderer: Renderer
    # The request's @capture/@expect lines with placeholders filled in.
    checks: list[str] = field(default_factory=list)

    def masked(self) -> str:
        """The request as text, with secret values hidden."""
        lines = [f"{self.method} {self.url}", *(f"{k}: {v}" for k, v in self.headers)]
        if self.body:
            lines.extend(["", self.body])
        return self.renderer.mask("\n".join(lines))


@dataclass
class Result:
    status: int
    reason: str
    http_version: str
    url: str
    headers: list[tuple[str, str]]
    body: bytes
    elapsed_ms: float
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)

    @property
    def content_type(self) -> str:
        for key, value in self.headers:
            if key.lower() == "content-type":
                return value
        return ""


def prepare(
    request: Request,
    variables: dict[str, str],
    secret_lookup: Callable[[str], str] = secretstore.lookup,
    mask: set[str] | None = None,
) -> Prepared:
    """Fill in placeholders. Raises TemplateError or SecretError.

    `mask` holds extra values to hide on screen, such as secret captured values."""
    renderer = Renderer(variables, secret_lookup)
    renderer.secret_values.update(v for v in mask or () if v)
    url = renderer.render(request.url)
    headers = [(renderer.render(k), renderer.render(v)) for k, v in request.headers]
    body = renderer.render(request.body)
    rendered_checks = [renderer.render(line) for line in request.checks]
    renderer.check()
    if "://" not in url:
        url = "http://" + url
    headers = [
        (k, _basic_auth(v, renderer) if k.lower() == "authorization" else v) for k, v in headers
    ]
    if any(k.lower() == "content-type" and "multipart/" in v.lower() for k, v in headers):
        # Multipart needs CRLF line breaks; .http files are saved with LF.
        body = re.sub(r"\r?\n", "\r\n", body)
    return Prepared(request.method, url, headers, body, renderer, rendered_checks)


_BASIC_PAIR = re.compile(r"^(basic)\s+(\S+)\s+(.+)$", re.IGNORECASE)


def _basic_auth(value: str, renderer: Renderer) -> str:
    """`Basic user password` (the JetBrains form) becomes `Basic base64(user:password)`."""
    match = _BASIC_PAIR.match(value.strip())
    if not match:
        return value
    scheme, user, password = match.groups()
    encoded = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
    if any(secret in password for secret in renderer.secret_values):
        renderer.secret_values.add(encoded)
    return f"{scheme} {encoded}"


def send(
    prepared: Prepared,
    *,
    timeout: float = 30.0,
    verify: bool = True,
    follow_redirects: bool = True,
    transport: httpx.BaseTransport | None = None,
    max_body: int = MAX_BODY,
) -> Result:
    """Send the request. Raises httpx.HTTPError on network failures."""
    headers = httpx.Headers(prepared.headers)
    headers.setdefault("User-Agent", USER_AGENT)
    with httpx.Client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        transport=transport,
        trust_env=True,
    ) as client:
        started = time.perf_counter()
        with client.stream(
            prepared.method,
            prepared.url,
            headers=headers,
            content=prepared.body.encode("utf-8") if prepared.body else None,
        ) as response:
            chunks: list[bytes] = []
            size = 0
            truncated = False
            for chunk in response.iter_bytes():
                size += len(chunk)
                if size > max_body:
                    chunks.append(chunk[: max_body - (size - len(chunk))])
                    truncated = True
                    break
                chunks.append(chunk)
            elapsed = (time.perf_counter() - started) * 1000
        return Result(
            status=response.status_code,
            reason=response.reason_phrase,
            http_version=response.http_version,
            url=str(response.url),
            headers=list(response.headers.multi_items()),
            body=b"".join(chunks),
            elapsed_ms=elapsed,
            truncated=truncated,
            redirects=[str(r.url) for r in response.history],
        )
