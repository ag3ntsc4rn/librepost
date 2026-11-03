"""Turn a Request into an HTTP call."""

from __future__ import annotations

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
) -> Prepared:
    """Fill in placeholders. Raises TemplateError or SecretError."""
    renderer = Renderer(variables, secret_lookup)
    url = renderer.render(request.url)
    headers = [(renderer.render(k), renderer.render(v)) for k, v in request.headers]
    body = renderer.render(request.body)
    renderer.check()
    if "://" not in url:
        url = "http://" + url
    return Prepared(request.method, url, headers, body, renderer)


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
