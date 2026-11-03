"""HAR files, as saved from a browser's network panel.

By default only API-looking traffic is kept (fetch/XHR and documents); images, scripts,
styles, fonts and media are dropped, as are repeated identical requests. Requests are
grouped into one file per host. Browser-only headers are removed, and cookies and auth
headers become secret references.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from ..httpfile import Request
from . import ImporterError, ImportResult
from .sanitize import Sanitizer, slug

KEEP_RESOURCE_TYPES = {"xhr", "fetch", "document", "other"}
SKIP_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")
SKIP_MIME_CONTAINS = ("javascript", "ecmascript", "woff")
DROP_HEADERS = {
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "accept-encoding",
    "te",
    "upgrade-insecure-requests",
    "priority",
    "proxy-connection",
    "transfer-encoding",
}
DROP_HEADER_PREFIXES = (":", "sec-ch-", "sec-fetch-")


def _keep(entry: dict[str, Any]) -> bool:
    url = str(entry.get("request", {}).get("url", ""))
    if not url.startswith(("http://", "https://")):
        return False
    resource = entry.get("_resourceType")
    if isinstance(resource, str):
        if resource.lower() == "preflight":
            return False
        return resource.lower() in KEEP_RESOURCE_TYPES
    mime = str(entry.get("response", {}).get("content", {}).get("mimeType", "")).lower()
    return not (mime.startswith(SKIP_MIME_PREFIXES) or any(m in mime for m in SKIP_MIME_CONTAINS))


def convert(data: Any, *, everything: bool = False) -> ImportResult:
    if not isinstance(data, dict) or not isinstance(data.get("log"), dict):
        raise ImporterError("Not a HAR file (no 'log' object).")
    entries = data["log"].get("entries") or []
    result = ImportResult()
    seen: set[tuple[str, str, str]] = set()
    names: dict[str, set[str]] = {}
    skipped = duplicates = 0

    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("request"), dict):
            continue
        if not everything and not _keep(entry):
            skipped += 1
            continue
        raw = entry["request"]
        method = str(raw.get("method") or "GET").upper()
        url = str(raw.get("url") or "")
        body = ""
        post = raw.get("postData")
        if isinstance(post, dict):
            if post.get("text"):
                body = str(post["text"])
            elif isinstance(post.get("params"), list):
                body = "&".join(
                    f"{p.get('name', '')}={p.get('value', '')}"
                    for p in post["params"]
                    if isinstance(p, dict)
                )
        key = (method, url, body)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)

        headers = []
        for header in raw.get("headers") or []:
            if not isinstance(header, dict):
                continue
            name = str(header.get("name", ""))
            lower = name.lower()
            if not name or lower in DROP_HEADERS or lower.startswith(DROP_HEADER_PREFIXES):
                continue
            headers.append((name, str(header.get("value", ""))))

        parts = urlsplit(url)
        host = parts.hostname or "har"
        rel = f"{slug(host.removeprefix('www.'), 'har')}.http"
        last = parts.path.rstrip("/").rsplit("/", 1)[-1] or "root"
        name = slug(f"{method} {last}", "request")
        taken = names.setdefault(rel, set())
        unique, n = name, 2
        while unique in taken:
            unique, n = f"{name}-{n}", n + 1
        taken.add(unique)

        request = Request(method=method, url=url, headers=headers, body=body, name=unique)
        sanitizer = Sanitizer(slug(host.removeprefix("www."), "har"))
        sanitizer.secrets = result.secrets
        result.files.setdefault(rel, []).append(sanitizer.request(request, f"HAR {method} {host}"))

    if skipped:
        result.warnings.append(
            f"Skipped {skipped} non-API request(s) (images, scripts, styles, fonts, preflights). Use --all to keep them."
        )
    if duplicates:
        result.warnings.append(f"Skipped {duplicates} repeated identical request(s).")
    if not result.files:
        raise ImporterError("No requests to import from this HAR file.")
    return result
