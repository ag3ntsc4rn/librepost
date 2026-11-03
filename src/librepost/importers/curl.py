"""curl commands, including the ones browsers produce with "Copy as cURL (bash)"."""

from __future__ import annotations

import re
import shlex
from urllib.parse import quote, urlsplit

from ..httpfile import Request
from . import ImporterError, ImportResult
from .sanitize import Sanitizer, slug

# Options that take a value. Anything not listed and not in FLAGS is reported and skipped.
VALUE_OPTIONS = {
    "-X": "request",
    "--request": "request",
    "-H": "header",
    "--header": "header",
    "-d": "data",
    "--data": "data",
    "--data-raw": "data-raw",
    "--data-ascii": "data",
    "--data-binary": "data",
    "--data-urlencode": "data-urlencode",
    "--json": "json",
    "-F": "form",
    "--form": "form",
    "--form-string": "form-string",
    "-u": "user",
    "--user": "user",
    "-b": "cookie",
    "--cookie": "cookie",
    "-A": "user-agent",
    "--user-agent": "user-agent",
    "-e": "referer",
    "--referer": "referer",
    "--url": "url",
    # Accepted and ignored:
    "-o": None,
    "--output": None,
    "-m": None,
    "--max-time": None,
    "--connect-timeout": None,
    "--retry": None,
    "-w": None,
    "--write-out": None,
    "-c": None,
    "--cookie-jar": None,
    "--cacert": None,
    "--capath": None,
    "-D": None,
    "--dump-header": None,
    "--limit-rate": None,
    "-r": None,
    "--range": None,
    "-x": "proxy",
    "--proxy": "proxy",
    "-E": "cert",
    "--cert": "cert",
    "--key": "cert",
    "--resolve": None,
    "--interface": None,
    "-T": "upload",
    "--upload-file": "upload",
}
FLAGS = {
    "-G": "get",
    "--get": "get",
    "-I": "head",
    "--head": "head",
    "-k": None,
    "--insecure": None,
    "-L": None,
    "--location": None,
    "-s": None,
    "--silent": None,
    "-S": None,
    "--show-error": None,
    "-v": None,
    "--verbose": None,
    "-i": None,
    "--include": None,
    "--compressed": None,
    "-f": None,
    "--fail": None,
    "--fail-with-body": None,
    "-N": None,
    "--no-buffer": None,
    "-g": None,
    "--globoff": None,
    "--http1.1": None,
    "--http2": None,
    "--http1.0": None,
    "--http2-prior-knowledge": None,
    "-#": None,
    "--progress-bar": None,
    "-0": None,
    "-4": None,
    "-6": None,
    "--tlsv1.2": None,
    "--tlsv1.3": None,
    "--ssl": None,
    "--path-as-is": None,
    "-j": None,
    "--junk-session-cookies": None,
}
ANSI_C = re.compile(r"\$'((?:[^'\\]|\\.)*)'")


def _decode_ansi_c(text: str) -> str:
    """Turn bash $'...' strings (used by browsers for bodies) into plain quoted strings."""

    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        try:
            decoded = (
                body.encode("utf-8").decode("unicode_escape").encode("latin-1").decode("utf-8")
            )
        except (UnicodeDecodeError, UnicodeEncodeError):
            decoded = body.encode("utf-8").decode("unicode_escape")
        return shlex.quote(decoded)

    return ANSI_C.sub(replace, text)


def tokenize(command: str) -> list[str]:
    command = re.sub(r"\\\r?\n", " ", command.strip())
    command = _decode_ansi_c(command)
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise ImporterError(f"Can't parse the curl command: {exc}") from None
    if not tokens or tokens[0] != "curl":
        raise ImporterError("Expected a command starting with 'curl'.")
    return tokens[1:]


def parse(command: str, warnings: list[str]) -> Request:
    tokens = tokenize(command)
    method = ""
    url = ""
    headers: list[tuple[str, str]] = []
    data: list[str] = []
    form: list[tuple[str, str]] = []
    get = head = json_body = False
    user = ""

    i = 0
    while i < len(tokens):
        token = tokens[i]
        i += 1
        option, value = token, None
        if token.startswith("--") and "=" in token:
            option, value = token.split("=", 1)
        elif token.startswith("-") and not token.startswith("--") and len(token) > 2:
            # -XPOST, -HAccept:..., or bundled flags like -sSL
            if token[:2] in VALUE_OPTIONS:
                option, value = token[:2], token[2:]
            else:
                expanded = [f"-{c}" for c in token[1:]]
                if all(e in FLAGS for e in expanded):
                    get = get or "-G" in expanded
                    head = head or "-I" in expanded
                    continue
        if not token.startswith("-") or token == "-":
            if url:
                warnings.append(f"Extra argument ignored: {token!r}")
            else:
                url = token
            continue
        if option in FLAGS:
            kind = FLAGS[option]
            get = get or kind == "get"
            head = head or kind == "head"
            continue
        if option not in VALUE_OPTIONS:
            warnings.append(f"Unsupported option ignored: {option}")
            continue
        if value is None:
            if i >= len(tokens):
                raise ImporterError(f"{option} needs a value.")
            value = tokens[i]
            i += 1
        kind = VALUE_OPTIONS[option]
        if kind == "request":
            method = value.upper()
        elif kind == "header":
            key, sep, val = value.partition(":")
            if sep:
                headers.append((key.strip(), val.strip()))
            elif value.endswith(";"):
                headers.append((value[:-1].strip(), ""))
        elif kind in ("data", "data-raw", "json"):
            if kind == "data" and value.startswith("@"):
                warnings.append(
                    f"Data from file {value[1:]!r} not imported; paste the content into the body."
                )
                continue
            data.append(value)
            json_body = json_body or kind == "json"
        elif kind == "data-urlencode":
            name, eq, content = value.partition("=")
            data.append(f"{name}={quote(content, safe='')}" if eq else quote(value, safe=""))
        elif kind in ("form", "form-string"):
            name, _, content = value.partition("=")
            if kind == "form" and content.startswith(("@", "<")):
                warnings.append(
                    f"Form file field {name!r} skipped; file uploads aren't supported yet."
                )
            else:
                form.append((name, content))
        elif kind == "user":
            user = value
        elif kind == "cookie":
            if "=" in value:
                headers.append(("Cookie", value))
            else:
                warnings.append(f"Cookie file {value!r} not imported.")
        elif kind == "user-agent":
            headers.append(("User-Agent", value))
        elif kind == "referer":
            headers.append(("Referer", value))
        elif kind == "url":
            url = value
        elif kind == "proxy":
            warnings.append("Proxy setting ignored; set HTTPS_PROXY in your environment instead.")
        elif kind == "cert":
            warnings.append("Client certificate options ignored; mTLS isn't supported yet.")
        elif kind == "upload":
            warnings.append("Upload (-T) ignored; file bodies aren't supported yet.")

    if not url:
        raise ImporterError("No URL in the curl command.")

    request = Request(url=url)
    names = {k.lower() for k, _ in headers}
    if form:
        boundary = "librepost-boundary"
        request.body = (
            "\n".join(
                f'--{boundary}\nContent-Disposition: form-data; name="{n}"\n\n{v}' for n, v in form
            )
            + f"\n--{boundary}--"
        )
        headers = [(k, v) for k, v in headers if k.lower() != "content-type"]
        headers.append(("Content-Type", f"multipart/form-data; boundary={boundary}"))
    elif data:
        body = "&".join(data)
        if get:
            sep = "&" if "?" in url else "?"
            request.url = f"{url}{sep}{body}"
        else:
            request.body = body
            if json_body:
                if "content-type" not in names:
                    headers.append(("Content-Type", "application/json"))
                if "accept" not in names:
                    headers.append(("Accept", "application/json"))
            elif "content-type" not in names:
                headers.append(("Content-Type", "application/x-www-form-urlencoded"))
    if user:
        name, _, password = user.partition(":")
        headers.append(("Authorization", f"Basic {name} {password}".rstrip()))

    if method:
        request.method = method
    elif head:
        request.method = "HEAD"
    elif request.body:
        request.method = "POST"
    request.headers = headers
    return request


def split_commands(text: str) -> list[str]:
    """Several commands may be pasted at once, one per line (continuations allowed)."""
    joined = re.sub(r"\\\r?\n", " ", text)
    commands: list[str] = []
    current: list[str] = []
    for line in joined.splitlines():
        if line.lstrip().startswith("curl ") and current:
            commands.append("\n".join(current))
            current = []
        if line.strip():
            current.append(line)
    if current:
        commands.append("\n".join(current))
    return commands


def convert(text: str, *, target: str = "imported.http") -> ImportResult:
    result = ImportResult()
    requests = []
    for command in split_commands(text):
        request = parse(command, result.warnings)
        host = urlsplit(request.url).hostname or "curl"
        path = urlsplit(request.url).path.strip("/")
        request.name = slug(f"{request.method} {path.split('/')[-1] if path else host}", "request")
        sanitizer = Sanitizer(slug(host.removeprefix("www."), "curl"))
        sanitizer.secrets = result.secrets
        requests.append(sanitizer.request(request, f"curl {request.method} {host}"))
    if not requests:
        raise ImporterError("No curl command found.")
    result.files[target] = requests
    return result
