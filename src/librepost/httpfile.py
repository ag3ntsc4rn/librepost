"""Read and write `.http` files, the plain-text request format used by the JetBrains HTTP
Client and the VS Code REST Client.

A file holds one or more requests separated by lines starting with `###`:

    @baseUrl = https://example.com

    # @name login
    POST {{baseUrl}}/login
    Content-Type: application/json

    {"user": "alice"}

    ###

    GET {{baseUrl}}/me

Supported: `# @name`, `// comments`, `@var = value` file variables, multi-line query
continuations (indented lines starting with `?` or `&`) and `HTTP/x` suffixes. Response
handler scripts (`> {% ... %}`) and output redirects (`>> file`, `<> file`) are kept
when the file is saved, but librepost does not run them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")

_SEPARATOR = re.compile(r"^###(.*)$")
_REQUEST_LINE = re.compile(
    r"^(?P<method>[A-Z]+)\s+(?P<url>\S.*?)(?:\s+HTTP/\d(?:\.\d)?)?\s*$",
)
_COMMENT = re.compile(r"^\s*(#|//)")
_NAME = re.compile(r"^\s*(?:#|//)\s*@name\s*[= ]\s*(?P<name>\S.*?)\s*$")
# `# @capture`, `# @capture-secret` and `# @expect` lines: see checks.py.
_CHECK = re.compile(r"^\s*(?:#|//)\s*(?P<check>@(?:capture-secret|capture|expect)\b.*?)\s*$")
_FILE_VARIABLE = re.compile(r"^@(?P<name>[A-Za-z_][\w.-]*)\s*=\s*(?P<value>.*?)\s*$")
_URL_CONTINUATION = re.compile(r"^\s+[?&]")
# Lines that end the body: response handlers and output redirects.
_TRAILER = re.compile(r"^(> \{%|> \S|>>!? |<> )")


class HttpFileError(ValueError):
    """A request can't be written as valid `.http` text."""


@dataclass
class Request:
    method: str = "GET"
    url: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    name: str = ""
    # Comment lines above the request line (other than `@name`), kept verbatim.
    comments: list[str] = field(default_factory=list)
    # `@capture` / `@capture-secret` / `@expect` lines, without the comment marker.
    checks: list[str] = field(default_factory=list)
    # Response handlers and redirects after the body, kept verbatim but never run.
    trailer: str = ""

    @property
    def label(self) -> str:
        return self.name or f"{self.method} {self.url}"


@dataclass
class HttpFile:
    requests: list[Request] = field(default_factory=list)
    variables: dict[str, str] = field(default_factory=dict)


def parse(text: str) -> HttpFile:
    result = HttpFile()
    for separator_name, block in _blocks(text):
        request = _parse_block(block, result.variables)
        if request is None:
            continue
        if not request.name and separator_name:
            request.name = separator_name
        result.requests.append(request)
    return result


def _blocks(text: str) -> list[tuple[str, list[str]]]:
    blocks: list[tuple[str, list[str]]] = [("", [])]
    for line in text.replace("\r\n", "\n").split("\n"):
        match = _SEPARATOR.match(line)
        if match:
            blocks.append((match.group(1).strip(), []))
        else:
            blocks[-1][1].append(line)
    return blocks


def _parse_block(lines: list[str], variables: dict[str, str]) -> Request | None:
    request = Request()
    i = 0
    # Comments, names and file variables before the request line.
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        name = _NAME.match(line)
        check = _CHECK.match(line)
        if name:
            request.name = name.group("name")
        elif check:
            request.checks.append(check.group("check"))
        elif _COMMENT.match(line):
            request.comments.append(line.rstrip())
        else:
            variable = _FILE_VARIABLE.match(line)
            if not variable:
                break
            variables[variable.group("name")] = variable.group("value")
        i += 1
    if i == len(lines):
        return None

    request_line = lines[i].strip()
    match = _REQUEST_LINE.match(request_line)
    if match and match.group("method") in METHODS:
        request.method = match.group("method")
        request.url = match.group("url")
    else:
        request.url = re.sub(r"\s+HTTP/\d(?:\.\d)?\s*$", "", request_line)
    i += 1
    while i < len(lines) and _URL_CONTINUATION.match(lines[i]):
        request.url += lines[i].strip()
        i += 1

    while i < len(lines) and lines[i].strip():
        line = lines[i]
        i += 1
        if _COMMENT.match(line):
            continue
        key, sep, value = line.partition(":")
        if sep:
            request.headers.append((key.strip(), value.strip()))

    body = lines[i + 1 :] if i < len(lines) else []
    for j, line in enumerate(body):
        if _TRAILER.match(line):
            request.trailer = "\n".join(body[j:]).strip("\n")
            body = body[:j]
            break
    request.body = "\n".join(body).strip("\n")
    return request


def validate(request: Request) -> None:
    """Raise HttpFileError if the request would not survive a save and reload."""
    if not request.url.strip():
        raise HttpFileError("The URL is empty.")
    if "\n" in request.url or "\n" in request.name:
        raise HttpFileError("The URL and name must be on one line.")
    if not re.fullmatch(r"[A-Z]+", request.method):
        raise HttpFileError(f"Invalid method: {request.method!r}")
    for key, value in request.headers:
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise HttpFileError(f"Invalid header name: {key!r}")
        if "\n" in value:
            raise HttpFileError(f"Header {key} has a line break in its value.")
    for line in request.body.split("\n"):
        if _SEPARATOR.match(line):
            raise HttpFileError("A body line can't start with ###: it separates requests.")
        if _TRAILER.match(line):
            raise HttpFileError(
                f"A body line can't start with {line[:3]!r}: .http files use it for response handlers."
            )


def dumps(httpfile: HttpFile) -> str:
    parts: list[str] = []
    if httpfile.variables:
        parts.append("\n".join(f"@{k} = {v}" for k, v in httpfile.variables.items()))
    for request in httpfile.requests:
        validate(request)
        lines = list(request.comments)
        lines.extend(f"# {check}" for check in request.checks)
        if request.name:
            lines.append(f"# @name {request.name}")
        lines.append(f"{request.method} {request.url}")
        lines.extend(f"{k}: {v}" for k, v in request.headers)
        if request.body:
            lines.extend(["", request.body])
        if request.trailer:
            lines.extend(["", request.trailer])
        parts.append("\n".join(lines))
    if httpfile.variables and httpfile.requests:
        head, first, *rest = parts
        parts = [f"{head}\n\n{first}", *rest]
    return "\n\n###\n\n".join(parts) + "\n"


def parse_headers(text: str) -> list[tuple[str, str]]:
    """Parse `Name: value` lines, as typed in the editor."""
    headers = []
    for number, line in enumerate(text.replace("\r\n", "\n").split("\n"), start=1):
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or not key.strip():
            raise HttpFileError(f"Header line {number} is not 'Name: value': {line.strip()!r}")
        headers.append((key.strip(), value.strip()))
    return headers


def format_headers(headers: list[tuple[str, str]]) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers)
