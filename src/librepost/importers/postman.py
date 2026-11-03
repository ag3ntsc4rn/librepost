"""Postman collections (v2.0 and v2.1) and environment/globals exports.

Folders become directories and each folder's requests go into one `.http` file named
after it. Collection variables go into `$shared` in http-client.env.json. Auth set on the
collection or a folder is inherited by requests the way Postman does it. Scripts are not
run by librepost, so they are not imported; a warning says how many were skipped.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from ..environments import SHARED
from ..httpfile import METHODS, Request
from . import ImporterError, ImportResult
from .sanitize import Sanitizer, slug
from .scripts import convert as convert_script

CONTENT_TYPES = {
    "json": "application/json",
    "xml": "application/xml",
    "html": "text/html",
    "text": "text/plain",
    "javascript": "application/javascript",
}
BOUNDARY = "librepost-boundary"
# Postman's dynamic variables that librepost also understands.
KNOWN_DYNAMIC = {"$guid", "$uuid", "$timestamp", "$isoTimestamp", "$randomInt"}
PATH_VARIABLE = re.compile(r"(?<=/):([A-Za-z_][\w-]*)")


def _auth_params(auth: dict[str, Any]) -> dict[str, str]:
    """Postman stores auth parameters as a list of {key, value} (v2.1) or a dict (v2.0)."""
    params = auth.get(auth.get("type", ""), {})
    if isinstance(params, list):
        return {
            str(p.get("key")): "" if p.get("value") is None else str(p.get("value"))
            for p in params
            if isinstance(p, dict)
        }
    if isinstance(params, dict):
        return {str(k): "" if v is None else str(v) for k, v in params.items()}
    return {}


class _Converter:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.name = str(data.get("info", {}).get("name") or "postman")
        self.result = ImportResult()
        self.sanitizer = Sanitizer(self.name)
        self.skipped_scripts = 0
        self.converted_checks = 0
        self.unknown_dynamic: set[str] = set()
        self.unsupported_auth: dict[str, list[str]] = {}

    def run(self) -> ImportResult:
        root = slug(self.name, "postman")
        top_checks = self._script_checks(self.data)
        self._folder(
            self.data.get("item", []), [root], self.data.get("auth"), self.name, top_checks
        )
        variables = {}
        for var in self.data.get("variable", []) or []:
            if not isinstance(var, dict) or var.get("disabled") or not var.get("key"):
                continue
            key = str(var["key"])
            value = "" if var.get("value") is None else str(var.get("value"))
            variables[key] = self.sanitizer.env_value(SHARED, key, value)
        if variables:
            self.result.environments[SHARED] = variables
        if self.converted_checks:
            self.result.warnings.append(
                f"Converted test scripts into {self.converted_checks} @capture/@expect line(s); review them in each request's Checks tab."
            )
        if self.skipped_scripts:
            self.result.warnings.append(
                f"Skipped {self.skipped_scripts} script(s) with code librepost can't convert "
                "(pre-request scripts, or test code beyond simple captures and checks)."
            )
        for kind, requests in self.unsupported_auth.items():
            sample = ", ".join(repr(n) for n in requests[:3]) + (", …" if len(requests) > 3 else "")
            self.result.warnings.append(
                f"{kind} auth isn't supported; add the header yourself in {len(requests)} request(s): {sample}"
            )
        if self.unknown_dynamic:
            names = ", ".join(sorted(self.unknown_dynamic))
            self.result.warnings.append(
                f"Postman dynamic variables librepost doesn't provide: {names}. Define them in an environment."
            )
        self.result.secrets = self.sanitizer.secrets
        return self.result

    def _script_checks(self, node: dict[str, Any]) -> list[str]:
        """Convert a node's test script; count anything that can't be converted."""
        found: list[str] = []
        for event in node.get("event", []) or []:
            if not isinstance(event, dict):
                continue
            exec_ = (event.get("script") or {}).get("exec")
            lines = exec_ if isinstance(exec_, list) else str(exec_ or "").splitlines()
            lines = [str(line) for line in lines]
            if not any(line.strip() for line in lines):
                continue
            if event.get("listen") != "test":
                self.skipped_scripts += 1
                continue
            conversion = convert_script(lines)
            found.extend(conversion.checks)
            self.converted_checks += len(conversion.checks)
            if conversion.unconverted:
                self.skipped_scripts += 1
        return found

    def _folder(
        self, items: list[Any], path: list[str], auth: Any, label: str, inherited: list[str]
    ) -> None:
        requests: list[Request] = []
        used_dirs: set[str] = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            if "item" in item:  # sub-folder
                sub = slug(str(item.get("name", "")), "folder")
                n, base = 2, sub
                while sub in used_dirs:
                    sub, n = f"{base}-{n}", n + 1
                used_dirs.add(sub)
                folder_auth = item.get("auth") or auth
                folder_checks = inherited + self._script_checks(item)
                self._folder(
                    item["item"] or [],
                    [*path, sub],
                    folder_auth,
                    str(item.get("name")),
                    folder_checks,
                )
            elif "request" in item:
                request = self._request(item, auth)
                if request is not None:
                    # Collection and folder scripts run for every request inside them.
                    own = self._script_checks(item)
                    request.checks = list(dict.fromkeys(inherited + own))
                    requests.append(request)
        if requests:
            rel = "/".join(path[:-1] + [path[-1] + ".http"])
            self.result.files[rel] = requests

    def _request(self, item: dict[str, Any], inherited_auth: Any) -> Request | None:
        raw = item["request"]
        name = str(item.get("name") or "")
        source = f"request {name!r}"
        if isinstance(raw, str):
            raw = {"method": "GET", "url": raw}
        if not isinstance(raw, dict):
            return None
        method = str(raw.get("method") or "GET").upper()
        if method not in METHODS:
            self.result.warnings.append(f"{name}: method {method} kept as is.")
        request = Request(method=method, url=self._url(raw.get("url")), name=name)
        description = item.get("description") or raw.get("description")
        if isinstance(description, dict):
            description = description.get("content")
        if isinstance(description, str) and description.strip():
            request.comments = [
                f"# {line}".rstrip() for line in description.strip().splitlines()[:10]
            ]

        for header in raw.get("header", []) or []:
            if isinstance(header, dict) and not header.get("disabled") and header.get("key"):
                request.headers.append((str(header["key"]), str(header.get("value") or "")))

        auth = raw.get("auth") if "auth" in raw else inherited_auth
        self._apply_auth(request, auth, name)
        self._body(request, raw.get("body"), name)
        self._note_dynamic(request)
        if not request.url:
            self.result.warnings.append(f"{name}: no URL; skipped.")
            return None
        return self.sanitizer.request(request, source)

    def _url(self, url: Any) -> str:
        variables: dict[str, str] = {}
        if isinstance(url, dict):
            for var in url.get("variable", []) or []:
                if isinstance(var, dict) and var.get("key"):
                    variables[str(var["key"])] = str(var.get("value") or "")
            raw = str(url.get("raw") or "")
            if not raw:
                host = url.get("host") or []
                path = url.get("path") or []
                host_s = ".".join(host) if isinstance(host, list) else str(host)
                path_s = "/".join(str(p) for p in path) if isinstance(path, list) else str(path)
                raw = f"{url.get('protocol', 'https')}://{host_s}/{path_s}"
        else:
            raw = str(url or "")

        def path_var(match: re.Match[str]) -> str:
            key = match.group(1)
            value = variables.get(key, "")
            return value if value else f"{{{{{key}}}}}"

        base, sep, query = raw.partition("?")
        return PATH_VARIABLE.sub(path_var, base) + sep + query

    def _apply_auth(self, request: Request, auth: Any, name: str) -> None:
        if not isinstance(auth, dict) or auth.get("type") in (None, "noauth", "inherit"):
            return
        kind = auth["type"]
        params = _auth_params(auth)
        if kind == "bearer":
            request.headers.append(("Authorization", f"Bearer {params.get('token', '')}"))
        elif kind == "basic":
            user = params.get("username", "")
            request.headers.append(("Authorization", f"Basic {user} {params.get('password', '')}"))
        elif kind == "apikey":
            key, value = params.get("key", "x-api-key"), params.get("value", "")
            if params.get("in") == "query":
                sep = "&" if "?" in request.url else "?"
                request.url += f"{sep}{key}={value}"
            else:
                request.headers.append((key, value))
        elif kind == "oauth2":
            token = params.get("accessToken", "")
            prefix = params.get("headerPrefix") or "Bearer"
            if token:
                request.headers.append(("Authorization", f"{prefix} {token}"))
            else:
                request.headers.append(("Authorization", f"{prefix} {{{{oauth2Token}}}}"))
                self.result.warnings.append(
                    f"{name}: OAuth 2.0 token flow isn't supported; set oauth2Token yourself."
                )
        else:
            self.unsupported_auth.setdefault(str(kind), []).append(name)

    def _body(self, request: Request, body: Any, name: str) -> None:
        if not isinstance(body, dict) or body.get("disabled"):
            return
        mode = body.get("mode")
        has_type = any(k.lower() == "content-type" for k, _ in request.headers)
        if mode == "raw":
            request.body = str(body.get("raw") or "")
            language = ((body.get("options") or {}).get("raw") or {}).get("language")
            if request.body and not has_type and language in CONTENT_TYPES:
                request.headers.append(("Content-Type", CONTENT_TYPES[language]))
        elif mode == "urlencoded":
            pairs = [
                f"{_form_quote(str(p.get('key', '')))}={_form_quote(str(p.get('value') or ''))}"
                for p in body.get("urlencoded", []) or []
                if isinstance(p, dict) and not p.get("disabled")
            ]
            request.body = "&".join(pairs)
            if not has_type:
                request.headers.append(("Content-Type", "application/x-www-form-urlencoded"))
        elif mode == "formdata":
            parts = []
            for field in body.get("formdata", []) or []:
                if not isinstance(field, dict) or field.get("disabled"):
                    continue
                if field.get("type") == "file":
                    self.result.warnings.append(
                        f"{name}: file field {field.get('key')!r} skipped; file uploads aren't supported yet."
                    )
                    continue
                parts.append(
                    f'--{BOUNDARY}\nContent-Disposition: form-data; name="{field.get("key", "")}"\n\n'
                    f"{field.get('value') or ''}"
                )
            if parts:
                request.body = "\n".join(parts) + f"\n--{BOUNDARY}--"
                request.headers = [
                    (k, v) for k, v in request.headers if k.lower() != "content-type"
                ]
                request.headers.append(
                    ("Content-Type", f"multipart/form-data; boundary={BOUNDARY}")
                )
        elif mode == "graphql":
            import json

            graphql = body.get("graphql") or {}
            payload: dict[str, Any] = {"query": graphql.get("query", "")}
            variables = graphql.get("variables")
            if isinstance(variables, str) and variables.strip():
                try:
                    payload["variables"] = json.loads(variables)
                except json.JSONDecodeError:
                    self.result.warnings.append(
                        f"{name}: GraphQL variables aren't valid JSON; dropped."
                    )
            request.body = json.dumps(payload, indent=2)
            if not has_type:
                request.headers.append(("Content-Type", "application/json"))
        elif mode == "file":
            self.result.warnings.append(f"{name}: binary file body skipped; not supported yet.")

    def _note_dynamic(self, request: Request) -> None:
        text = " ".join([request.url, request.body, *(v for _, v in request.headers)])
        for match in re.finditer(r"\{\{\s*(\$[A-Za-z]+)\s*\}\}", text):
            if match.group(1) not in KNOWN_DYNAMIC:
                self.unknown_dynamic.add(match.group(1))


def _form_quote(value: str) -> str:
    # Leave {{placeholders}} readable; they are filled in before sending.
    return quote(value, safe="{}$")


def convert_collection(data: Any) -> ImportResult:
    if isinstance(data, dict) and isinstance(data.get("collection"), dict):
        data = data["collection"]
    if not isinstance(data, dict) or "item" not in data:
        raise ImporterError("Not a Postman collection (no 'item' list).")
    schema = str(data.get("info", {}).get("schema", ""))
    if "v1" in schema:
        raise ImporterError("Postman v1 collections aren't supported; re-export as v2.1.")
    return _Converter(data).run()


def convert_environment(data: Any) -> ImportResult:
    if not isinstance(data, dict) or not isinstance(data.get("values"), list):
        raise ImporterError("Not a Postman environment export (no 'values' list).")
    if data.get("_postman_variable_scope") == "globals":
        env = SHARED
    else:
        env = slug(str(data.get("name") or "imported"), "imported")
    sanitizer = Sanitizer(env if env != SHARED else "globals")
    result = ImportResult()
    values: dict[str, str] = {}
    for var in data["values"]:
        if not isinstance(var, dict) or not var.get("key") or var.get("enabled") is False:
            continue
        key = str(var["key"])
        value = "" if var.get("value") is None else str(var.get("value"))
        values[key] = sanitizer.env_value(env, key, value, secret=var.get("type") == "secret")
    result.environments[env] = values
    result.secrets = sanitizer.secrets
    return result
