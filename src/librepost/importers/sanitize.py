"""Swap literal credentials for `{{secret:keychain/...}}` references.

Every importer runs its requests and environment values through a Sanitizer, so imported
files never hold a working credential. The values are collected so the caller can put them
in the keychain (or tell the user how to).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..httpfile import Request
from ..leakcheck import SENSITIVE_HEADER, SENSITIVE_NAME, TOKEN_PATTERNS, literal_credential

AUTH_SCHEMES = ("bearer", "basic", "token", "digest", "apikey")
SENSITIVE_QUERY = re.compile(
    r"^(api[-_]?key|apikey|key|token|access[-_]?token|auth|signature|sig|secret|password|client[-_]?secret)$",
    re.IGNORECASE,
)


def slug(text: str, fallback: str = "item", limit: int = 60) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return value[:limit].rstrip("-") or fallback


@dataclass
class Secret:
    name: str
    value: str
    source: str


@dataclass
class Sanitizer:
    prefix: str
    secrets: list[Secret] = field(default_factory=list)

    def ref(self, hint: str, value: str, source: str) -> str:
        """Return a reference for `value`, reusing the name if the value was seen before."""
        for secret in self.secrets:
            if secret.value == value and value:
                return f"{{{{secret:keychain/{secret.name}}}}}"
        base = f"{slug(self.prefix, 'import')}-{slug(hint, 'secret')}"
        name, n = base, 2
        taken = {s.name for s in self.secrets}
        while name in taken:
            name, n = f"{base}-{n}", n + 1
        self.secrets.append(Secret(name, value, source))
        return f"{{{{secret:keychain/{name}}}}}"

    def header(self, key: str, value: str, source: str) -> str:
        if not SENSITIVE_HEADER.match(key) or not literal_credential(value):
            return self.tokens(value, source)
        scheme, _, rest = value.strip().partition(" ")
        if scheme.lower() == "basic" and " " in rest.strip():
            # JetBrains form "Basic user password": only the password is secret.
            user, _, password = rest.strip().partition(" ")
            if "{{" in password:
                return value
            return f"{scheme} {user} {self.ref('password', password, source)}"
        if scheme.lower() in AUTH_SCHEMES and rest.strip():
            hint = "token" if scheme.lower() in ("bearer", "token") else key
            return f"{scheme} {self.ref(hint, rest.strip(), source)}"
        return self.ref(key, value.strip(), source)

    def tokens(self, text: str, source: str) -> str:
        """Replace anything matching a known token format."""
        for rule, pattern in TOKEN_PATTERNS:
            if rule == "private-key":
                continue

            def replace(match: re.Match[str], rule: str = rule) -> str:
                return self.ref(rule, match.group(0), source)

            text = pattern.sub(replace, text)
        return text

    def url(self, url: str, source: str) -> str:
        base, sep, query = url.partition("?")
        if not sep:
            return self.tokens(url, source)
        parts = []
        for pair in query.split("&"):
            key, eq, value = pair.partition("=")
            if eq and SENSITIVE_QUERY.match(key) and literal_credential(value):
                value = self.ref(key, value, source)
            parts.append(f"{key}{eq}{value}")
        return self.tokens(base, source) + "?" + "&".join(parts)

    def request(self, request: Request, source: str) -> Request:
        request.url = self.url(request.url, source)
        request.headers = [(k, self.header(k, v, source)) for k, v in request.headers]
        request.body = self.tokens(request.body, source)
        return request

    def env_value(self, env: str, key: str, value: str, *, secret: bool = False) -> str:
        if "{{" in value:
            return value
        if secret or (SENSITIVE_NAME.search(key) and (literal_credential(value) or not value)):
            return self.ref(key, value, f"environment {env}")
        if SENSITIVE_NAME.search(key) and " " in value.strip():
            # Prose like "Your token here": a placeholder, so ask for the real value.
            return self.ref(key, "", f"environment {env}")
        return self.tokens(value, f"environment {env}")
