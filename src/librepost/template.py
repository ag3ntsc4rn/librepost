"""Fill in `{{...}}` placeholders.

{{name}}                   an environment or file variable (may itself contain placeholders)
{{secret:keychain/name}}   a secret, looked up at send time (see secretstore)
{{$uuid}} {{$guid}}        a random UUID
{{$timestamp}}             Unix time in seconds
{{$isoTimestamp}}          current UTC time, ISO 8601
{{$randomInt}}             a random integer from 0 to 999
"""

from __future__ import annotations

import random
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

PLACEHOLDER = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")
MAX_DEPTH = 10
MASK = "••••••"


class TemplateError(ValueError):
    pass


def _dynamic(name: str) -> str | None:
    if name in ("$uuid", "$guid"):
        return str(uuid.uuid4())
    if name == "$timestamp":
        return str(int(time.time()))
    if name == "$isoTimestamp":
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if name == "$randomInt":
        return str(random.randint(0, 999))
    return None


class Renderer:
    """Renders text against a set of variables, remembering every secret value it used so
    callers can mask them in anything shown on screen."""

    def __init__(
        self,
        variables: dict[str, str],
        secret_lookup: Callable[[str], str],
    ) -> None:
        self.variables = variables
        self.secret_lookup = secret_lookup
        self.secret_values: set[str] = set()
        self._secret_cache: dict[str, str] = {}
        self.missing: list[str] = []

    def render(self, text: str) -> str:
        return self._render(text, 0)

    def _render(self, text: str, depth: int) -> str:
        if depth > MAX_DEPTH:
            raise TemplateError("Variables refer to each other in a loop.")

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name.startswith("secret:"):
                ref = name.removeprefix("secret:")
                if ref not in self._secret_cache:
                    self._secret_cache[ref] = self.secret_lookup(ref)
                value = self._secret_cache[ref]
                if value:
                    self.secret_values.add(value)
                return value
            dynamic = _dynamic(name)
            if dynamic is not None:
                return dynamic
            if name in self.variables:
                return self._render(self.variables[name], depth + 1)
            if name not in self.missing:
                self.missing.append(name)
            return match.group(0)

        return PLACEHOLDER.sub(replace, text)

    def check(self) -> None:
        if self.missing:
            names = ", ".join(self.missing)
            raise TemplateError(
                f"Undefined variable(s): {names}. Define them in http-client.env.json, "
                "http-client.private.env.json or with @name = value in the file."
            )

    def mask(self, text: str) -> str:
        for value in sorted(self.secret_values, key=len, reverse=True):
            text = text.replace(value, MASK)
        return text
