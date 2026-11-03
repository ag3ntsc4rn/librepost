"""Environments, in the JetBrains HTTP Client format.

`http-client.env.json` is committed and holds shared, non-secret values.
`http-client.private.env.json` is gitignored and overrides it per machine:

    {
      "$shared": {"apiVersion": "v2"},
      "dev":     {"baseUrl": "https://dev.example.com", "token": "{{secret:keychain/dev-token}}"},
      "prod":    {"baseUrl": "https://api.example.com"}
    }

`$shared` values apply to every environment.
"""

from __future__ import annotations

import json
from pathlib import Path

PUBLIC_FILE = "http-client.env.json"
PRIVATE_FILE = "http-client.private.env.json"
SHARED = "$shared"


class EnvFileError(ValueError):
    pass


def _read(path: Path) -> dict[str, dict[str, str]]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvFileError(f"Can't read {path.name}: {exc}") from None
    if not isinstance(data, dict):
        raise EnvFileError(f"{path.name} must contain a JSON object of environments.")
    result: dict[str, dict[str, str]] = {}
    for env, values in data.items():
        if not isinstance(values, dict):
            raise EnvFileError(f"{path.name}: environment {env!r} must be an object.")
        result[env] = {str(k): _to_text(v) for k, v in values.items()}
    return result


def _to_text(value: object) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value)


def load(root: Path) -> dict[str, dict[str, str]]:
    """All environments under `root`, with private values overriding public ones."""
    merged = _read(root / PUBLIC_FILE)
    for env, values in _read(root / PRIVATE_FILE).items():
        merged.setdefault(env, {}).update(values)
    return merged


def names(root: Path) -> list[str]:
    return sorted(env for env in load(root) if env != SHARED)


# Connection settings (see connection.py), not variables.
RESERVED = ("SSLConfiguration", "ProxyConfiguration")


def variables(root: Path, env: str | None) -> dict[str, str]:
    envs = load(root)
    result = dict(envs.get(SHARED, {}))
    if env:
        if env not in envs:
            raise EnvFileError(f"Unknown environment {env!r}.")
        result.update(envs[env])
    for key in RESERVED:
        result.pop(key, None)
    return result
