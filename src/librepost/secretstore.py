"""Secret references: `{{secret:<provider>/<key>}}`.

Values are looked up only when a request is sent, so they never land in `.http` files,
environment files or git history.

Providers:
    keychain/<key>  the OS keychain (macOS Keychain, Windows Credential Manager, Secret
                    Service on Linux), under the service name "librepost"
    env/<NAME>      an environment variable of the librepost process
"""

from __future__ import annotations

import os
import re

SERVICE = "librepost"
PROVIDERS = ("keychain", "env")

_KEY = re.compile(r"[A-Za-z0-9_.-]+")


class SecretError(LookupError):
    pass


def check_key(key: str) -> None:
    if not _KEY.fullmatch(key):
        raise SecretError(f"Invalid secret name {key!r}: use letters, digits, '.', '_' and '-'.")


def lookup(ref: str) -> str:
    provider, _, key = ref.partition("/")
    if provider not in PROVIDERS or not key:
        raise SecretError(
            f"Unknown secret reference 'secret:{ref}'. Use secret:keychain/<name> or secret:env/<NAME>."
        )
    check_key(key)
    if provider == "env":
        try:
            return os.environ[key]
        except KeyError:
            raise SecretError(f"Environment variable {key} is not set.") from None
    value = _keyring_call("get_password", key)
    if value is None:
        raise SecretError(
            f"Secret '{key}' is not in the keychain. Add it with: librepost secret set {key}"
        )
    return str(value)


def exists(ref: str) -> bool:
    """Whether a reference resolves, without returning the value."""
    try:
        return lookup(ref) != ""
    except SecretError:
        return False


def store(key: str, value: str) -> None:
    check_key(key)
    _keyring_call("set_password", key, value)


def delete(key: str) -> None:
    check_key(key)
    _keyring_call("delete_password", key)


def _keyring_call(name: str, *args: str) -> object:
    import keyring
    import keyring.errors

    try:
        return getattr(keyring, name)(SERVICE, *args)
    except keyring.errors.PasswordDeleteError:
        raise SecretError(f"Secret '{args[0]}' is not in the keychain.") from None
    except keyring.errors.KeyringError as exc:
        raise SecretError(
            f"The OS keychain is unavailable ({exc}). On a headless machine, use secret:env/<NAME> instead."
        ) from None
