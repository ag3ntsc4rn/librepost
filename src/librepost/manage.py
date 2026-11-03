"""Editing environments and listing secret references, for the UI.

Shared values live in http-client.env.json (committed); private values live in
http-client.private.env.json (this machine only, created readable by the owner alone).
A credential-looking value is never written to the shared file.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .connection import PROXY_KEY, SSL_KEY
from .environments import PRIVATE_FILE, PUBLIC_FILE, RESERVED, SHARED
from .importers.sanitize import slug
from .leakcheck import SENSITIVE_NAME, TOKEN_PATTERNS, git_ignored, literal_credential
from .workspace import Workspace

SECRET_REF = re.compile(r"\{\{\s*secret:([A-Za-z]+)/([^{}\s]*)\s*\}\}")
ENV_NAME = re.compile(r"[A-Za-z0-9_.-]+")
VAR_NAME = re.compile(r"[A-Za-z_$][\w.$-]*")
SHARED_LOCATION, PRIVATE_LOCATION = "shared", "private"


class ManageError(ValueError):
    pass


@dataclass
class Row:
    key: str
    value: str
    location: str = SHARED_LOCATION
    secret: bool = False

    @property
    def sensitive(self) -> bool:
        """A credential-like name: its value is masked on screen."""
        return bool(SENSITIVE_NAME.search(self.key))

    @property
    def secret_ref(self) -> str:
        match = SECRET_REF.fullmatch(self.value.strip())
        return f"{match.group(1)}/{match.group(2)}" if match else ""


@dataclass
class SecretRef:
    provider: str
    key: str
    used_in: list[str] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.provider}/{self.key}"


def _read(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManageError(f"Can't read {path.name}: {exc}") from None
    if not isinstance(data, dict):
        raise ManageError(f"{path.name} must contain a JSON object of environments.")
    return data


def _write(path: Path, data: dict[str, Any], *, private: bool) -> None:
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".librepost-", suffix=".tmp")
    try:
        # mkstemp creates the file readable by the owner only, which the private file
        # needs. An existing shared file keeps its mode.
        if not private and path.exists():
            os.chmod(tmp, path.stat().st_mode & 0o777)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value)


def env_names(root: Path) -> list[str]:
    names = set(_read(root / PUBLIC_FILE)) | set(_read(root / PRIVATE_FILE))
    return [SHARED] + sorted(n for n in names if n != SHARED)


def rows(root: Path, env: str) -> list[Row]:
    result = []
    for location, filename in ((SHARED_LOCATION, PUBLIC_FILE), (PRIVATE_LOCATION, PRIVATE_FILE)):
        values = _read(root / filename).get(env, {})
        if isinstance(values, dict):
            for key, value in values.items():
                if key not in RESERVED:  # connection settings have their own form
                    result.append(Row(str(key), _text(value), location))
    return result


def _keep_reserved(old: Any, new: dict[str, Any]) -> dict[str, Any]:
    """Carry an environment's connection settings over when its variables are replaced."""
    if isinstance(old, dict):
        new.update({k: v for k, v in old.items() if k in RESERVED})
    return new


def looks_like_credential(key: str, value: str) -> bool:
    if "{{" in value:
        return False
    if any(p.search(value) for _, p in TOKEN_PATTERNS):
        return True
    return bool(SENSITIVE_NAME.search(key)) and literal_credential(value)


def check_env_name(env: str) -> None:
    if env != SHARED and not ENV_NAME.fullmatch(env):
        raise ManageError(
            f"Invalid environment name {env!r}: use letters, digits, '.', '_' and '-'."
        )


def save(root: Path, env: str, new_rows: list[Row], store: Callable[[str, str], None]) -> list[str]:
    """Replace environment `env` with `new_rows`. Returns the names of secrets stored."""
    check_env_name(env)
    seen: set[tuple[str, str]] = set()
    for row in new_rows:
        if not VAR_NAME.fullmatch(row.key):
            raise ManageError(f"Invalid variable name {row.key!r}.")
        if row.location not in (SHARED_LOCATION, PRIVATE_LOCATION):
            raise ManageError(f"Invalid location for {row.key}.")
        if (row.key, row.location) in seen:
            raise ManageError(f"{row.key} appears twice in the {row.location} values.")
        seen.add((row.key, row.location))
        if (
            row.location == SHARED_LOCATION
            and not row.secret
            and looks_like_credential(row.key, row.value)
        ):
            raise ManageError(
                f"{row.key} looks like a credential, so it can't be saved as a shared value "
                "(that file is committed to git). Tick 🔒 to keep it in your keychain, or store it as private."
            )

    stored = []
    for row in new_rows:
        if row.secret and not row.secret_ref:
            if not row.value:
                raise ManageError(f"Enter a value for {row.key} to store it in the keychain.")
            name = f"{slug(env if env != SHARED else 'shared')}-{slug(row.key)}"
            store(name, row.value)
            row.value = f"{{{{secret:keychain/{name}}}}}"
            stored.append(name)

    shared = {r.key: r.value for r in new_rows if r.location == SHARED_LOCATION}
    private = {r.key: r.value for r in new_rows if r.location == PRIVATE_LOCATION}

    public_data = _read(root / PUBLIC_FILE)
    shared = _keep_reserved(public_data.get(env), shared)
    if shared or env != SHARED:
        public_data[env] = shared  # an empty object keeps the environment listed
    else:
        public_data.pop(SHARED, None)
    _write(root / PUBLIC_FILE, public_data, private=False)

    private_path = root / PRIVATE_FILE
    private_data = _read(private_path)
    private = _keep_reserved(private_data.get(env), private)
    if private:
        private_data[env] = private
    elif env in private_data:
        del private_data[env]
    else:
        return stored
    _write(private_path, private_data, private=True)
    return stored


@dataclass
class ConnectionForm:
    client_cert: str = ""
    client_key: str = ""
    passphrase_ref: str = ""  # an existing {{secret:...}} reference, if any
    has_literal_passphrase: bool = False
    ca: str = ""
    verify: bool = True
    proxy: str = ""


def connection_form(root: Path, env: str) -> ConnectionForm:
    values = _read(root / PRIVATE_FILE).get(env, {})
    values = values if isinstance(values, dict) else {}
    tls = values.get(SSL_KEY, {}) if isinstance(values.get(SSL_KEY), dict) else {}
    proxy = values.get(PROXY_KEY, {}) if isinstance(values.get(PROXY_KEY), dict) else {}

    def path(value: Any) -> str:
        return str(value.get("path", "") if isinstance(value, dict) else value or "")

    passphrase = str(tls.get("certificatePassphrase") or "")
    match = SECRET_REF.fullmatch(passphrase.strip())
    return ConnectionForm(
        client_cert=path(tls.get("clientCertificate")),
        client_key=path(tls.get("clientCertificateKey")),
        passphrase_ref=f"{match.group(1)}/{match.group(2)}" if match else "",
        has_literal_passphrase=bool(passphrase) and not match,
        ca=path(tls.get("caCertificate")),
        verify=tls.get("verifyHostCertificate", True) is not False,
        proxy=str(proxy.get("url") or ""),
    )


def save_connection(
    root: Path,
    env: str,
    form: ConnectionForm,
    new_passphrase: str,
    clear_passphrase: bool,
    store: Callable[[str, str], None],
) -> None:
    """Write the environment's connection settings to the private file only."""
    check_env_name(env)
    if form.client_key and not form.client_cert:
        raise ManageError("A client key needs a client certificate too.")
    if form.proxy and not form.proxy.startswith(("http://", "https://", "socks5://")):
        raise ManageError("The proxy URL must start with http://, https:// or socks5://.")
    private_path = root / PRIVATE_FILE
    data = _read(private_path)
    current = data.get(env)
    values: dict[str, Any] = current if isinstance(current, dict) else {}
    tls_value = values.get(SSL_KEY)
    old_tls: dict[str, Any] = tls_value if isinstance(tls_value, dict) else {}

    tls: dict[str, Any] = {}
    if form.client_cert:
        tls["clientCertificate"] = form.client_cert
    if form.client_key:
        tls["clientCertificateKey"] = form.client_key
    if new_passphrase:
        name = f"{slug(env if env != SHARED else 'shared')}-cert-passphrase"
        store(name, new_passphrase)
        tls["certificatePassphrase"] = f"{{{{secret:keychain/{name}}}}}"
    elif old_tls.get("certificatePassphrase") and not clear_passphrase:
        tls["certificatePassphrase"] = old_tls["certificatePassphrase"]
    if form.ca:
        tls["caCertificate"] = form.ca
    if not form.verify:
        tls["verifyHostCertificate"] = False

    values = {k: v for k, v in values.items() if k not in RESERVED}
    if tls:
        values[SSL_KEY] = tls
    if form.proxy:
        values[PROXY_KEY] = {"url": form.proxy}
    if values:
        data[env] = values
    else:
        data.pop(env, None)
    _write(private_path, data, private=True)


def create(root: Path, env: str) -> None:
    check_env_name(env)
    if env in env_names(root):
        raise ManageError(f"Environment {env!r} already exists.")
    data = _read(root / PUBLIC_FILE)
    data[env] = {}
    _write(root / PUBLIC_FILE, data, private=False)


def delete(root: Path, env: str) -> None:
    check_env_name(env)
    for filename in (PUBLIC_FILE, PRIVATE_FILE):
        path = root / filename
        data = _read(path)
        if env in data:
            del data[env]
            _write(path, data, private=filename == PRIVATE_FILE)


def private_file_tracked(root: Path) -> bool:
    """True when the private file exists in a git repository and isn't gitignored."""
    path = root / PRIVATE_FILE
    return path.exists() and git_ignored(path) is False


def ignore_private_file(root: Path) -> None:
    gitignore = root / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    if PRIVATE_FILE in existing.splitlines():
        return
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    with gitignore.open("a", encoding="utf-8", newline="\n") as f:
        f.write(f"{prefix}# librepost: per-machine values, never committed\n{PRIVATE_FILE}\n")


def secret_refs(root: Path) -> list[SecretRef]:
    """Every {{secret:...}} reference in the workspace's request and environment files."""
    workspace = Workspace(root)
    found: dict[str, SecretRef] = {}
    sources = [*workspace.files(), PUBLIC_FILE, PRIVATE_FILE]
    for rel in sources:
        path = workspace.root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for match in SECRET_REF.finditer(text):
            ref = SecretRef(match.group(1), match.group(2))
            entry = found.setdefault(ref.ref, ref)
            if rel not in entry.used_in:
                entry.used_in.append(rel)
    return sorted(found.values(), key=lambda r: (r.provider, r.key.lower()))
