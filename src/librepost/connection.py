"""Client certificates (mTLS), extra CA certificates, host verification and proxies.

Configured per environment in the JetBrains HTTP Client format, plus a few librepost
additions, and read **only from http-client.private.env.json**: a repository you clone
must not be able to send your requests through its own proxy or switch off certificate
checks. The same keys in the shared file are ignored with a warning.

    "dev": {
      "SSLConfiguration": {
        "clientCertificate": "~/.certs/me.pem",          # or {"path": "...", "format": "PEM"}
        "clientCertificateKey": "~/.certs/me-key.pem",   # omit if the key is in the cert file
        "certificatePassphrase": "{{secret:keychain/dev-cert-pass}}",   # librepost
        "caCertificate": "~/.certs/corp-ca.pem",         # librepost: added to the usual CAs
        "verifyHostCertificate": true
      },
      "ProxyConfiguration": {"url": "http://user:{{secret:keychain/proxy}}@proxy:8080"}   # librepost
    }

`$shared` settings apply to every environment; an environment's own settings override them.
"""

from __future__ import annotations

import json
import os
import ssl
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .environments import PRIVATE_FILE, PUBLIC_FILE, SHARED
from .template import Renderer

SSL_KEY = "SSLConfiguration"
PROXY_KEY = "ProxyConfiguration"
RESERVED = (SSL_KEY, PROXY_KEY)


class ConnectionError_(ValueError):
    """The connection settings can't be used."""


@dataclass
class Connection:
    client_cert: Path | None = None
    client_key: Path | None = None
    passphrase: str = ""  # may hold placeholders
    ca: Path | None = None
    verify: bool = True
    proxy: str = ""  # may hold placeholders
    warnings: list[str] = field(default_factory=list)

    @property
    def configured(self) -> bool:
        return bool(self.client_cert or self.ca or not self.verify or self.proxy)


@dataclass
class Settings:
    verify: ssl.SSLContext | bool = True
    proxy: str | None = None
    # Human-readable notes for "Request sent"; may contain secrets until masked.
    notes: list[str] = field(default_factory=list)


def _read(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}  # environments.load() reports unreadable files
    return data if isinstance(data, dict) else {}


def _path(value: Any, root: Path, what: str) -> Path | None:
    if isinstance(value, dict):
        fmt = str(value.get("format", "PEM")).upper()
        if fmt != "PEM":
            raise ConnectionError_(
                f"{what}: only PEM files are supported. Convert a .pfx/.p12 with: "
                "openssl pkcs12 -in cert.p12 -out cert.pem -nodes"
            )
        value = value.get("path")
    if not value:
        return None
    path = Path(os.path.expandvars(str(value))).expanduser()
    return path if path.is_absolute() else root / path


def _encrypted(path: Path) -> bool:
    try:
        text = path.read_text(encoding="ascii", errors="ignore")
    except OSError:
        return False
    return "ENCRYPTED PRIVATE KEY" in text or "Proc-Type: 4,ENCRYPTED" in text


def load(root: Path, env: str | None) -> Connection:
    public, private = _read(root / PUBLIC_FILE), _read(root / PRIVATE_FILE)
    conn = Connection()
    scopes = [SHARED] + ([env] if env else [])
    for scope in scopes:
        values = public.get(scope)
        if isinstance(values, dict) and any(key in values for key in RESERVED):
            conn.warnings.append(
                f"Ignored connection settings for {scope!r} in {PUBLIC_FILE}: they only take "
                f"effect in {PRIVATE_FILE}, so a shared repository can't redirect your traffic."
            )
    merged: dict[str, dict[str, Any]] = {}
    for scope in scopes:
        values = private.get(scope)
        if not isinstance(values, dict):
            continue
        for key in RESERVED:
            if isinstance(values.get(key), dict):
                merged[key] = {**merged.get(key, {}), **values[key]}

    tls = merged.get(SSL_KEY, {})
    conn.client_cert = _path(tls.get("clientCertificate"), root, "clientCertificate")
    conn.client_key = _path(tls.get("clientCertificateKey"), root, "clientCertificateKey")
    conn.ca = _path(tls.get("caCertificate"), root, "caCertificate")
    conn.passphrase = str(tls.get("certificatePassphrase") or "")
    conn.verify = tls.get("verifyHostCertificate", True) is not False
    if tls.get("hasCertificatePassphrase") and not conn.passphrase:
        conn.warnings.append(
            "hasCertificatePassphrase is set but no certificatePassphrase: add one, e.g. "
            '"certificatePassphrase": "{{secret:keychain/<name>}}".'
        )
    if conn.client_key and not conn.client_cert:
        raise ConnectionError_("clientCertificateKey is set without clientCertificate.")
    conn.proxy = str(merged.get(PROXY_KEY, {}).get("url") or "")
    return conn


def settings(conn: Connection, renderer: Renderer, *, insecure: bool = False) -> Settings:
    """Build what httpx needs. Placeholders are filled in with (and masked by) `renderer`."""
    passphrase = renderer.render(conn.passphrase) if conn.passphrase else ""
    proxy = renderer.render(conn.proxy) if conn.proxy else ""
    renderer.check()
    if passphrase:
        renderer.secret_values.add(passphrase)
    result = Settings(proxy=proxy or None)
    if proxy:
        if not proxy.startswith(("http://", "https://", "socks5://")):
            raise ConnectionError_(
                f"Proxy URL must start with http://, https:// or socks5://: {proxy}"
            )
        result.notes.append(f"via proxy {proxy}")
    verify = conn.verify and not insecure
    if not (conn.client_cert or conn.ca or not verify):
        return result  # httpx defaults, including SSL_CERT_FILE from the environment

    for path, what in (
        (conn.client_cert, "client certificate"),
        (conn.client_key, "client key"),
        (conn.ca, "CA certificate"),
    ):
        if path and not path.is_file():
            raise ConnectionError_(f"The {what} file doesn't exist: {path}")

    base = os.environ.get("SSL_CERT_FILE")
    if not base:
        import certifi

        base = certifi.where()
    context = ssl.create_default_context(cafile=base)
    if conn.ca:
        try:
            context.load_verify_locations(cafile=str(conn.ca))
        except ssl.SSLError as exc:
            raise ConnectionError_(
                f"Can't read the CA certificate {conn.ca}: {exc.reason or exc}"
            ) from None
        result.notes.append(f"extra CA certificate {conn.ca}")
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        result.notes.append("server certificate NOT verified")
    if conn.client_cert:
        try:
            context.load_cert_chain(
                str(conn.client_cert),
                str(conn.client_key) if conn.client_key else None,
                # Without a passphrase, fail instead of letting OpenSSL prompt on the terminal.
                password=passphrase or (lambda: ""),
            )
        except ssl.SSLError as exc:
            reason = str(exc.reason or exc)
            if _encrypted(conn.client_key or conn.client_cert):
                hint = (
                    "the passphrase is wrong"
                    if passphrase
                    else "the key is encrypted, so set certificatePassphrase (the Key passphrase field)"
                )
            else:
                hint = "the certificate and key don't match, or they aren't PEM"
            raise ConnectionError_(
                f"Can't load the client certificate ({reason}): {hint}."
            ) from None
        except OSError as exc:
            raise ConnectionError_(f"Can't read the client certificate: {exc}") from None
        result.notes.append(f"client certificate {conn.client_cert}")
    result.verify = context
    return result
