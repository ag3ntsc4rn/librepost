"""Throwaway certificates, an HTTPS server that requires a client certificate, and a
small HTTP proxy (with CONNECT tunnelling), all on 127.0.0.1."""

from __future__ import annotations

import datetime as dt
import http.server
import ipaddress
import select
import socket
import ssl
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class Certs:
    ca: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path
    client_key_encrypted: Path
    client_combined: Path  # cert and key in one file
    other_client_cert: Path  # signed by a CA the server doesn't trust
    other_client_key: Path
    passphrase: str = "fake-key-passphrase"


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _cert(
    subject: str,
    key: ec.EllipticCurvePrivateKey,
    issuer: str,
    issuer_key: ec.EllipticCurvePrivateKey,
    *,
    ca: bool = False,
    server: bool = False,
) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    else:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
            critical=False,
        )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        ).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    elif not ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def _key(key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> bytes:
    algorithm: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm
    )


def make_certs(folder: Path) -> Certs:
    folder.mkdir(parents=True, exist_ok=True)
    ca_key, other_ca_key = (
        ec.generate_private_key(ec.SECP256R1()),
        ec.generate_private_key(ec.SECP256R1()),
    )
    server_key, client_key, other_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    ca = _cert("librepost test CA", ca_key, "librepost test CA", ca_key, ca=True)
    server = _cert("localhost", server_key, "librepost test CA", ca_key, server=True)
    client = _cert("test client", client_key, "librepost test CA", ca_key)
    other = _cert("stranger", other_key, "other CA", other_ca_key)

    certs = Certs(
        ca=folder / "ca.pem",
        server_cert=folder / "server.pem",
        server_key=folder / "server-key.pem",
        client_cert=folder / "client.pem",
        client_key=folder / "client-key.pem",
        client_key_encrypted=folder / "client-key-enc.pem",
        client_combined=folder / "client-combined.pem",
        other_client_cert=folder / "other.pem",
        other_client_key=folder / "other-key.pem",
    )
    certs.ca.write_bytes(_pem(ca))
    certs.server_cert.write_bytes(_pem(server))
    certs.server_key.write_bytes(_key(server_key))
    certs.client_cert.write_bytes(_pem(client))
    certs.client_key.write_bytes(_key(client_key))
    certs.client_key_encrypted.write_bytes(_key(client_key, certs.passphrase.encode()))
    certs.client_combined.write_bytes(_pem(client) + _key(client_key))
    certs.other_client_cert.write_bytes(_pem(other))
    certs.other_client_key.write_bytes(_key(other_key))
    return certs


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        peer = self.connection.getpeercert() if isinstance(self.connection, ssl.SSLSocket) else None
        subject = ""
        if peer:
            subject = dict(item for rdn in peer.get("subject", ()) for item in rdn).get(
                "commonName", ""
            )  # type: ignore[misc]
        body = f'{{"client": "{subject}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@contextmanager
def mtls_server(certs: Certs) -> Iterator[int]:
    """An HTTPS server on 127.0.0.1 that requires a client certificate from the test CA."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certs.server_cert, certs.server_key)
    context.load_verify_locations(certs.ca)
    context.verify_mode = ssl.CERT_REQUIRED
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


class _Proxy(http.server.BaseHTTPRequestHandler):
    seen: list[str]

    def do_CONNECT(self) -> None:  # noqa: N802
        self.seen.append(f"CONNECT {self.path}")
        host, port = self.path.rsplit(":", 1)
        upstream = socket.create_connection((host, int(port)))
        self.send_response(200, "Connection established")
        self.end_headers()
        sockets = [self.connection, upstream]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 5)
                if not readable:
                    break
                for sock in readable:
                    data = sock.recv(65536)
                    if not data:
                        return
                    (upstream if sock is self.connection else self.connection).sendall(data)
        finally:
            upstream.close()

    def do_GET(self) -> None:  # noqa: N802
        self.seen.append(f"GET {self.path} auth={self.headers.get('Proxy-Authorization', '')}")
        body = b'{"via": "proxy"}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@contextmanager
def proxy_server() -> Iterator[tuple[int, list[str]]]:
    seen: list[str] = []
    handler = type("Handler", (_Proxy,), {"seen": seen})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], seen
    finally:
        server.shutdown()
        server.server_close()
