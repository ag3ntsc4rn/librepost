import json
import ssl
from pathlib import Path

import httpx
import pytest
from tls_helpers import Certs, make_certs, mtls_server, proxy_server

from librepost import connection, environments, manage, runner
from librepost.connection import ConnectionError_
from librepost.httpfile import Request
from librepost.manage import ConnectionForm, Row
from librepost.template import Renderer


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certs:
    return make_certs(tmp_path_factory.mktemp("certs"))


def write_private(root: Path, data: dict[str, object]) -> None:
    (root / environments.PRIVATE_FILE).write_text(json.dumps(data))


def lookup(ref: str) -> str:
    return {"keychain/pass": "fake-key-passphrase", "keychain/proxy-pw": "fake-proxy-pw"}[ref]


def send(root: Path, env: str | None, url: str, *, insecure: bool = False) -> runner.Result:
    prepared = runner.prepare(Request("GET", url), {}, lookup)
    net = connection.settings(connection.load(root, env), prepared.renderer, insecure=insecure)
    return runner.send(prepared, verify=net.verify, proxy=net.proxy, timeout=10)


def test_load_reads_private_file_only(tmp_path: Path, certs: Certs) -> None:
    (tmp_path / environments.PUBLIC_FILE).write_text(
        json.dumps(
            {"dev": {"base": "x", "ProxyConfiguration": {"url": "http://evil.invalid:8080"}}}
        )
    )
    write_private(
        tmp_path,
        {
            "$shared": {"SSLConfiguration": {"caCertificate": str(certs.ca)}},
            "dev": {
                "SSLConfiguration": {
                    "clientCertificate": "certs/me.pem",
                    "verifyHostCertificate": False,
                }
            },
        },
    )
    conn = connection.load(tmp_path, "dev")
    assert conn.proxy == ""  # the shared file's proxy is ignored...
    assert "Ignored connection settings for 'dev'" in conn.warnings[0]  # ...with a warning
    assert conn.ca == certs.ca  # $shared applies
    assert conn.client_cert == tmp_path / "certs/me.pem"  # relative to the workspace
    assert conn.verify is False
    # Connection settings are not variables.
    assert environments.variables(tmp_path, "dev") == {"base": "x"}


def test_load_errors_and_home_paths(tmp_path: Path) -> None:
    write_private(
        tmp_path,
        {"dev": {"SSLConfiguration": {"clientCertificate": {"path": "a.p12", "format": "PFX"}}}},
    )
    with pytest.raises(ConnectionError_, match="only PEM"):
        connection.load(tmp_path, "dev")
    write_private(tmp_path, {"dev": {"SSLConfiguration": {"clientCertificateKey": "k.pem"}}})
    with pytest.raises(ConnectionError_, match="without clientCertificate"):
        connection.load(tmp_path, "dev")
    write_private(tmp_path, {"dev": {"SSLConfiguration": {"clientCertificate": "~/me.pem"}}})
    assert connection.load(tmp_path, "dev").client_cert == Path.home() / "me.pem"


def test_settings_defaults_and_errors(tmp_path: Path, certs: Certs) -> None:
    plain = connection.settings(connection.Connection(), Renderer({}, lookup))
    assert plain.verify is True and plain.proxy is None and plain.notes == []

    insecure = connection.settings(connection.Connection(), Renderer({}, lookup), insecure=True)
    assert (
        isinstance(insecure.verify, ssl.SSLContext) and insecure.verify.verify_mode == ssl.CERT_NONE
    )

    with pytest.raises(ConnectionError_, match="doesn't exist"):
        connection.settings(
            connection.Connection(client_cert=tmp_path / "nope.pem"), Renderer({}, lookup)
        )
    # An encrypted key without a passphrase fails cleanly instead of prompting on the terminal.
    with pytest.raises(ConnectionError_, match="passphrase"):
        connection.settings(
            connection.Connection(
                client_cert=certs.client_cert, client_key=certs.client_key_encrypted
            ),
            Renderer({}, lookup),
        )
    with pytest.raises(ConnectionError_, match="passphrase"):
        connection.settings(
            connection.Connection(
                client_cert=certs.client_cert,
                client_key=certs.client_key_encrypted,
                passphrase="wrong",
            ),
            Renderer({}, lookup),
        )
    with pytest.raises(ConnectionError_, match="don't match"):
        connection.settings(
            connection.Connection(client_cert=certs.client_cert, client_key=certs.other_client_key),
            Renderer({}, lookup),
        )
    with pytest.raises(ConnectionError_, match="must start with"):
        connection.settings(connection.Connection(proxy="proxy.invalid:8080"), Renderer({}, lookup))


def test_mtls_with_client_certificate(tmp_path: Path, certs: Certs) -> None:
    with mtls_server(certs) as port:
        url = f"https://localhost:{port}/"
        # Without a client certificate the server refuses the connection.
        write_private(tmp_path, {"dev": {"SSLConfiguration": {"caCertificate": str(certs.ca)}}})
        with pytest.raises(httpx.HTTPError):
            send(tmp_path, "dev", url)

        write_private(
            tmp_path,
            {
                "dev": {
                    "SSLConfiguration": {
                        "clientCertificate": str(certs.client_cert),
                        "clientCertificateKey": str(certs.client_key_encrypted),
                        "certificatePassphrase": "{{secret:keychain/pass}}",
                        "caCertificate": str(certs.ca),
                    }
                }
            },
        )
        result = send(tmp_path, "dev", url)
        assert result.status == 200 and json.loads(result.body) == {"client": "test client"}
        assert result.tls["subject"] == "localhost"
        assert result.tls["issuer"] == "librepost test CA"
        assert result.tls["version"].startswith("TLS")

        # Certificate and key in one file.
        write_private(
            tmp_path,
            {
                "dev": {
                    "SSLConfiguration": {
                        "clientCertificate": str(certs.client_combined),
                        "caCertificate": str(certs.ca),
                    }
                }
            },
        )
        assert send(tmp_path, "dev", url).status == 200

        # A certificate from a CA the server doesn't trust is refused.
        write_private(
            tmp_path,
            {
                "dev": {
                    "SSLConfiguration": {
                        "clientCertificate": str(certs.other_client_cert),
                        "clientCertificateKey": str(certs.other_client_key),
                        "caCertificate": str(certs.ca),
                    }
                }
            },
        )
        with pytest.raises(httpx.HTTPError):
            send(tmp_path, "dev", url)


def test_server_certificate_verification(tmp_path: Path, certs: Certs) -> None:
    with mtls_server(certs) as port:
        url = f"https://localhost:{port}/"
        client = {"clientCertificate": str(certs.client_combined)}
        # The test CA isn't trusted by default...
        write_private(tmp_path, {"dev": {"SSLConfiguration": client}})
        with pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
            send(tmp_path, "dev", url)
        # ...unless verification is switched off, which the response reports.
        write_private(
            tmp_path, {"dev": {"SSLConfiguration": {**client, "verifyHostCertificate": False}}}
        )
        result = send(tmp_path, "dev", url)
        assert result.status == 200 and result.tls["verified"] == "no"
        # The custom CA is added to the default ones, not swapped in for them.
        conn = connection.Connection(ca=certs.ca)
        context = connection.settings(conn, Renderer({}, lookup)).verify
        assert isinstance(context, ssl.SSLContext)
        assert len(context.get_ca_certs()) > 10


def test_proxy_http_and_connect(tmp_path: Path, certs: Certs) -> None:
    with proxy_server() as (proxy_port, seen), mtls_server(certs) as port:
        write_private(
            tmp_path,
            {
                "dev": {
                    "ProxyConfiguration": {
                        "url": f"http://me:{{{{secret:keychain/proxy-pw}}}}@127.0.0.1:{proxy_port}"
                    },
                    "SSLConfiguration": {
                        "clientCertificate": str(certs.client_combined),
                        "caCertificate": str(certs.ca),
                    },
                }
            },
        )
        plain = send(tmp_path, "dev", "http://api.example.invalid/x")
        assert json.loads(plain.body) == {"via": "proxy"}
        assert seen[0].startswith("GET http://api.example.invalid/x auth=Basic ")

        tunnelled = send(tmp_path, "dev", f"https://localhost:{port}/")
        assert json.loads(tunnelled.body) == {"client": "test client"}
        assert seen[-1] == f"CONNECT localhost:{port}"

        prepared = runner.prepare(Request("GET", "http://a.invalid"), {}, lookup)
        net = connection.settings(connection.load(tmp_path, "dev"), prepared.renderer)
        assert (
            prepared.renderer.mask(net.notes[0])
            == f"via proxy http://me:••••••@127.0.0.1:{proxy_port}"
        )


def test_manage_connection_form(tmp_path: Path, certs: Certs) -> None:
    stored: dict[str, str] = {}
    (tmp_path / environments.PUBLIC_FILE).write_text('{"dev": {}}')
    form = ConnectionForm(
        client_cert=str(certs.client_cert),
        client_key=str(certs.client_key_encrypted),
        ca=str(certs.ca),
        verify=True,
        proxy="http://proxy.invalid:8080",
    )
    manage.save_connection(tmp_path, "dev", form, "fake-key-passphrase", False, stored.__setitem__)
    assert stored == {"dev-cert-passphrase": "fake-key-passphrase"}
    private = json.loads((tmp_path / environments.PRIVATE_FILE).read_text())
    assert (
        private["dev"]["SSLConfiguration"]["certificatePassphrase"]
        == "{{secret:keychain/dev-cert-passphrase}}"
    )
    assert (tmp_path / environments.PUBLIC_FILE).read_text() == '{"dev": {}}'  # untouched

    shown = manage.connection_form(tmp_path, "dev")
    assert (
        shown.passphrase_ref == "keychain/dev-cert-passphrase"
        and shown.proxy == "http://proxy.invalid:8080"
    )

    # Saving variables keeps the connection settings; the editor doesn't list them as variables.
    manage.save(tmp_path, "dev", [Row("me", "x", "private")], stored.__setitem__)
    private = json.loads((tmp_path / environments.PRIVATE_FILE).read_text())
    assert set(private["dev"]) == {"me", "SSLConfiguration", "ProxyConfiguration"}
    assert [r.key for r in manage.rows(tmp_path, "dev")] == ["me"]

    # Saving again without a new passphrase keeps the stored one; "remove" drops it.
    manage.save_connection(tmp_path, "dev", form, "", False, stored.__setitem__)
    assert manage.connection_form(tmp_path, "dev").passphrase_ref
    manage.save_connection(tmp_path, "dev", ConnectionForm(), "", True, stored.__setitem__)
    assert json.loads((tmp_path / environments.PRIVATE_FILE).read_text())["dev"] == {"me": "x"}

    with pytest.raises(manage.ManageError, match="proxy URL"):
        manage.save_connection(
            tmp_path, "dev", ConnectionForm(proxy="proxy:80"), "", False, stored.__setitem__
        )
