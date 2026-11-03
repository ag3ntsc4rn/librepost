import json
import uuid
from pathlib import Path

import pytest

from librepost import environments, secretstore
from librepost.environments import EnvFileError
from librepost.secretstore import SecretError
from librepost.template import MASK, Renderer, TemplateError


def fake_secrets(ref: str) -> str:
    return {"keychain/token": "s3cr3t-value"}[ref]


def test_variables_nested_and_secrets_masked() -> None:
    r = Renderer(
        {
            "base": "https://{{host}}",
            "host": "example.invalid",
            "auth": "{{secret:keychain/token}}",
        },
        fake_secrets,
    )
    assert r.render("{{base}}/x?a={{ auth }}") == "https://example.invalid/x?a=s3cr3t-value"
    r.check()
    assert r.mask("token=s3cr3t-value") == f"token={MASK}"


def test_missing_variables_listed_once() -> None:
    r = Renderer({}, fake_secrets)
    r.render("{{a}} {{b}} {{a}}")
    with pytest.raises(TemplateError, match="a, b"):
        r.check()


def test_loop_detected() -> None:
    r = Renderer({"a": "{{b}}", "b": "{{a}}"}, fake_secrets)
    with pytest.raises(TemplateError, match="loop"):
        r.render("{{a}}")


def test_dynamic_variables() -> None:
    r = Renderer({}, fake_secrets)
    uuid.UUID(r.render("{{$uuid}}"))
    assert r.render("{{$timestamp}}").isdigit()
    assert 0 <= int(r.render("{{$randomInt}}")) <= 999


def test_env_secret_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LP_TEST_TOKEN", "abc")
    assert secretstore.lookup("env/LP_TEST_TOKEN") == "abc"
    monkeypatch.delenv("LP_TEST_TOKEN")
    with pytest.raises(SecretError, match="not set"):
        secretstore.lookup("env/LP_TEST_TOKEN")


@pytest.mark.parametrize("ref", ["vault/x", "keychain/", "keychain/../x", "env/a b"])
def test_bad_secret_refs(ref: str) -> None:
    with pytest.raises(SecretError):
        secretstore.lookup(ref)


def test_keychain_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    import keyring

    store = {("librepost", "tok"): "v"}
    monkeypatch.setattr(keyring, "get_password", lambda s, k: store.get((s, k)))
    assert secretstore.lookup("keychain/tok") == "v"
    with pytest.raises(SecretError, match="librepost secret set nope"):
        secretstore.lookup("keychain/nope")


def test_environments_merge(tmp_path: Path) -> None:
    (tmp_path / environments.PUBLIC_FILE).write_text(
        json.dumps({"$shared": {"v": "1"}, "dev": {"base": "pub", "n": 3}, "prod": {"base": "p"}})
    )
    (tmp_path / environments.PRIVATE_FILE).write_text(json.dumps({"dev": {"base": "priv"}}))
    assert environments.names(tmp_path) == ["dev", "prod"]
    assert environments.variables(tmp_path, "dev") == {"v": "1", "base": "priv", "n": "3"}
    assert environments.variables(tmp_path, None) == {"v": "1"}
    with pytest.raises(EnvFileError):
        environments.variables(tmp_path, "staging")


def test_environments_bad_json(tmp_path: Path) -> None:
    (tmp_path / environments.PUBLIC_FILE).write_text("{nope")
    with pytest.raises(EnvFileError, match="Can't read"):
        environments.load(tmp_path)
