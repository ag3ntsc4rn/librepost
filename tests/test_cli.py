from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from librepost import runner
from librepost.cli import app

cli = CliRunner()


def test_init_then_check(tmp_path: Path) -> None:
    result = cli.invoke(app, ["init", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (tmp_path / "requests/example.http").exists()
    assert "http-client.private.env.json" in (tmp_path / ".gitignore").read_text()
    # Running init twice doesn't duplicate the gitignore entry.
    cli.invoke(app, ["init", str(tmp_path)])
    assert (tmp_path / ".gitignore").read_text().count("http-client.private.env.json") == 1

    result = cli.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 0, result.output


def test_check_fails_on_leak(tmp_path: Path) -> None:
    (tmp_path / "a.http").write_text(
        "GET https://example.invalid\nX-Api-Key: fake-fake-fake-fake\n"
    )
    result = cli.invoke(app, ["check", str(tmp_path)])
    assert result.exit_code == 1
    assert "literal-header" in result.output


def test_run_uses_env_and_name(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "http-client.env.json").write_text(
        '{"dev": {"base": "https://api.example.invalid"}}'
    )
    (tmp_path / "a.http").write_text(
        "# @name first\nGET {{base}}/1\n\n###\n\n# @name second\nDELETE {{base}}/2\n"
    )
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(f"{request.method} {request.url}")
        return httpx.Response(404, text="gone")

    original = runner.send
    monkeypatch.setattr(
        "librepost.cli.runner.send",
        lambda p, **kw: original(p, transport=httpx.MockTransport(handler), **kw),
    )
    result = cli.invoke(
        app, ["run", str(tmp_path / "a.http"), "-n", "second", "-e", "dev", "--fail"]
    )
    assert seen == ["DELETE https://api.example.invalid/2"]
    assert result.exit_code == 22
    assert "gone" in result.output


def test_run_unknown_name(tmp_path: Path) -> None:
    (tmp_path / "a.http").write_text("# @name one\nGET https://example.invalid\n")
    result = cli.invoke(app, ["run", str(tmp_path / "a.http"), "-n", "two"])
    assert result.exit_code == 2
    assert "Names in this file: one" in result.output


def test_run_reports_checks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a.http").write_text(
        "# @expect status == 200\n# @expect $.ok == true\nGET https://api.example.invalid\n"
    )
    original = runner.send
    monkeypatch.setattr(
        "librepost.cli.runner.send",
        lambda p, **kw: original(
            p,
            transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"ok": False})),
            **kw,
        ),
    )
    result = cli.invoke(app, ["run", str(tmp_path / "a.http")])
    assert result.exit_code == 1
    assert "✓ status == 200" in result.output and "✗ $.ok == true" in result.output
