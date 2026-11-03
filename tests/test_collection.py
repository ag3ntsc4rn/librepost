import json
import xml.etree.ElementTree as ET
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from librepost import checks, collection, importers
from librepost.cli import app
from librepost.importers.scripts import convert


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        (
            'pm.environment.set("token", pm.response.json().access_token);',
            ["@capture token = $.access_token"],
        ),
        (
            "pm.collectionVariables.set('id', pm.response.json().data[0].id)",
            ["@capture id = $.data[0].id"],
        ),
        (
            'postman.setEnvironmentVariable("t", JSON.parse(responseBody).auth["token"]);',
            ['@capture t = $.auth["token"]'],
        ),
        (
            'var jsonData = pm.response.json();\npm.globals.set("uid", jsonData.user.id);',
            ["@capture uid = $.user.id"],
        ),
        (
            'pm.environment.set("loc", pm.response.headers.get("Location"));',
            ["@capture loc = header Location"],
        ),
        ("pm.response.to.have.status(201);", ["@expect status == 201"]),
        ("pm.expect(pm.response.code).to.eql(200);", ["@expect status == 200"]),
        ('tests["Status code is 200"] = responseCode.code === 200;', ["@expect status == 200"]),
        ("pm.response.to.be.ok;", ["@expect status < 300"]),
        ('pm.response.to.have.header("Content-Type");', ["@expect header Content-Type exists"]),
        ("pm.expect(pm.response.responseTime).to.be.below(500);", ["@expect duration < 500"]),
        (
            "pm.expect(pm.response.text()).to.include('welcome');",
            ['@expect body contains "welcome"'],
        ),
        (
            "const d = pm.response.json(); pm.expect(d.name).to.eql('Ada');",
            ['@expect $.name == "Ada"'],
        ),
        ("pm.expect(pm.response.json().count).to.be.above(3)", ["@expect $.count > 3"]),
        (
            "pm.expect(pm.response.json().items).to.have.lengthOf(2)",
            ["@expect $.items.length == 2"],
        ),
        ('pm.expect(pm.response.json().tags).to.include("x")', ['@expect $.tags contains "x"']),
        ("pm.expect(pm.response.json().id).to.exist", ["@expect $.id exists"]),
        ("pm.expect(pm.response.json().err).to.be.undefined", ["@expect $.err !exists"]),
        ("pm.expect(pm.response.json().ok).to.be.true", ["@expect $.ok == true"]),
        ("pm.expect(pm.response.json()).to.have.property('id')", ['@expect $["id"] exists']),
        (
            'pm.test("ok", function () {\n    pm.response.to.have.status(200);\n});',
            ["@expect status == 200"],
        ),
        ('pm.test("ok", () => { pm.response.to.have.status(200); });', ["@expect status == 200"]),
    ],
)
def test_convert_patterns(script: str, expected: list[str]) -> None:
    result = convert(script.splitlines())
    assert result.checks == expected
    assert result.unconverted == []
    checks.parse(result.checks)  # every converted line is valid


def test_convert_reports_unknown_code() -> None:
    result = convert(
        [
            'pm.test("x", function () {',
            "    pm.response.to.have.status(200);",
            "    var schema = {type: 'object'};",
            "    pm.expect(tv4.validate(pm.response.json(), schema)).to.be.true;",
            "});",
            "// a comment",
            "console.log('done');",
        ]
    )
    assert result.checks == ["@expect status == 200"]
    assert len(result.unconverted) == 2


def test_postman_import_converts_scripts() -> None:
    collection_data = {
        "info": {"name": "Shop"},
        "event": [
            {
                "listen": "test",
                "script": {"exec": ["pm.expect(pm.response.responseTime).to.be.below(2000);"]},
            }
        ],
        "item": [
            {
                "name": "login",
                "event": [
                    {
                        "listen": "test",
                        "script": {
                            "exec": [
                                "var j = pm.response.json();",
                                'pm.environment.set("token", j.token);',
                                "pm.response.to.have.status(200);",
                            ]
                        },
                    },
                    {
                        "listen": "prerequest",
                        "script": {"exec": ["pm.variables.set('x', Date.now());"]},
                    },
                ],
                "request": {"method": "POST", "url": "https://shop.invalid/login"},
            }
        ],
    }
    result = importers.convert(json.dumps(collection_data))
    (request,) = result.files["shop.http"]
    assert request.checks == [
        "@expect duration < 2000",
        "@capture token = $.token",
        "@expect status == 200",
    ]
    joined = " ".join(result.warnings)
    assert "3 @capture/@expect line(s)" in joined
    assert "Skipped 1 script(s)" in joined  # the pre-request script


def make_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login":
            return httpx.Response(200, json={"token": "fake-run-token", "user": {"id": 9}})
        if request.url.path == "/me":
            ok = request.headers.get("authorization") == "Bearer fake-run-token"
            return httpx.Response(200 if ok else 401, json={"id": 9})
        return httpx.Response(500, text="boom")

    return httpx.MockTransport(handler)


@pytest.fixture
def suite(tmp_path: Path) -> Path:
    (tmp_path / "http-client.env.json").write_text(
        '{"ci": {"base": "https://api.example.invalid"}}'
    )
    (tmp_path / "a-auth.http").write_text(
        "# @capture token = $.token\n# @capture uid = $.user.id\n# @expect status == 200\n"
        "# @name login\nPOST {{base}}/login\n\n###\n\n"
        "# @expect status == 200\n# @expect $.id == {{uid}}\n# @name me\n"
        "GET {{base}}/me\nAuthorization: Bearer {{token}}\n"
    )
    (tmp_path / "b-broken.http").write_text(
        "# @expect status == 200\n# @name broken\nGET {{base}}/explode\n\n###\n\n"
        "# @name undefined\nGET {{base}}/{{nope}}\n"
    )
    return tmp_path


def test_run_carries_captures_and_reports(suite: Path) -> None:
    result = collection.run([suite], suite, "ci", transport=make_transport())
    names = [(s.name, s.passed) for s in result.steps]
    assert names == [("login", True), ("me", True), ("broken", False), ("undefined", False)]
    me = result.steps[1]
    assert me.status == 200
    broken, undefined = result.steps[2], result.steps[3]
    assert broken.results[0].actual == "500"
    assert "Undefined variable(s): nope" in undefined.error
    assert result.check_count == 4 and result.checks_failed == 1


def test_bail_stops_early(suite: Path) -> None:
    result = collection.run([suite], suite, "ci", bail=True, transport=make_transport())
    assert [s.name for s in result.steps] == ["login", "me", "broken"]


def test_junit_xml(suite: Path) -> None:
    result = collection.run([suite], suite, "ci", transport=make_transport())
    xml = collection.junit(result)
    root = ET.fromstring(xml)
    assert (
        root.attrib["tests"] == "4"
        and root.attrib["failures"] == "1"
        and root.attrib["errors"] == "1"
    )
    suites = {s.attrib["name"]: s for s in root.findall("testsuite")}
    assert set(suites) == {"a-auth.http", "b-broken.http"}
    broken = suites["b-broken.http"].find("testcase[@name='broken']/failure")
    assert broken is not None and "status == 200 (got 500)" in (broken.text or "")
    # The captured token is never written to the report.
    assert "fake-run-token" not in xml


def test_cli_test_command(suite: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from librepost import runner

    original = runner.send
    monkeypatch.setattr(
        "librepost.collection.runner.send",
        lambda p, **kw: original(p, **{**kw, "transport": make_transport()}),
    )
    report = suite / "report.xml"
    result = CliRunner().invoke(app, ["test", str(suite), "-e", "ci", "--junit", str(report)])
    assert result.exit_code == 1, result.output
    assert "2 passed, 2 failed" in result.output
    assert "✗ status == 200" in result.output
    assert report.exists() and "fake-run-token" not in result.output

    passing = CliRunner().invoke(app, ["test", str(suite / "a-auth.http"), "-e", "ci"])
    assert passing.exit_code == 0, passing.output


def test_convert_multiline_property_chain() -> None:
    # From Newman's examples/sample-collection.json.
    result = convert(
        [
            "pm.test('expect response json contain args', function () {",
            "    pm.expect(pm.response.json().args).to.have.property('source')",
            "      .and.equal('newman-sample-github-collection')",
            "})",
        ]
    )
    assert result.checks == [
        '@expect $.args["source"] exists',
        '@expect $.args["source"] == "newman-sample-github-collection"',
    ]
    assert result.unconverted == []
