import json
from typing import Any

import pytest

from librepost import checks
from librepost.checks import CheckError
from librepost.httpfile import dumps, parse
from librepost.runner import Result


def result(
    body: Any = None, status: int = 200, headers: list[tuple[str, str]] | None = None
) -> Result:
    raw = (
        body if isinstance(body, bytes) else json.dumps(body).encode() if body is not None else b""
    )
    return Result(
        status=status,
        reason="OK",
        http_version="HTTP/1.1",
        url="https://a.invalid",
        headers=headers or [("Content-Type", "application/json")],
        body=raw,
        elapsed_ms=123.4,
    )


BODY = {
    "access_token": "fake-access-token",
    "user": {"id": 42, "name": "Ada", "tags": ["admin", "beta"], "active": True},
    "items": [{"id": 1}, {"id": 2}, {"id": 3}],
    "odd-key": "x",
    "empty": None,
}


@pytest.mark.parametrize(
    ("line", "passed"),
    [
        ("@expect status == 200", True),
        ("@expect status != 200", False),
        ("@expect status < 300", True),
        ("@expect duration < 1000", True),
        ("@expect duration >= 1000", False),
        ("@expect $.user.id == 42", True),
        ('@expect $.user.id == "42"', True),
        ("@expect $.user.name == Ada", True),
        ('@expect $.user.name == "Ada"', True),
        ("@expect $.user.active == true", True),
        ("@expect $.user.tags contains admin", True),
        ("@expect $.user.tags !contains root", True),
        ("@expect $.items.length == 3", True),
        ("@expect $.items[-1].id == 3", True),
        ("@expect $.items[5] exists", False),
        ('@expect $["odd-key"] == x', True),
        ("@expect $.empty exists", True),
        ("@expect $.empty == null", True),
        ("@expect $.nope !exists", True),
        ("@expect $.nope == 1", False),
        ("@expect $.user.name matches ^A.a$", True),
        ("@expect header content-type contains json", True),
        ("@expect header X-Missing exists", False),
        ("@expect body contains fake-access", True),
        ('@expect regex "\\"id\\": (\\\\d+)" == 42', True),
        ("expect status == 200", True),  # '@' is optional
        ("# @expect status == 200", True),  # so is a comment marker
    ],
)
def test_expectations(line: str, passed: bool) -> None:
    outcome = checks.run(checks.parse([line]), result(BODY))
    assert outcome.results[0].passed is passed, outcome.results[0]


def test_captures_and_masking_defaults() -> None:
    plan = checks.parse(
        [
            "@capture token = $.access_token",
            "@capture userId = $.user.id",
            "@capture-secret session = header Set-Cookie",
            "@capture name = $.user.name",
            "@capture gone = $.nope",
        ]
    )
    outcome = checks.run(
        plan,
        result(
            BODY, headers=[("Set-Cookie", "sid=fake-sid"), ("Content-Type", "application/json")]
        ),
    )
    assert outcome.values == {
        "token": "fake-access-token",
        "userId": "42",
        "session": "sid=fake-sid",
        "name": "Ada",
    }
    # "token" is masked because of its name; "session" because of @capture-secret.
    assert outcome.secret == {"token", "session"}
    assert outcome.missing == ["gone"]


def test_non_json_body() -> None:
    outcome = checks.run(
        checks.parse(["@expect $.a exists", '@capture csrf = regex "name=csrf value=(\\w+)"']),
        result(b"<input name=csrf value=abc123>", headers=[("Content-Type", "text/html")]),
    )
    assert not outcome.results[0].passed
    assert outcome.values == {"csrf": "abc123"}


@pytest.mark.parametrize(
    "line",
    [
        "@expect status",
        "@expect status ==",
        "@expect status exists 1",
        "@expect nonsense == 1",
        "@expect $.a..b == 1",
        "@expect $.a matches (",
        "@capture = $.a",
        "@capture x = whatever",
        "@capture x $.a",
        "@check status == 200",
        "@expect header == x",
    ],
)
def test_parse_errors(line: str) -> None:
    with pytest.raises(CheckError):
        checks.parse([line])


def test_checks_round_trip_in_http_files() -> None:
    text = (
        "# A login request\n"
        "# @capture-secret token = $.access_token\n"
        "# @expect status == 200\n"
        "# @name login\n"
        "POST https://a.invalid/login\n"
    )
    request = parse(text).requests[0]
    assert request.comments == ["# A login request"]
    assert request.checks == ["@capture-secret token = $.access_token", "@expect status == 200"]
    assert dumps(parse(text)) == text


def test_quoted_patterns_need_no_json_escaping() -> None:
    outcome = checks.run(
        checks.parse(['@expect body matches "id=\\d+"', "@expect body matches 'id=\\d+'"]),
        result(b"id=42", headers=[]),
    )
    assert [r.passed for r in outcome.results] == [True, True]
