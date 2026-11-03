import pytest

from librepost.httpfile import (
    HttpFile,
    HttpFileError,
    Request,
    dumps,
    parse,
    parse_headers,
    validate,
)

SAMPLE = """\
@baseUrl = https://example.invalid

# Logs in
# @name login
POST {{baseUrl}}/login HTTP/1.1
Content-Type: application/json
// a header comment
Accept: */*

{"user": "alice"}

###

GET {{baseUrl}}/search
    ?q=books
    &page=2

### list users
https://example.invalid/users

> {% client.global.set("x", 1) %}
"""


def test_parse_sample() -> None:
    f = parse(SAMPLE)
    assert f.variables == {"baseUrl": "https://example.invalid"}
    login, search, users = f.requests

    assert login.name == "login"
    assert login.method == "POST"
    assert login.url == "{{baseUrl}}/login"
    assert login.headers == [("Content-Type", "application/json"), ("Accept", "*/*")]
    assert login.body == '{"user": "alice"}'
    assert login.comments == ["# Logs in"]

    assert search.method == "GET"
    assert search.url == "{{baseUrl}}/search?q=books&page=2"
    assert search.body == ""

    assert users.name == "list users"
    assert users.method == "GET"
    assert users.url == "https://example.invalid/users"
    assert users.body == ""
    assert users.trailer.startswith("> {%")


def test_round_trip_is_stable() -> None:
    once = dumps(parse(SAMPLE))
    assert dumps(parse(once)) == once
    again = parse(once)
    assert [r.name for r in again.requests] == ["login", "", "list users"]
    assert again.requests[2].trailer.startswith("> {%")


def test_dumps_format() -> None:
    text = dumps(
        HttpFile(
            [
                Request("POST", "https://example.invalid", [("A", "1")], "body", name="one"),
                Request("GET", "https://example.invalid/2"),
            ]
        )
    )
    assert text == (
        "# @name one\nPOST https://example.invalid\nA: 1\n\nbody\n\n###\n\n"
        "GET https://example.invalid/2\n"
    )


def test_crlf_and_empty() -> None:
    assert parse("").requests == []
    assert parse("# only a comment\n").requests == []
    f = parse("GET https://example.invalid\r\nX-A: 1\r\n")
    assert f.requests[0].headers == [("X-A", "1")]


def test_multiline_body_with_blank_lines() -> None:
    f = parse("POST https://example.invalid\n\nline1\n\nline3\n\n\n")
    assert f.requests[0].body == "line1\n\nline3"


@pytest.mark.parametrize(
    "request_",
    [
        Request("GET", ""),
        Request("GET", "https://a.invalid\nGET https://b.invalid"),
        Request("get", "https://a.invalid"),
        Request("GET", "https://a.invalid", [("Bad Name", "x")]),
        Request("GET", "https://a.invalid", [("X", "a\nb")]),
        Request("POST", "https://a.invalid", body="ok\n### not a separator"),
        Request("POST", "https://a.invalid", body="> {% handler %}"),
    ],
)
def test_validate_rejects_unsaveable(request_: Request) -> None:
    with pytest.raises(HttpFileError):
        validate(request_)


def test_parse_headers() -> None:
    assert parse_headers("A: 1\r\n\nB:two:three\n") == [("A", "1"), ("B", "two:three")]
    with pytest.raises(HttpFileError, match="line 2"):
        parse_headers("A: 1\nnot a header")
