"""Captures and checks: take values from a response and test it, without running scripts.

Written above the request line in a `.http` file (other tools treat them as comments):

    # @capture token = $.access_token
    # @capture-secret refresh = $.refresh_token
    # @capture next = header Location
    # @expect status == 200
    # @expect $.items.length >= 1
    # @expect header Content-Type contains json
    # @expect duration < 500

Subjects:
    status              the status code
    duration            response time in milliseconds
    body                the body as text
    header <Name>       a response header (case-insensitive)
    $.a.b[0]["c-d"]     a value in a JSON body; `.length` on a list or string gives its size
    regex "<pattern>"   the first group (or whole match) of a regular expression on the body

Captures named like credentials (token, password, apiKey, ...) are masked on screen even
without `@capture-secret`.

Operators: == != < <= > >= contains !contains matches exists !exists.
Values are JSON (200, "text", true, null, [1, 2]) or a bare word, read as text.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from .leakcheck import SENSITIVE_NAME
from .runner import Result

OPERATORS = (
    "==",
    "!=",
    "<=",
    ">=",
    "<",
    ">",
    "!contains",
    "contains",
    "matches",
    "!exists",
    "exists",
)
_UNARY = ("exists", "!exists")
_CAPTURE = re.compile(r"^@(capture|capture-secret)\s+([A-Za-z_][\w.-]*)\s*=\s*(.+)$")
_EXPECT = re.compile(r"^@expect\s+(.+)$")
_PATH_TOKEN = re.compile(r"""\.([A-Za-z_$][\w$-]*)|\[\s*(-?\d+)\s*\]|\[\s*(['"])(.*?)\3\s*\]""")
_MISSING = object()


class CheckError(ValueError):
    """A capture or expect line can't be understood."""


@dataclass
class Capture:
    name: str
    subject: str
    secret: bool = False


@dataclass
class Expect:
    text: str
    subject: str
    op: str
    expected: Any = None


@dataclass
class Plan:
    captures: list[Capture] = field(default_factory=list)
    expects: list[Expect] = field(default_factory=list)


@dataclass
class CheckResult:
    text: str
    passed: bool
    actual: str = ""


@dataclass
class Outcome:
    # Captured name -> value, and which of them are secret.
    values: dict[str, str] = field(default_factory=dict)
    secret: set[str] = field(default_factory=set)
    missing: list[str] = field(default_factory=list)  # captures that found nothing
    results: list[CheckResult] = field(default_factory=list)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)


def normalise(line: str) -> str:
    """Accept lines typed with or without the leading '@' or comment marker."""
    line = line.strip()
    line = re.sub(r"^(#|//)\s*", "", line)
    if re.match(r"^(capture-secret|capture|expect)\b", line):
        line = "@" + line
    return line


def parse(lines: list[str]) -> Plan:
    plan = Plan()
    for number, raw in enumerate(lines, start=1):
        line = normalise(raw)
        if not line:
            continue
        capture = _CAPTURE.match(line)
        if capture:
            kind, name, subject = capture.groups()
            _check_subject(subject.strip(), number)
            plan.captures.append(Capture(name, subject.strip(), kind == "capture-secret"))
            continue
        expect = _EXPECT.match(line)
        if not expect:
            raise CheckError(
                f"Check line {number}: start with @capture, @capture-secret or @expect: {raw.strip()!r}"
            )
        plan.expects.append(_parse_expect(expect.group(1).strip(), number))
    return plan


def _parse_expect(text: str, number: int) -> Expect:
    # The subject can contain spaces (header X-Y, regex "a b"), so find the operator
    # by scanning for the first token that is one.
    tokens = _split(text)
    for i, token in enumerate(tokens):
        if token in OPERATORS and i > 0:
            subject = " ".join(tokens[:i])
            op = token
            rest = " ".join(tokens[i + 1 :])
            _check_subject(subject, number)
            if op in _UNARY:
                if len(tokens) > i + 1:
                    raise CheckError(f"Check line {number}: {op} takes no value.")
                return Expect(f"@expect {text}", subject, op)
            if not rest:
                raise CheckError(f"Check line {number}: {op} needs a value.")
            expected = _literal(rest)
            if op == "matches":
                try:
                    re.compile(str(expected))
                except re.error as exc:
                    raise CheckError(f"Check line {number}: invalid pattern: {exc}") from None
            return Expect(f"@expect {text}", subject, op, expected)
    raise CheckError(f"Check line {number}: no operator found; use one of {', '.join(OPERATORS)}.")


def _split(text: str) -> list[str]:
    """Split on spaces, keeping quoted strings together."""
    return re.findall(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|\S+', text)


def _literal(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # "value=(\w+)" isn't valid JSON (\w), but the quotes still mean "this text".
        if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
            return text[1:-1]
        return text


def _check_subject(subject: str, number: int) -> None:
    if subject in ("status", "duration", "body"):
        return
    if subject.startswith("header "):
        if not subject[7:].strip():
            raise CheckError(f"Check line {number}: header needs a name.")
        return
    if subject.startswith("regex "):
        pattern = _literal(subject[6:].strip())
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise CheckError(f"Check line {number}: invalid pattern: {exc}") from None
        return
    if subject.startswith("$"):
        rest = subject[1:]
        consumed = "".join(m.group(0) for m in _PATH_TOKEN.finditer(rest))
        if consumed != rest:
            raise CheckError(f"Check line {number}: can't read the JSON path {subject!r}.")
        return
    raise CheckError(
        f"Check line {number}: unknown subject {subject!r}; use status, duration, body, "
        'header <Name>, $.json.path or regex "pattern".'
    )


def value(subject: str, result: Result) -> Any:
    """The subject's value in this response, or _MISSING."""
    if subject == "status":
        return result.status
    if subject == "duration":
        return round(result.elapsed_ms)
    if subject == "body":
        return result.body.decode("utf-8", errors="replace")
    if subject.startswith("header "):
        name = subject[7:].strip().lower()
        for key, val in result.headers:
            if key.lower() == name:
                return val
        return _MISSING
    if subject.startswith("regex "):
        pattern = str(_literal(subject[6:].strip()))
        match = re.search(pattern, result.body.decode("utf-8", errors="replace"))
        if not match:
            return _MISSING
        return match.group(1) if match.groups() else match.group(0)
    try:
        data: Any = json.loads(result.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _MISSING
    for match in _PATH_TOKEN.finditer(subject[1:]):
        key, index, _, quoted = match.groups()
        if key is not None:
            if isinstance(data, dict) and key in data:
                data = data[key]
            elif key == "length" and isinstance(data, list | str):
                data = len(data)
            else:
                return _MISSING
        elif index is not None:
            i = int(index)
            if not isinstance(data, list) or not -len(data) <= i < len(data):
                return _MISSING
            data = data[i]
        else:
            if not isinstance(data, dict) or quoted not in data:
                return _MISSING
            data = data[quoted]
    return data


def _text(val: Any) -> str:
    if val is _MISSING:
        return "(missing)"
    if isinstance(val, str):
        return val
    return json.dumps(val, ensure_ascii=False)


def _number(val: Any) -> float | None:
    if isinstance(val, bool):
        return None
    if isinstance(val, int | float):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val)
        except ValueError:
            return None
    return None


def _compare(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        return actual is not _MISSING
    if op == "!exists":
        return actual is _MISSING
    if actual is _MISSING:
        return False
    if op in ("==", "!="):
        a, e = _number(actual), _number(expected)
        if a is not None and e is not None and not isinstance(actual, str | bool):
            equal = a == e
        else:
            equal = actual == expected or (isinstance(actual, str) and actual == _text(expected))
        return equal if op == "==" else not equal
    if op in ("<", "<=", ">", ">="):
        a, e = _number(actual), _number(expected)
        if a is None or e is None:
            return False
        return {"<": a < e, "<=": a <= e, ">": a > e, ">=": a >= e}[op]
    if op in ("contains", "!contains"):
        if isinstance(actual, str):
            found = _text(expected) in actual
        elif isinstance(actual, list):
            found = expected in actual
        elif isinstance(actual, dict):
            found = str(expected) in actual
        else:
            found = False
        return found if op == "contains" else not found
    if op == "matches":
        return re.search(str(expected), _text(actual)) is not None
    raise CheckError(f"Unknown operator {op}")


def run(plan: Plan, result: Result) -> Outcome:
    outcome = Outcome()
    for capture in plan.captures:
        val = value(capture.subject, result)
        if val is _MISSING:
            outcome.missing.append(capture.name)
            continue
        outcome.values[capture.name] = _text(val)
        # Credential-like names are masked even without @capture-secret.
        if capture.secret or SENSITIVE_NAME.search(capture.name):
            outcome.secret.add(capture.name)
    for expect in plan.expects:
        actual = value(expect.subject, result)
        passed = _compare(actual, expect.op, expect.expected)
        outcome.results.append(CheckResult(expect.text, passed, _text(actual)))
    return outcome
