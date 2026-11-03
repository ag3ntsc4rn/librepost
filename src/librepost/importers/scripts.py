"""Turn common Postman test-script statements into @capture / @expect lines.

Only well-known one-line patterns are recognised; nothing is executed. A script with
any statement that isn't recognised (or harmless boilerplate) counts as "not converted",
so the importer can say so.

    pm.environment.set("token", pm.response.json().access_token)  ->  @capture token = $.access_token
    pm.response.to.have.status(200)                                ->  @expect status == 200
    pm.expect(jsonData.user.id).to.eql(42)                         ->  @expect $.user.id == 42
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

_PATH = r"((?:\.[A-Za-z_$][\w$]*|\[\s*\d+\s*\]|\[\s*[\"'][^\"']*[\"']\s*\])*)"
_JSON = r"(?:pm\.response\.json\(\)|JSON\.parse\(\s*responseBody\s*\))"
_NAME = r"[\"']([\w.$-]+)[\"']"
_LITERAL = r"(-?\d+(?:\.\d+)?|true|false|null|\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')"

_ALIAS = re.compile(rf"^(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*{_JSON}$")
_SET = re.compile(
    r"^(?:pm\.(?:environment|collectionVariables|globals|variables)\.set"
    r"|postman\.set(?:Environment|Global)Variable)"
    rf"\(\s*{_NAME}\s*,\s*(.+?)\s*\)$"
)
_STATUS = [
    re.compile(r"^pm\.response\.to\.have\.status\(\s*(\d{3})\s*\)$"),
    re.compile(
        r"^pm\.expect\(\s*pm\.response\.code\s*\)\.to\.(?:eql|equal|be\.equal|deep\.equal)\(\s*(\d{3})\s*\)$"
    ),
    re.compile(r"^tests\[[^\]]+\]\s*=\s*responseCode\.code\s*===?\s*(\d{3})$"),
]
_OK = re.compile(r"^pm\.response\.to\.(?:be\.ok|be\.success)$")
_HEADER = re.compile(r"^pm\.response\.to\.have\.header\(\s*[\"']([^\"']+)[\"']\s*\)$")
_DURATION = re.compile(
    r"^pm\.expect\(\s*pm\.response\.responseTime\s*\)\.to\.be\.(below|lessThan|above)\(\s*(\d+)\s*\)$"
)
_BODY_INCLUDES = re.compile(
    r"^pm\.expect\(\s*pm\.response\.text\(\)\s*\)\.to\.include\(\s*" + _LITERAL + r"\s*\)$"
)
_EXPECT = re.compile(r"^pm\.expect\(\s*(.+?)\s*\)\.to\.((?:not\.)?[\w.]+?)(?:\(\s*(.*?)\s*\))?$")

_COMPARE = {
    "eql": "==",
    "equal": "==",
    "be.equal": "==",
    "deep.equal": "==",
    "eq": "==",
    "not.eql": "!=",
    "not.equal": "!=",
    "include": "contains",
    "contain": "contains",
    "not.include": "!contains",
    "be.above": ">",
    "be.greaterThan": ">",
    "be.below": "<",
    "be.lessThan": "<",
    "be.at.least": ">=",
    "be.at.most": "<=",
    "match": "matches",
}
_UNARY = {
    "exist": "exists",
    "not.exist": "!exists",
    "be.undefined": "!exists",
    "not.be.undefined": "exists",
    "be.ok": "exists",
    "be.true": "== true",
    "be.false": "== false",
    "be.null": "== null",
    "not.be.null": "!= null",
}
# Boilerplate around the statements that matter.
_TRIVIAL = re.compile(
    r"^(?:$|//.*|\}\)?;?$|\}\s*\);?$|pm\.test\(.*function\s*\(\s*\)\s*\{$|pm\.test\(.*=>\s*\{$"
    r"|console\.\w+\(.*\)$|tests\[[^\]]+\]\s*=\s*true$)"
)


@dataclass
class Conversion:
    checks: list[str] = field(default_factory=list)
    unconverted: list[str] = field(default_factory=list)


def _statements(lines: list[str]) -> list[str]:
    text = "\n".join(lines)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    # Chained calls continued on the next line: `pm.expect(x)\n  .to.equal(1)`.
    text = re.sub(r"\n\s*(?=\.)", "", text)
    parts = []
    for line in text.splitlines():
        line = line.strip()
        # pm.test("x", function () { pm.response.to.have.status(200); });
        inner = re.match(
            r"^pm\.test\(.*?(?:function\s*\(\s*\)|\(\s*\)\s*=>)\s*\{(.*)\}\s*\)\s*;?$", line
        )
        if inner:
            line = inner.group(1)
        for part in line.split(";"):
            part = part.strip()
            if part:
                parts.append(part)
    return parts


def _json_path(expr: str, aliases: set[str]) -> str | None:
    expr = expr.strip()
    match = re.fullmatch(_JSON + _PATH, expr)
    if match:
        return "$" + match.group(1).replace("'", '"')
    for alias in aliases:
        match = re.fullmatch(re.escape(alias) + _PATH, expr)
        if match:
            return "$" + match.group(1).replace("'", '"')
    return None


def _literal(text: str) -> str | None:
    text = text.strip()
    if not re.fullmatch(_LITERAL, text):
        return None
    if text.startswith("'"):
        return json.dumps(text[1:-1].replace("\\'", "'"))
    return text


def _subject(expr: str, aliases: set[str]) -> str | None:
    expr = expr.strip()
    if expr in ("pm.response.code", "responseCode.code"):
        return "status"
    if expr == "pm.response.responseTime":
        return "duration"
    if expr == "pm.response.text()":
        return "body"
    header = re.fullmatch(r"pm\.response\.headers\.get\(\s*[\"']([^\"']+)[\"']\s*\)", expr)
    if header:
        return f"header {header.group(1)}"
    length = re.fullmatch(r"(.+)\.length", expr)
    path = _json_path(expr, aliases)
    if path:
        return path
    if length:
        inner = _json_path(length.group(1), aliases)
        return f"{inner}.length" if inner else None
    return None


def convert(lines: list[str]) -> Conversion:
    result = Conversion()
    aliases: set[str] = set()
    for statement in _statements(lines):
        alias = _ALIAS.match(statement)
        if alias:
            aliases.add(alias.group(1))
            continue
        converted = _property_chain(statement, aliases) or [_one(statement, aliases)]
        if all(converted):
            result.checks.extend(line for line in converted if line)
        elif not _TRIVIAL.match(statement):
            result.unconverted.append(statement)
    return result


_PROPERTY_CHAIN = re.compile(
    r"^pm\.expect\(\s*(.+?)\s*\)\.to\.have\.property\(\s*"
    + _LITERAL
    + r"\s*\)\.and\.(?:to\.)?(?:be\.)?(eql|equal|deep\.equal)\(\s*"
    + _LITERAL
    + r"\s*\)$"
)


def _property_chain(statement: str, aliases: set[str]) -> list[str | None]:
    """`pm.expect(x).to.have.property('k').and.equal(v)` checks both the key and its value."""
    match = _PROPERTY_CHAIN.match(statement)
    if not match:
        return []
    expr, key, _, value = match.groups()
    subject = _subject(expr, aliases)
    key_literal, value_literal = _literal(key), _literal(value)
    if not subject or not key_literal or not key_literal.startswith('"') or value_literal is None:
        return [None]
    target = f"{subject}[{key_literal}]"
    return [f"@expect {target} exists", f"@expect {target} == {value_literal}"]


def _one(statement: str, aliases: set[str]) -> str | None:
    setter = _SET.match(statement)
    if setter:
        name, expr = setter.groups()
        subject = _subject(expr, aliases)
        return f"@capture {name} = {subject}" if subject else None
    for pattern in _STATUS:
        match = pattern.match(statement)
        if match:
            return f"@expect status == {match.group(1)}"
    if _OK.match(statement):
        return "@expect status < 300"
    header = _HEADER.match(statement)
    if header:
        return f"@expect header {header.group(1)} exists"
    duration = _DURATION.match(statement)
    if duration:
        op = ">" if duration.group(1) == "above" else "<"
        return f"@expect duration {op} {duration.group(2)}"
    body = _BODY_INCLUDES.match(statement)
    if body:
        literal = _literal(body.group(1))
        return f"@expect body contains {literal}" if literal else None
    expect = _EXPECT.match(statement)
    if not expect:
        return None
    expr, chain, arg = expect.groups()
    subject = _subject(expr, aliases)
    if subject is None:
        return None
    if chain in _UNARY and not arg:
        return f"@expect {subject} {_UNARY[chain]}"
    if chain in ("have.lengthOf", "have.length") and arg and re.fullmatch(r"\d+", arg):
        return f"@expect {subject}.length == {arg}"
    if chain in ("have.property", "have.key") and arg:
        key = _literal(arg)
        if key and key.startswith('"'):
            return f"@expect {subject}[{key}] exists"
        return None
    compare = _COMPARE.get(chain)
    if compare and arg is not None:
        literal = _literal(arg)
        if literal is None:
            return None
        if compare == "matches":
            return None  # JavaScript regex literals aren't converted
        return f"@expect {subject} {compare} {literal}"
    return None
