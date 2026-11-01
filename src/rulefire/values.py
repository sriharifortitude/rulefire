"""Sigma detection values: wildcard strings, the value modifiers, and matching against an event."""

from __future__ import annotations

import base64
import ipaddress
import itertools
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

STAR = object()
QMARK = object()

Token = str | object
Matcher = Callable[[dict[str, Any]], bool]


class RuleError(Exception):
    """A rule uses something this evaluator does not support, or is malformed."""


def parse_wildcards(s: str) -> list[Token]:
    """Splits a Sigma string into literal text and wildcards.

    A backslash escapes the character after it only when that is *, ? or another backslash;
    anywhere else, including at the end of the string, it is a literal backslash.
    """
    out: list[Token] = []
    buf: list[str] = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s) and s[i + 1] in "*?\\":
            buf.append(s[i + 1])
            i += 2
            continue
        if c in "*?":
            if buf:
                out.append("".join(buf))
                buf = []
            out.append(STAR if c == "*" else QMARK)
        else:
            buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return out


def literal(tokens: list[Token]) -> str:
    if any(not isinstance(t, str) for t in tokens):
        raise RuleError("this modifier cannot be applied to a value with wildcards")
    return "".join(t for t in tokens if isinstance(t, str))


def to_regex(tokens: list[Token], cased: bool) -> re.Pattern[str]:
    parts = []
    for t in tokens:
        if t is STAR:
            parts.append(".*")
        elif t is QMARK:
            parts.append(".")
        else:
            parts.append(re.escape(str(t)))
    return re.compile("".join(parts), re.DOTALL if cased else re.DOTALL | re.IGNORECASE)


def lookup(event: dict[str, Any], field: str) -> tuple[bool, Any]:
    """Returns (present, value). A dotted name falls back to walking nested objects."""
    if field in event:
        return True, event[field]
    if "." in field:
        node: Any = event
        for part in field.split("."):
            if not isinstance(node, dict) or part not in node:
                return False, None
            node = node[part]
        return True, node
    return False, None


def as_text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def each(v: Any) -> Iterator[Any]:
    """A field holding a list matches when any element does."""
    if isinstance(v, list):
        yield from v
    else:
        yield v


# Modifiers that change what the value means, rather than transform it.
TYPE_MODIFIERS = {"re", "cidr", "exists", "gt", "gte", "lt", "lte", "fieldref"}
KNOWN = TYPE_MODIFIERS | {
    "contains",
    "startswith",
    "endswith",
    "all",
    "base64",
    "base64offset",
    "utf16le",
    "utf16be",
    "utf16",
    "wide",
    "windash",
    "cased",
    "i",
    "m",
    "s",
}

WINDASH = ["-", "/", "\u2013", "\u2014", "\u2015"]
_WINDASH_AT = re.compile(r"(?<!\w)[-/](?=\w)")


@dataclass
class Value:
    """One value on its way through the modifiers: wildcard tokens, or bytes once encoded."""

    tokens: list[Token] | None = None
    data: bytes | None = None

    def text_tokens(self) -> list[Token]:
        if self.tokens is not None:
            return self.tokens
        assert self.data is not None
        return [self.data.decode("latin-1")]


def _encode(values: list[Value], codec: str) -> list[Value]:
    out = []
    for v in values:
        if v.data is not None:
            raise RuleError("an encoding modifier cannot follow another encoding modifier")
        s = literal(v.text_tokens())
        data = s.encode("utf-16-le" if codec == "utf16le" else "utf-16-be" if codec == "utf16be" else "utf-16")
        out.append(Value(data=data))
    return out


def _bytes(v: Value) -> bytes:
    return v.data if v.data is not None else literal(v.text_tokens()).encode()


def _base64offset(data: bytes) -> list[str]:
    # The three ways the value can sit in a base64 stream, keeping only the characters that do
    # not depend on the bytes around it.
    start = (0, 2, 3)
    end = (None, -3, -2)
    out = []
    for i in range(3):
        enc = base64.b64encode(b"\0" * i + data).decode()
        out.append(enc[start[i] : end[(len(data) + i) % 3]])
    return out


def _windash(tokens: list[Token]) -> list[list[Token]]:
    """Every combination of dash characters at each place a - or / starts an option."""
    places: list[tuple[int, int]] = []  # (token index, character index)
    for ti, t in enumerate(tokens):
        if isinstance(t, str):
            for m in _WINDASH_AT.finditer(t):
                places.append((ti, m.start()))
    if not places:
        return [tokens]
    out = []
    for combo in itertools.product(WINDASH, repeat=len(places)):
        new: list[Token] = list(tokens)
        for (ti, ci), dash in sorted(zip(places, combo, strict=True), reverse=True):
            s = new[ti]
            assert isinstance(s, str)
            new[ti] = s[:ci] + dash + s[ci + 1 :]
        out.append(new)
    return out


def compile_field(field: str, modifiers: list[str], raw: Any) -> Matcher:
    """Builds the matcher for one `field|modifier...: value(s)` entry."""
    for m in modifiers:
        if m == "expand":
            raise RuleError("the expand modifier needs placeholder values, which rulefire does not have")
        if m not in KNOWN:
            raise RuleError(f"unknown modifier {m!r}")
    raws = raw if isinstance(raw, list) else [raw]
    match_all = "all" in modifiers
    if not raws:
        raise RuleError(f"{field or 'keyword'} has an empty list of values")
    kind = next((m for m in modifiers if m in TYPE_MODIFIERS), None)
    if kind is not None:
        matchers = [_typed(field, kind, modifiers, r) for r in raws]
    else:
        matchers = [_plain(field, modifiers, r) for r in raws]
    if match_all:
        return lambda e: all(m(e) for m in matchers)
    return lambda e: any(m(e) for m in matchers)


def _typed(field: str, kind: str, modifiers: list[str], raw: Any) -> Matcher:
    present = _getter(field)
    if kind == "exists":
        if not isinstance(raw, bool):
            raise RuleError("exists takes true or false")
        return lambda e: (present(e)[0] and present(e)[1] is not None) == raw
    if kind == "re":
        flags = 0
        if "i" in modifiers:
            flags |= re.IGNORECASE
        if "m" in modifiers:
            flags |= re.MULTILINE
        if "s" in modifiers:
            flags |= re.DOTALL
        try:
            rx = re.compile(str(raw), flags)
        except re.error as err:
            raise RuleError(f"invalid regular expression {raw!r}: {err}") from err
        return _any_value(present, lambda v: v is not None and rx.search(as_text(v)) is not None)
    if kind == "cidr":
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
        except ValueError as err:
            raise RuleError(f"invalid network {raw!r}") from err

        def in_net(v: Any) -> bool:
            try:
                return v is not None and ipaddress.ip_address(as_text(v)) in net
            except ValueError:
                return False

        return _any_value(present, in_net)
    if kind == "fieldref":
        other = _getter(str(raw))

        def same(e: dict[str, Any]) -> bool:
            (p1, v1), (p2, v2) = present(e), other(e)
            if not (p1 and p2) or v1 is None or v2 is None:
                return False
            a, b = as_text(v1), as_text(v2)
            return a == b if "cased" in modifiers else a.casefold() == b.casefold()

        return same
    # gt, gte, lt, lte
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise RuleError(f"{kind} needs a number, not {raw!r}")
    ops: dict[str, Callable[[float, float], bool]] = {
        "gt": lambda a, b: a > b,
        "gte": lambda a, b: a >= b,
        "lt": lambda a, b: a < b,
        "lte": lambda a, b: a <= b,
    }
    op = ops[kind]

    def compare(v: Any) -> bool:
        n = _number(v)
        return n is not None and op(n, float(raw))

    return _any_value(present, compare)


def _number(v: Any) -> float | None:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, int | float):
        return float(v)
    try:
        return float(str(v))
    except ValueError:
        return None


def _plain(field: str, modifiers: list[str], raw: Any) -> Matcher:
    present = _getter(field)
    if raw is None:
        if modifiers:
            raise RuleError("null cannot take modifiers")
        return lambda e: present(e)[1] is None
    if isinstance(raw, bool):
        return _any_value(present, lambda v: isinstance(v, bool) and v == raw)
    if isinstance(raw, int | float) and not modifiers:
        # A number matches the same number, or text that spells it.
        return _any_value(present, lambda v: v is not None and _num_equal(v, raw))
    values = [Value(tokens=parse_wildcards(as_text(raw)))]
    if field == "" and not modifiers:
        # A keyword is a search for text anywhere in the event.
        modifiers = ["contains"]
    for m in modifiers:
        if m in ("utf16le", "utf16be", "utf16", "wide"):
            values = _encode(values, "utf16le" if m == "wide" else m)
        elif m == "base64":
            values = [Value(tokens=[base64.b64encode(_bytes(v)).decode()]) for v in values]
        elif m == "base64offset":
            values = [Value(tokens=[s]) for v in values for s in _base64offset(_bytes(v))]
        elif m == "windash":
            values = [Value(tokens=t) for v in values for t in _windash(v.text_tokens())]
        elif m == "contains":
            values = [Value(tokens=_wrap(v.text_tokens(), True, True)) for v in values]
        elif m == "startswith":
            values = [Value(tokens=_wrap(v.text_tokens(), False, True)) for v in values]
        elif m == "endswith":
            values = [Value(tokens=_wrap(v.text_tokens(), True, False)) for v in values]
    cased = "cased" in modifiers
    patterns = [to_regex(v.text_tokens(), cased) for v in values]

    def matches(v: Any) -> bool:
        if v is None:
            return False
        s = as_text(v)
        return any(p.fullmatch(s) for p in patterns)

    if field == "":
        return lambda e: any(matches(v) for v in _all_values(e))
    return _any_value(present, matches)


def _num_equal(v: Any, raw: int | float) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int | float):
        return v == raw
    return as_text(v) == as_text(raw)


def _wrap(tokens: list[Token], before: bool, after: bool) -> list[Token]:
    return ([STAR] if before else []) + list(tokens) + ([STAR] if after else [])


def _getter(field: str) -> Callable[[dict[str, Any]], tuple[bool, Any]]:
    return lambda e: lookup(e, field)


def _any_value(get: Callable[[dict[str, Any]], tuple[bool, Any]], pred: Callable[[Any], bool]) -> Matcher:
    def m(e: dict[str, Any]) -> bool:
        present, v = get(e)
        return present and any(pred(x) for x in each(v))

    return m


def _all_values(e: Any) -> Iterator[Any]:
    if isinstance(e, dict):
        for v in e.values():
            yield from _all_values(v)
    elif isinstance(e, list):
        for v in e:
            yield from _all_values(v)
    else:
        yield e
