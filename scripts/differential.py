"""Compares rulefire with pySigma's SQLite backend over a directory of Sigma rules.

For each rule it builds events from the rule itself: one that should satisfy each selection,
then near misses of those (a field dropped, the case swapped, one character changed) and
pairs of them merged, so filters fire too. rulefire evaluates each event; pySigma turns the
rule into SQL, which runs over the same events in SQLite. Every event on which the two
disagree is printed.

    python scripts/differential.py RULES_DIR... [--limit N] [--show N]

Needs pySigma and pySigma-backend-sqlite (pip install -e ".[differential]").
"""

from __future__ import annotations

import argparse
import base64
import collections
import ipaddress
import re
import re._parser as sre_parse  # private, but the only parse tree of a pattern the stdlib has
import sqlite3
import sys
from pathlib import Path
from typing import Any

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from rulefire.rule import from_dict
from rulefire.values import QMARK, STAR, RuleError, parse_wildcards

MAX_EVENTS = 80


def regex_sample(pattern: str) -> str | None:
    """A string the regular expression matches, for plain expressions; None for lookarounds,
    backreferences and anything else this does not handle."""
    try:
        tree = sre_parse.parse(pattern)
    except re.error:
        return None

    def gen(items: Any) -> str | None:
        out = []
        for op, arg in items:
            name = str(op)
            if name == "LITERAL":
                out.append(chr(arg))
            elif name == "ANY":
                out.append("a")
            elif name == "IN":
                c = in_class(arg)
                if c is None:
                    return None
                out.append(c)
            elif name in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                lo, _hi, sub = arg
                s = gen(sub)
                if s is None:
                    return None
                out.append(s * max(lo, 1))
            elif name == "SUBPATTERN":
                s = gen(arg[-1])
                if s is None:
                    return None
                out.append(s)
            elif name == "BRANCH":
                s = gen(arg[1][0])
                if s is None:
                    return None
                out.append(s)
            elif name == "AT":
                continue
            else:
                return None
        return "".join(out)

    def in_class(items: Any) -> str | None:
        if not items or str(items[0][0]) == "NEGATE":
            return None
        op, arg = items[0]
        name = str(op)
        if name == "LITERAL":
            return chr(arg)
        if name == "RANGE":
            return chr(arg[0])
        if name == "CATEGORY":
            return {"CATEGORY_DIGIT": "7", "CATEGORY_SPACE": " ", "CATEGORY_WORD": "w"}.get(str(arg).upper())
        return None

    return gen(tree)


def witness_text(raw: Any, mods: list[str], dash: str = "-") -> str | None:
    """A string the value (with these modifiers) should match, or None when unsure how."""
    if "re" in mods:
        sample = regex_sample(str(raw))
        if sample is None or not re.search(str(raw), sample, re.I if "i" in mods else 0):
            return None
        return sample
    if "fieldref" in mods:
        return None
    encodings = [m for m in mods if m in ("utf16le", "utf16be", "utf16", "wide")]
    if encodings:
        if "base64offset" not in mods or "*" in str(raw) or "?" in str(raw):
            return None
        codec = {"utf16le": "utf-16-le", "wide": "utf-16-le", "utf16be": "utf-16-be", "utf16": "utf-16"}[encodings[0]]
        return base64.b64encode(b"xy" + str(raw).encode(codec) + b"zz").decode()
    s = "".join("Xy" if t is STAR else "q" if t is QMARK else str(t) for t in parse_wildcards(str(raw)))
    if "windash" in mods:
        s = re.sub(r"(?<!\w)[-/](?=\w)", dash, s)
    if "base64" in mods:
        if any(t is not STAR and not isinstance(t, str) for t in parse_wildcards(str(raw))) or "*" in str(raw):
            return None
        return base64.b64encode(str(raw).encode()).decode()
    if "base64offset" in mods:
        return base64.b64encode(b"xy" + str(raw).encode() + b"zz").decode()
    if "contains" in mods:
        return "pre " + s + " post"
    if "startswith" in mods:
        return s + " post"
    if "endswith" in mods:
        return "pre " + s
    return s


def witness(body: dict[str, Any], dash: str = "-") -> dict[str, Any] | None:
    """An event meant to satisfy every entry of one selection map."""
    event: dict[str, Any] = {}
    for key, value in body.items():
        field, *mods = str(key).split("|")
        if field == "":
            return None
        values = value if isinstance(value, list) else [value]
        if not values:
            return None
        if "exists" in mods:
            if values[0] is True:
                event[field] = "present"
            continue
        if values[0] is None:
            continue
        if "fieldref" in mods:
            event[field] = event[str(values[0])] = "same value"
            continue
        if "cidr" in mods:
            net = ipaddress.ip_network(str(values[0]), strict=False)
            event[field] = str(net.network_address + 1) if net.num_addresses > 1 else str(net.network_address)
            continue
        if any(m in mods for m in ("gt", "gte", "lt", "lte")):
            n = values[0]
            event[field] = n + 1 if "gt" in mods else n - 1 if "lt" in mods else n
            continue
        if isinstance(values[0], bool | int | float) and not mods:
            event[field] = values[0]
            continue
        if "all" in mods:
            parts = [witness_text(v, [m for m in mods if m != "all"]) for v in values]
            if any(p is None for p in parts):
                return None
            event[field] = " ".join(p for p in parts if p is not None)
            continue
        text = witness_text(values[0], mods, dash)
        if text is None:
            return None
        event[field] = text
    return event


def witnesses(body: dict[str, Any]) -> list[dict[str, Any]]:
    """Witness events; for a windash entry, one per dash character."""
    dashes = ["-", "/", "\u2013"] if any("windash" in str(k) for k in body) else ["-"]
    return [w for d in dashes if (w := witness(body, d)) is not None]


def variants(event: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for k, v in event.items():
        out.append({x: y for x, y in event.items() if x != k})
        if isinstance(v, str) and v:
            out.append({**event, k: v.swapcase()})
            i = next((j for j, c in enumerate(v) if c.isalnum()), 0)
            out.append({**event, k: v[:i] + ("Z" if v[i] != "Z" else "Y") + v[i + 1 :]})
        elif isinstance(v, int) and not isinstance(v, bool):
            out.append({**event, k: v + 1})
            out.append({**event, k: str(v)})
    return out


def events_for(det: dict[str, Any]) -> list[dict[str, Any]]:
    bases = []
    for name, body in det.items():
        if name in ("condition", "timeframe"):
            continue
        maps = body if isinstance(body, list) else [body]
        for m in maps:
            if isinstance(m, dict):
                bases.extend(witnesses(m))
    out = list(bases)
    for b in bases:
        out.extend(variants(b))
    for i, a in enumerate(bases):
        for b in bases[i + 1 :]:
            out.append({**a, **b})
    seen, unique = set(), []
    for e in out:
        key = repr(sorted(e.items(), key=lambda kv: kv[0]))
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique[:MAX_EVENTS]


def fields_in(det: dict[str, Any]) -> set[str]:
    out = set()
    for name, body in det.items():
        if name in ("condition", "timeframe"):
            continue
        for m in body if isinstance(body, list) else [body]:
            if isinstance(m, dict):
                for key, value in m.items():
                    field, *mods = str(key).split("|")
                    if field:
                        out.add(field)
                    if "fieldref" in mods:
                        out.update(str(v) for v in (value if isinstance(value, list) else [value]))
    return out


def oracle(sql: str, events: list[dict[str, Any]], fields: set[str]) -> set[int]:
    db = sqlite3.connect(":memory:")
    db.create_function("REGEXP", 2, lambda p, s: s is not None and re.search(p, str(s)) is not None)
    cols = sorted(fields | {k for e in events for k in e})
    # The backend writes a value without wildcards as `=`, which SQLite compares case-sensitively,
    # while Sigma matches case-insensitively. NOCASE columns give `=` Sigma's meaning; LIKE
    # already ignores case.
    quoted = ", ".join(f'"{c}" COLLATE NOCASE' for c in cols)
    db.execute(f"CREATE TABLE logs (_rfid, {quoted})")
    for i, e in enumerate(events):
        db.execute(f"INSERT INTO logs VALUES ({', '.join('?' * (len(cols) + 1))})", [i, *(e.get(c) for c in cols)])
    names = [d[0] for d in db.execute(sql).description]
    idx = names.index("_rfid")
    return {row[idx] for row in db.execute(sql)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rules", nargs="+")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--show", type=int, default=20)
    args = ap.parse_args()
    backend = sqliteBackend()
    counts: collections.Counter[str] = collections.Counter()
    shown = 0
    paths = sorted(p for d in args.rules for p in Path(d).rglob("*.yml"))
    if args.limit:
        paths = paths[: args.limit]
    for path in paths:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        try:
            rule = from_dict(doc, str(path))
        except RuleError:
            counts["rulefire rejects the rule"] += 1
            continue
        try:
            queries = backend.convert(SigmaCollection.from_dicts([doc]))
        except Exception:  # any pySigma failure means there is no oracle
            counts["pySigma cannot convert the rule"] += 1
            continue
        if len(queries) != 1:
            counts["pySigma made several queries"] += 1
            continue
        events = events_for(doc["detection"])
        try:
            real = oracle(str(queries[0]), events, fields_in(doc["detection"]))
        except sqlite3.Error:
            counts["the SQL does not run"] += 1
            continue
        mine = {i for i, e in enumerate(events) if rule.matches(e)}
        counts["rules compared"] += 1
        counts["events compared"] += len(events)
        counts["matching events"] += len(real)
        if real:
            counts["rules with a matching event"] += 1
        text = path.read_text(encoding="utf-8")
        for m in ("re", "windash", "base64offset", "cidr", "fieldref", "all"):
            if re.search(rf"\|{m}[|:]", text):
                counts[f"rules using |{m}"] += 1
                if real:
                    counts[f"rules using |{m} with a matching event"] += 1
        unexplained = False
        for i in sorted(mine ^ real):
            known = known_difference(events[i], i in mine, str(queries[0]), fields_in(doc["detection"]))
            if known:
                counts["known difference: " + known] += 1
                continue
            unexplained = True
            counts["events that disagree"] += 1
            if shown < args.show:
                shown += 1
                print(f"{path}\n  event:     {events[i]}\n  rulefire:  {i in mine}\n  pySigma:   {i in real}")
                print(f"  sql:       {queries[0]}"[:600])
        if unexplained:
            counts["rules that disagree"] += 1
    for k, v in sorted(counts.items()):
        print(f"{k}: {v}")
    return 1 if counts["rules that disagree"] else 0


def known_difference(event: dict[str, Any], mine: bool, sql: str, fields: set[str]) -> str | None:
    """Names a difference README.md documents, after checking it is the cause, or returns None."""
    for k, v in event.items():
        if isinstance(v, str) and v.isdigit() and (0 in oracle(sql, [{**event, k: int(v)}], fields)) == mine:
            return "a number written as text matches the number"
    texts = [v for v in event.values() if isinstance(v, str)]
    if any(ord(c) > 127 for t in texts for c in t):
        folded = {k: v.lower() if isinstance(v, str) else v for k, v in event.items()}
        if (0 in oracle(sql, [folded], fields)) == mine:
            return "case is ignored for non-ASCII letters too"
    return None


if __name__ == "__main__":
    sys.exit(main())
