"""Command line: test, scan, explain and check."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO
from xml.sax.saxutils import escape, quoteattr

from rulefire import __version__, testfile
from rulefire import rule as rules
from rulefire.values import RuleError


def main(argv: Sequence[str] | None = None, out: TextIO = sys.stdout, err: TextIO = sys.stderr) -> int:
    ap = argparse.ArgumentParser(prog="rulefire", description="Regression tests for Sigma detection rules.")
    ap.add_argument("--version", action="version", version=f"rulefire {__version__}")
    sub = ap.add_subparsers(dest="command", required=True)

    t = sub.add_parser("test", help="run *.tests.yml files: events each rule must and must not fire on")
    t.add_argument("paths", nargs="+")
    t.add_argument("--junit", metavar="FILE", help="also write the results as JUnit XML")
    t.add_argument("-q", "--quiet", action="store_true", help="print only failures and the summary")

    s = sub.add_parser("scan", help="count how often each rule fires over a file of events (JSON lines)")
    s.add_argument("rules", nargs="+")
    s.add_argument("--events", required=True, metavar="FILE")
    s.add_argument("--benign", action="store_true", help="the events are known benign: exit 1 if any rule fires")
    s.add_argument("--show", type=int, default=0, metavar="N", help="print up to N matching events per rule")

    e = sub.add_parser("explain", help="evaluate one rule against one event and say why it fired or not")
    e.add_argument("rule")
    e.add_argument("event", help="a JSON object, or @FILE")

    c = sub.add_parser("check", help="load rules and report what rulefire cannot evaluate")
    c.add_argument("rules", nargs="+")

    try:
        args = ap.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    try:
        if args.command == "test":
            return _test(args.paths, args.junit, args.quiet, out, err)
        if args.command == "scan":
            return _scan(args.rules, Path(args.events), args.benign, args.show, out=out, err=err)
        if args.command == "explain":
            return _explain(args.rule, args.event, out, err)
        return _check(args.rules, out)
    except (OSError, ValueError) as exc:
        print(f"rulefire: {exc}", file=err)
        return 2


def _test(paths: list[str], junit: str | None, quiet: bool, out: TextIO, err: TextIO) -> int:
    files = testfile.discover(paths)
    if not files:
        print("rulefire: no *.tests.yml files found", file=err)
        return 2
    passed = failed = broken = 0
    report: list[tuple[testfile.TestFile, list[testfile.Result]]] = []
    for path in files:
        tf = testfile.load(path)
        if tf.error or tf.rule is None:
            broken += 1
            print(f"{path.as_posix()}\n  ERROR {tf.error}", file=out)
            report.append((tf, []))
            continue
        results = testfile.run(tf)
        report.append((tf, results))
        bad = [r for r in results if not r.ok]
        if bad or not quiet:
            print(f"{path.as_posix()}  ({tf.rule.title or tf.rule.path})", file=out)
        for r in results:
            if r.ok:
                passed += 1
                if not quiet:
                    print(f"  ok    {r.case.label}", file=out)
                continue
            failed += 1
            print(f"  FAIL  {r.case.label}: {'fired' if r.fired else 'did not fire'}", file=out)
            print(f"        condition: {tf.rule.condition_text}", file=out)
            for line in r.why:
                print(f"        {line}", file=out)
    print(f"\n{passed} passed, {failed} failed, {broken} test file(s) could not run", file=out)
    if junit:
        Path(junit).write_text(_junit(report), encoding="utf-8")
    return 0 if failed == 0 and broken == 0 else 1


def _junit(report: list[tuple[testfile.TestFile, list[testfile.Result]]]) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', "<testsuites>"]
    for tf, results in report:
        name = quoteattr(str(tf.path))
        if tf.error:
            lines.append(f'  <testsuite name={name} tests="1" failures="0" errors="1">')
            lines.append(f'    <testcase name="load"><error message={quoteattr(tf.error)}/></testcase>')
        else:
            fails = sum(not r.ok for r in results)
            lines.append(f'  <testsuite name={name} tests="{len(results)}" failures="{fails}" errors="0">')
            for r in results:
                if r.ok:
                    lines.append(f"    <testcase name={quoteattr(r.case.label)}/>")
                else:
                    msg = "fired" if r.fired else "did not fire"
                    lines.append(f"    <testcase name={quoteattr(r.case.label)}>")
                    lines.append(f"      <failure message={quoteattr(msg)}>{escape(chr(10).join(r.why))}</failure>")
                    lines.append("    </testcase>")
        lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines) + "\n"


def _rule_paths(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out.extend(sorted(q for q in p.rglob("*.yml") if not q.name.endswith(".tests.yml")))
        else:
            out.append(p)
    return out


def _scan(paths: list[str], events_path: Path, benign: bool, show: int, *, out: TextIO, err: TextIO) -> int:
    loaded: list[rules.Rule] = []
    for p in _rule_paths(paths):
        try:
            loaded.append(rules.load(p))
        except RuleError as exc:
            print(f"rulefire: skipping {p.as_posix()}: {exc}", file=err)
    events = testfile.read_jsonl(events_path)
    hits = []
    for r in loaded:
        matched = [e for e in events if r.matches(e)]
        if matched:
            hits.append((r, matched))
    hits.sort(key=lambda h: (-len(h[1]), h[0].path))
    for r, matched in hits:
        print(f"{len(matched):>7}  {r.title}  ({r.path})", file=out)
        for e in matched[:show]:
            print(f"         {json.dumps(e, ensure_ascii=False)}", file=out)
    print(f"\n{len(loaded)} rule(s), {len(events)} event(s); {len(hits)} rule(s) fired", file=out)
    return 1 if benign and hits else 0


def _explain(rule_path: str, event_arg: str, out: TextIO, err: TextIO) -> int:
    try:
        r = rules.load(rule_path)
    except RuleError as exc:
        print(f"rulefire: {rule_path}: {exc}", file=err)
        return 2
    text = Path(event_arg[1:]).read_text(encoding="utf-8") if event_arg.startswith("@") else event_arg
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"the event is not JSON: {exc.msg}") from exc
    if not isinstance(event, dict):
        raise ValueError("the event must be a JSON object")
    fired = r.matches(event)
    print(f"{r.title or r.path}: {'fires' if fired else 'does not fire'}", file=out)
    print(f"condition: {r.condition_text}", file=out)
    for line in testfile.explain(r, event):
        print(f"  {line}", file=out)
    return 0


def _check(paths: list[str], out: TextIO) -> int:
    bad = 0
    files = _rule_paths(paths)
    for p in files:
        try:
            r = rules.load(p)
        except RuleError as exc:
            bad += 1
            print(f"{p.as_posix()}: {exc}", file=out)
            continue
        for name in r.unused:
            print(f"{p.as_posix()}: selection {name} is never used by the condition", file=out)
    print(f"\n{len(files)} rule(s), {bad} cannot be evaluated", file=out)
    return 1 if bad else 0
