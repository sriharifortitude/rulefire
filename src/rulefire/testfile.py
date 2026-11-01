"""Test files: a rule, the events it must fire on, and the events it must not fire on."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from rulefire import rule as rules
from rulefire.condition import referenced
from rulefire.values import RuleError


@dataclass
class Case:
    label: str
    event: dict[str, Any]
    want: bool


@dataclass
class Result:
    case: Case
    fired: bool
    why: list[str]

    @property
    def ok(self) -> bool:
        return self.fired == self.case.want


@dataclass
class TestFile:
    path: Path
    rule: rules.Rule | None
    cases: list[Case]
    error: str = ""


def discover(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out.extend(sorted(q for q in p.rglob("*") if q.name.endswith((".tests.yml", ".tests.yaml"))))
        else:
            out.append(p)
    return out


def load(path: Path) -> TestFile:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as err:
        return TestFile(path, None, [], f"cannot read the test file: {err}")
    if not isinstance(doc, dict) or "rule" not in doc:
        return TestFile(path, None, [], "a test file needs a `rule:` path")
    try:
        rule = rules.load(path.parent / str(doc["rule"]))
    except OSError as err:
        return TestFile(path, None, [], f"cannot read the rule: {err}")
    except RuleError as err:
        return TestFile(path, None, [], f"cannot use the rule {doc['rule']}: {err}")
    cases: list[Case] = []
    try:
        for key, want in (("match", True), ("no_match", False)):
            for i, e in enumerate(doc.get(key) or []):
                if not isinstance(e, dict):
                    raise ValueError(f"{key}[{i}] is not a mapping")
                cases.append(Case(f"{key}[{i}]", e, want))
            if f"{key}_file" in doc:
                events_path = path.parent / str(doc[f"{key}_file"])
                for n, e in read_jsonl_lines(events_path):
                    cases.append(Case(f"{doc[f'{key}_file']}:{n}", e, want))
    except (OSError, ValueError) as err:
        return TestFile(path, rule, [], str(err))
    if not cases:
        return TestFile(path, rule, [], "the test file has no match or no_match events")
    return TestFile(path, rule, cases)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [e for _, e in read_jsonl_lines(path)]


def read_jsonl_lines(path: Path) -> list[tuple[int, dict[str, Any]]]:
    """The events in a JSON lines file, each with its line number; blank lines are skipped."""
    out = []
    with path.open(encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError as err:
                raise ValueError(f"{path}:{n}: not JSON: {err.msg}") from err
            if not isinstance(e, dict):
                raise ValueError(f"{path}:{n}: not a JSON object")
            out.append((n, e))
    return out


def run(tf: TestFile) -> list[Result]:
    assert tf.rule is not None
    return [Result(c, tf.rule.matches(c.event), explain(tf.rule, c.event)) for c in tf.cases]


def explain(rule: rules.Rule, event: dict[str, Any]) -> list[str]:
    """One line per selection the condition uses: whether it matched, and if not, what failed."""
    lines = []
    for name in sorted(referenced(rule.condition)):
        sel = rule.selections[name]
        if sel.matches(event):
            lines.append(f"{name}: matched")
            continue
        failed = sel.explain(event)
        if len(failed) == 1:
            lines.append(f"{name}: no match ({failed[0]} did not match)")
        else:
            lines.append(f"{name}: none of its {len(failed)} alternatives matched")
    return lines
