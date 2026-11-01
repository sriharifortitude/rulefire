"""Loading a Sigma rule and evaluating it against one event."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rulefire import condition
from rulefire.values import Matcher, RuleError, compile_field


@dataclass
class Entry:
    """One `field|modifiers: values` line of a selection, or a keyword list."""

    key: str
    matcher: Matcher


@dataclass
class Selection:
    name: str
    # Alternatives (a list of maps is an OR); each alternative is an AND of its entries.
    alternatives: list[list[Entry]]

    def matches(self, event: dict[str, Any]) -> bool:
        return any(all(e.matcher(event) for e in alt) for alt in self.alternatives)

    def explain(self, event: dict[str, Any]) -> list[str]:
        """For each alternative, the entries that did not match."""
        out = []
        for alt in self.alternatives:
            failed = [e.key for e in alt if not e.matcher(event)]
            out.append(", ".join(failed) if failed else "")
        return out


@dataclass
class Rule:
    path: str
    title: str
    id: str
    level: str
    logsource: dict[str, str]
    selections: dict[str, Selection]
    condition: condition.Node
    condition_text: str
    unused: list[str] = field(default_factory=list)

    def matches(self, event: dict[str, Any]) -> bool:
        cache: dict[str, bool] = {}

        def sel(name: str) -> bool:
            if name not in cache:
                cache[name] = self.selections[name].matches(event)
            return cache[name]

        return condition.evaluate(self.condition, sel)


def load(path: str | Path) -> Rule:
    text = Path(path).read_text(encoding="utf-8")
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as err:
        raise RuleError(f"not valid YAML: {err}") from err
    if len(docs) != 1:
        raise RuleError("a file with several YAML documents (a rule collection) is not supported")
    return from_dict(docs[0], Path(path).as_posix())


def from_dict(doc: Any, path: str = "<rule>") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("a rule must be a YAML mapping")
    if "correlation" in doc:
        raise RuleError("correlation rules are not supported")
    det = doc.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        raise RuleError("the rule has no detection with a condition")
    cond = det["condition"]
    if isinstance(cond, list):
        if not cond or not all(isinstance(c, str) for c in cond):
            raise RuleError("condition must be text or a list of texts")
        cond_text = " or ".join(f"({c})" for c in cond)
    elif isinstance(cond, str):
        cond_text = cond
    else:
        raise RuleError("condition must be text or a list of texts")
    selections = {}
    for name, body in det.items():
        if name in ("condition", "timeframe"):
            continue
        selections[str(name)] = _selection(str(name), body)
    node = condition.parse(cond_text, list(selections))
    used = condition.referenced(node)
    logsource = doc.get("logsource") or {}
    return Rule(
        path=path,
        title=str(doc.get("title", "")),
        id=str(doc.get("id", "")),
        level=str(doc.get("level", "")),
        logsource={str(k): str(v) for k, v in logsource.items()} if isinstance(logsource, dict) else {},
        selections=selections,
        condition=node,
        condition_text=cond_text,
        unused=[n for n in selections if n not in used],
    )


def _selection(name: str, body: Any) -> Selection:
    if isinstance(body, dict):
        return Selection(name, [_entries(body)])
    if isinstance(body, list):
        if not body:
            raise RuleError(f"selection {name} is empty")
        alts: list[list[Entry]] = []
        keywords = [b for b in body if not isinstance(b, dict)]
        for b in body:
            if isinstance(b, dict):
                alts.append(_entries(b))
        if keywords:
            alts.append([Entry("keywords", compile_field("", [], keywords))])
        return Selection(name, alts)
    if isinstance(body, str | int | float):
        return Selection(name, [[Entry("keywords", compile_field("", [], [body]))]])
    raise RuleError(f"selection {name} is neither a map nor a list")


def _entries(body: dict[Any, Any]) -> list[Entry]:
    if not body:
        raise RuleError("a selection map is empty")
    out = []
    for key, value in body.items():
        name, *mods = str(key).split("|")
        out.append(Entry(str(key), compile_field(name, mods, value)))
    return out
