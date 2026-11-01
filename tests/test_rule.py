from pathlib import Path
from typing import Any

import pytest
import yaml

from rulefire.condition import And, Not, Or, Ref, parse, tokenize
from rulefire.rule import Rule, from_dict, load
from rulefire.values import RuleError


def rule(detection: str) -> Rule:
    return from_dict({"title": "t", "detection": yaml.safe_load(detection)})


def test_precedence_not_and_or() -> None:
    names = ["a", "b", "c"]
    assert parse("a or b and c", names) == Or((Ref("a"), And((Ref("b"), Ref("c")))))
    assert parse("not a and b", names) == And((Not(Ref("a")), Ref("b")))
    assert parse("not (a or b)", names) == Not(Or((Ref("a"), Ref("b"))))
    assert parse("A AND NOT b", ["A", "b"]) == And((Ref("A"), Not(Ref("b"))))
    assert tokenize("not(a or b)") == ["not", "(", "a", "or", "b", ")"]


def test_of_expressions() -> None:
    names = ["sel_a", "sel_b", "filter", "_hidden"]
    assert parse("1 of sel_*", names) == Or((Ref("sel_a"), Ref("sel_b")))
    assert parse("all of sel_*", names) == And((Ref("sel_a"), Ref("sel_b")))
    assert parse("1 of filter*", names) == Ref("filter")
    assert parse("all of them", names) == And((Ref("sel_a"), Ref("sel_b"), Ref("filter")))
    with pytest.raises(RuleError):
        parse("1 of nothing*", names)


@pytest.mark.parametrize(
    "text",
    ["a and", "a b", "(a", "missing", "and a", "a or )"],
)
def test_bad_conditions(text: str) -> None:
    with pytest.raises(RuleError):
        parse(text, ["a"])


def test_aggregations_are_named() -> None:
    with pytest.raises(RuleError, match="aggregations"):
        parse("a | count() > 5", ["a"])


def test_a_list_of_maps_is_or_and_a_map_is_and() -> None:
    r = rule(
        """
        sel:
          - Image|endswith: '\\cmd.exe'
            User: admin
          - OriginalFileName: Cmd.Exe
        condition: sel
        """
    )
    assert r.matches({"Image": "C:\\x\\cmd.exe", "User": "admin"})
    assert not r.matches({"Image": "C:\\x\\cmd.exe", "User": "bob"})
    assert r.matches({"OriginalFileName": "cmd.exe"})


def test_keywords_and_condition_lists() -> None:
    r = rule(
        """
        keywords:
          - 'mimikatz'
          - 'sekurlsa'
        other:
          Image: x
        condition:
          - keywords
          - other
        """
    )
    assert r.matches({"msg": "sekurlsa::logonpasswords"})
    assert r.matches({"Image": "x"})
    assert not r.matches({"msg": "hello"})


def test_filters_and_unused_selections() -> None:
    r = rule(
        """
        sel:
          CommandLine|contains: vssadmin
        filter_backup:
          ParentImage|endswith: '\\backup.exe'
        unused:
          Foo: bar
        condition: sel and not filter_backup
        """
    )
    assert r.matches({"CommandLine": "vssadmin delete shadows"})
    assert not r.matches({"CommandLine": "vssadmin delete shadows", "ParentImage": "C:\\b\\backup.exe"})
    assert r.unused == ["unused"]


def test_selection_results_are_reused() -> None:
    calls: list[dict[str, Any]] = []
    r = rule("a: {x: 1}\ncondition: a and (a or a)")
    entry = r.selections["a"].alternatives[0][0]
    original = entry.matcher

    def counting(e: dict[str, Any]) -> bool:
        calls.append(e)
        return original(e)

    entry.matcher = counting
    assert r.matches({"x": 1})
    assert len(calls) == 1


@pytest.mark.parametrize(
    "doc",
    [
        "not a mapping",
        {"detection": {"sel": {"a": 1}}},
        {"detection": {"condition": 5, "sel": {"a": 1}}},
        {"detection": {"condition": "sel", "sel": None}},
        {"correlation": {"type": "event_count"}, "detection": {"condition": "s", "s": {"a": 1}}},
        {"detection": {"condition": "sel", "sel": {}}},
        {"detection": {"condition": "sel", "sel": []}},
    ],
)
def test_rejected_rules(doc: Any) -> None:
    with pytest.raises(RuleError):
        from_dict(doc)


def test_load_from_files(tmp_path: Path) -> None:
    p = tmp_path / "r.yml"
    p.write_text("title: t\ndetection:\n  s: {a: 1}\n  condition: s\n", encoding="utf-8")
    assert load(p).title == "t"
    valid = "title: t\ndetection:\n  s: {a: 1}\n  condition: s\n"
    p.write_text(valid + "---\n" + valid, encoding="utf-8")
    with pytest.raises(RuleError, match="several YAML documents"):
        load(p)
    p.write_text("", encoding="utf-8")
    with pytest.raises(RuleError):
        load(p)
    p.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleError):
        load(p)
