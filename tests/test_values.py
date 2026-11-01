import base64
from typing import Any

import pytest

from rulefire.values import QMARK, STAR, RuleError, _base64offset, _windash, compile_field, parse_wildcards


def m(field_spec: str, value: Any, event: dict[str, Any]) -> bool:
    field, *mods = field_spec.split("|")
    return compile_field(field, mods, value)(event)


def test_wildcards_and_escapes() -> None:
    assert parse_wildcards("a*b?c") == ["a", STAR, "b", QMARK, "c"]
    assert parse_wildcards(r"a\*b") == ["a*b"]
    assert parse_wildcards(r"a\?b") == ["a?b"]
    assert parse_wildcards("a\\\\*") == ["a\\", STAR]
    # A backslash before anything else, or at the end, is just a backslash.
    assert parse_wildcards(r"C:\Windows\x") == [r"C:\Windows\x"]
    assert parse_wildcards("end\\") == ["end\\"]


def test_plain_values_match_whole_and_ignore_case() -> None:
    e = {"Image": r"C:\Windows\System32\CMD.EXE"}
    assert m("Image", r"c:\windows\system32\cmd.exe", e)
    assert not m("Image", "cmd.exe", e)
    assert m("Image", "*cmd.exe", e)
    assert m("Image", "*\\CM?.EXE", e)
    assert not m("Image", "*\\C?.EXE", e), "? is exactly one character"
    # In a Windows path, \? is an escaped question mark, not a backslash and a wildcard.
    assert not m("Image", r"C:\Windows\System32\?MD.EXE", e)
    assert m("Image", r"C:\Windows\System32\\?MD.EXE", e)
    assert not m("Image|cased", r"c:\windows\system32\cmd.exe", e)
    assert m("Image|cased", r"C:\Windows\System32\CMD.EXE", e)
    assert m("Image", "*\u00e9*", {"Image": "M\u00c9DIA"}), "case is ignored beyond ASCII"


def test_position_modifiers() -> None:
    e = {"CommandLine": "powershell -enc AAAA"}
    assert m("CommandLine|contains", "-ENC", e)
    assert m("CommandLine|startswith", "powershell", e)
    assert m("CommandLine|endswith", "aaaa", e)
    assert not m("CommandLine|startswith", "-enc", e)
    assert m("CommandLine|contains", "*-enc*", e), "wildcards already there are fine"


def test_lists_are_or_unless_all() -> None:
    e = {"CommandLine": "a b"}
    assert m("CommandLine|contains", ["x", "b"], e)
    assert not m("CommandLine|contains|all", ["x", "b"], e)
    assert m("CommandLine|contains|all", ["a", "b"], e)


def test_null_exists_and_missing_fields() -> None:
    assert m("Foo", None, {})
    assert m("Foo", None, {"Foo": None})
    assert not m("Foo", None, {"Foo": ""})
    assert m("Foo|exists", True, {"Foo": ""})
    assert not m("Foo|exists", True, {"Foo": None})
    assert m("Foo|exists", False, {})
    assert not m("Foo", "*", {}), "a wildcard does not match a missing field"
    assert m("Foo", "", {"Foo": ""})


def test_numbers_and_booleans() -> None:
    assert m("EventID", 4688, {"EventID": 4688})
    assert m("EventID", 4688, {"EventID": "4688"}), "text that spells the number"
    assert not m("EventID", 4688, {"EventID": 4689})
    assert m("EventID", "4688", {"EventID": 4688})
    assert m("Enabled", True, {"Enabled": True})
    assert not m("Enabled", True, {"Enabled": "true"})
    assert not m("Enabled", True, {"Enabled": 1})
    assert m("Enabled|cased", "true", {"Enabled": True}), "a boolean reads as true/false in text"
    assert not m("Size|gt", 0, {"Size": True}), "a boolean is not a number"
    assert m("Size|lte", 10, {"Size": 10})
    assert not m("EventID", 1, {"EventID": True})
    assert m("Size|gt", 10, {"Size": 11})
    assert not m("Size|gt", 10, {"Size": 10})
    assert m("Size|gte", 10, {"Size": "10"})
    assert m("Size|lt", 10, {"Size": 9.5})
    assert not m("Size|lte", 10, {"Size": "big"})
    with pytest.raises(RuleError):
        compile_field("Size", ["gt"], "ten")


def test_regular_expressions() -> None:
    e = {"CommandLine": "Invoke-Expression (New-Object Net.WebClient)"}
    assert m("CommandLine|re", r"New-Object\s+Net\.WebClient", e)
    assert not m("CommandLine|re", r"new-object", e), "re is case-sensitive by default"
    assert m("CommandLine|re|i", r"new-object", e)
    assert m("Text|re|m", "^b$", {"Text": "a\nb"})
    assert m("Text|re|s", "a.b", {"Text": "a\nb"})
    with pytest.raises(RuleError):
        compile_field("x", ["re"], "(")


def test_cidr() -> None:
    assert m("DestinationIp|cidr", "10.0.0.0/8", {"DestinationIp": "10.200.1.1"})
    assert not m("DestinationIp|cidr", "10.0.0.0/8", {"DestinationIp": "11.0.0.1"})
    assert not m("DestinationIp|cidr", "10.0.0.0/8", {"DestinationIp": "10.example"})
    assert m("DestinationIp|cidr", "fe80::/10", {"DestinationIp": "fe80::1"})
    assert m("DestinationIp|cidr", ["192.168.0.0/16", "172.16.0.0/12"], {"DestinationIp": "172.20.0.5"})


def test_base64offset_matches_the_sigma_documentation() -> None:
    assert sorted(_base64offset(b"http://")) == sorted(["aHR0cDovL", "h0dHA6Ly", "odHRwOi8v"])
    assert m("CommandLine|base64offset|contains", "http://", {"CommandLine": "x aHR0cDovL3d3dy5leGFtcGxl y"})
    assert m("CommandLine|base64", "http://", {"CommandLine": "aHR0cDovLw=="})


def test_wide_then_base64offset() -> None:

    payload = base64.b64encode("Xinvoke-mimikatzY".encode("utf-16-le")).decode()
    assert m("CommandLine|wide|base64offset|contains", "invoke-mimikatz", {"CommandLine": payload})
    assert not m("CommandLine|base64offset|contains", "invoke-mimikatz", {"CommandLine": payload})


def test_windash() -> None:
    variants = {"".join(str(t) for t in v) for v in _windash(["-f -urlcache a-b"])}
    assert "/f /urlcache a-b" in variants
    assert "\u2013f -urlcache a-b" in variants
    assert all(v.endswith("a-b") for v in variants), "a dash inside a word is not an option"
    assert len(variants) == 25
    assert m("CommandLine|windash|contains", "-f", {"CommandLine": "certutil /f"})


def test_fieldref() -> None:
    assert m("TargetFilename|fieldref", "Image", {"TargetFilename": "C:\\A.exe", "Image": "c:\\a.exe"})
    assert not m("TargetFilename|fieldref|cased", "Image", {"TargetFilename": "C:\\A.exe", "Image": "c:\\a.exe"})
    assert not m("TargetFilename|fieldref", "Image", {"TargetFilename": "x"})


def test_event_shapes() -> None:
    assert m("process.name", "cmd.exe", {"process": {"name": "cmd.exe"}})
    assert m("process.name", "cmd.exe", {"process.name": "cmd.exe"})
    assert not m("process.name", "cmd.exe", {"process": "cmd.exe"})
    assert m("Tags", "admin", {"Tags": ["user", "admin"]}), "a list field matches if any element does"


def test_keywords_search_every_value() -> None:
    assert m("", "mimikatz", {"a": {"b": ["x", "run MIMIKATZ now"]}})
    assert not m("", "mimikatz", {"a": "nothing"})


def test_rejected_modifiers() -> None:
    for mods in (["expand"], ["nonsense"]):
        with pytest.raises(RuleError):
            compile_field("x", mods, "v")
    with pytest.raises(RuleError):
        compile_field("x", ["base64"], "a*b")
    with pytest.raises(RuleError):
        compile_field("x", [], [])
    with pytest.raises(RuleError):
        compile_field("x", ["contains"], None)
