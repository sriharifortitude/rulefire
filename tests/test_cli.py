import io
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from rulefire.cli import main

EXAMPLES = Path(__file__).parent.parent / "examples"


def run(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_the_examples_pass() -> None:
    code, out, _ = run("test", str(EXAMPLES / "tests"))
    assert code == 0, out
    assert "7 passed, 0 failed" in out


def test_the_first_version_of_the_rule_fails_and_says_why(tmp_path: Path) -> None:
    junit = tmp_path / "r.xml"
    code, out, _ = run("test", "-q", str(EXAMPLES / "regression"), "--junit", str(junit))
    assert code == 1
    assert "4 passed, 3 failed" in out
    assert "download: no match (CommandLine|contains|all did not match)" in out
    assert "certutil: no match (Image|endswith did not match)" in out
    assert "  ok " not in out, "--quiet hides passing cases"
    suite = ET.parse(junit).getroot().find("testsuite")
    assert suite is not None and suite.get("tests") == "7" and suite.get("failures") == "3"


def write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


RULE = "title: t\ndetection:\n  s: {CommandLine|contains: evil}\n  condition: s\n"


def test_events_from_jsonl_and_broken_test_files(tmp_path: Path) -> None:
    write(tmp_path, "r.yml", RULE)
    write(tmp_path, "bad.jsonl", '{"CommandLine": "evil"}\n\n{"CommandLine": "fine"}\n')
    write(tmp_path, "a.tests.yml", "rule: r.yml\nmatch_file: bad.jsonl\n")
    code, out, _ = run("test", str(tmp_path))
    assert code == 1 and "bad.jsonl:3: did not fire" in out
    write(tmp_path, "a.tests.yml", "rule: missing.yml\nmatch: [{}]\n")
    code, out, _ = run("test", str(tmp_path / "a.tests.yml"))
    assert code == 1 and "cannot read the rule" in out
    for body, message in [
        ("match: [{}]\n", "needs a `rule:`"),
        ("rule: r.yml\n", "no match or no_match"),
        ("rule: r.yml\nmatch: [1]\n", "not a mapping"),
        ("rule: r.yml\nmatch_file: nope.jsonl\n", "nope.jsonl"),
    ]:
        write(tmp_path, "a.tests.yml", body)
        code, out, _ = run("test", str(tmp_path / "a.tests.yml"))
        assert code == 1 and message in out, (body, out)
    write(tmp_path, "notjson.jsonl", "{oops\n")
    write(tmp_path, "a.tests.yml", "rule: r.yml\nmatch_file: notjson.jsonl\n")
    _, out, _ = run("test", str(tmp_path / "a.tests.yml"))
    assert "notjson.jsonl:1: not JSON" in out


def test_no_test_files(tmp_path: Path) -> None:
    code, _, err = run("test", str(tmp_path))
    assert code == 2 and "no *.tests.yml" in err


def test_scan(tmp_path: Path) -> None:
    write(tmp_path, "r.yml", RULE)
    write(tmp_path, "broken.yml", "title: b\ndetection: {condition: nope}\n")
    events = write(tmp_path, "e.jsonl", "\n".join(json.dumps({"CommandLine": c}) for c in ["evil", "evil 2", "ok"]))
    code, out, err = run("scan", str(tmp_path), "--events", str(events), "--show", "1")
    assert code == 0
    assert "      2  t" in out and '"evil"' in out and '"evil 2"' not in out
    assert "skipping" in err and "broken.yml" in err
    assert run("scan", str(tmp_path / "r.yml"), "--events", str(events), "--benign")[0] == 1
    baseline = EXAMPLES / "baseline.jsonl"
    assert run("scan", str(EXAMPLES / "rules"), "--events", str(baseline), "--benign")[0] == 0


def test_explain(tmp_path: Path) -> None:
    r = write(tmp_path, "r.yml", RULE)
    code, out, _ = run("explain", str(r), '{"CommandLine": "very evil"}')
    assert code == 0 and "t: fires" in out and "s: matched" in out
    ev = write(tmp_path, "e.json", '{"CommandLine": "fine"}')
    _, out, _ = run("explain", str(r), f"@{ev}")
    assert "does not fire" in out and "s: no match (CommandLine|contains did not match)" in out
    assert run("explain", str(r), "[1]")[0] == 2
    assert run("explain", str(r), "{bad")[0] == 2
    bad = write(tmp_path, "bad.yml", "title: b\ndetection: {condition: x}\n")
    assert run("explain", str(bad), "{}")[0] == 2


def test_check(tmp_path: Path) -> None:
    write(tmp_path, "r.yml", "title: t\ndetection:\n  s: {a: 1}\n  u: {b: 2}\n  condition: s\n")
    code, out, _ = run("check", str(tmp_path))
    assert code == 0 and "selection u is never used" in out
    write(tmp_path, "x.yml", "title: x\ndetection:\n  s: {a|expand: '%x%'}\n  condition: s\n")
    code, out, _ = run("check", str(tmp_path))
    assert code == 1 and "expand" in out and "1 cannot be evaluated" in out


def test_usage_errors() -> None:
    assert run()[0] == 2
    assert run("--version")[0] == 0
    assert run("test", "a", "--nope")[0] == 2


def test_none_of_several_alternatives(tmp_path: Path) -> None:
    r = write(tmp_path, "r.yml", "title: t\ndetection:\n  s: [{a: 1}, {b: 2}]\n  condition: s\n")
    _, out, _ = run("explain", str(r), "{}")
    assert "s: none of its 2 alternatives matched" in out
