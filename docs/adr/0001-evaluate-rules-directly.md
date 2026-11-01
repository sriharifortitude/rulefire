# 1. Evaluate Sigma rules directly, and check that against pySigma

Status: accepted

## Context

A detection rule is code that nobody runs until an attacker does. The usual way to test one
is to replay an attack in a lab, ship the logs to a SIEM and look for the alert. That takes
a lab, a SIEM and an afternoon, so it happens once, when the rule is written, and not when
someone later adds a filter for a noisy server and quietly stops the rule firing on the
attack it was written for.

What is missing is the unit test: given this event, does the rule fire? That needs something
that can evaluate a Sigma rule against an event without a SIEM.

Three ways to get that were considered:

- **Convert with pySigma and run the query.** pySigma turns rules into queries for a backend.
  With the SQLite backend the query could run over events in an in-memory table. But keyword
  searches need a full-text column the backend asks to be configured, the value types follow
  SQLite's rules rather than Sigma's (`=` is case-sensitive, `'5003' = 5003` is false), and
  a failing test would be explained by a generated SQL string, not by the rule.
- **Use an EVTX hunting tool** (Hayabusa, Chainsaw, Zircolite). They evaluate Sigma rules,
  but over Windows event logs and their own field mappings. A test would have to be written
  as an EVTX file.
- **Evaluate the rule directly.** Parse the detection, apply the modifiers, evaluate the
  condition over a JSON event. More work, and a second implementation of Sigma's semantics
  that could be wrong in its own ways.

## Decision

Evaluate rules directly, in plain Python with PyYAML as the only dependency, so that a
failure can be explained in the rule's own terms: which selection did not match, and which
entry in it failed.

Treat that implementation as a hypothesis and test it against pySigma. `scripts/differential.py`
builds events from every rule in the SigmaHQ repository (events meant to satisfy each
selection, near misses of them, and pairs merged so filters fire), runs pySigma's SQL for the
rule over them in SQLite, and requires the two to agree on every event. Where SQLite and
Sigma differ, the oracle is adjusted towards Sigma and the adjustment is written down:
the table's columns are declared `COLLATE NOCASE`, because the backend writes plain values
as `=`, which SQLite compares case-sensitively.

## Consequences

- Test failures name selections and entries, which is what someone tuning a rule needs.
- Semantics are pinned by two independent sources, the specification and pySigma's
  behaviour over three thousand real rules, instead of by my reading of the spec alone.
- Two differences remain and are documented rather than hidden. rulefire matches a number
  against text that spells it (`EventID: 4688` matches `"4688"`), because log pipelines
  often deliver numbers as strings; SQLite does not. rulefire ignores the case of every
  letter; SQLite only of ASCII letters.
- What pySigma cannot convert (107 SigmaHQ rules, all keyword searches) has no oracle,
  and is covered only by rulefire's own tests.
