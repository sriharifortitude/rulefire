# 2. What rulefire leaves out

Status: accepted

## Context

Sigma has grown beyond single-event detection: correlation rules count or order events over
time, `expand` fills in values from a configuration, and processing pipelines rename fields
for each SIEM. Supporting all of it would turn a test tool into a detection engine.

## Decision

rulefire evaluates one rule against one event, and refuses, with a message, anything that
needs more:

- **Correlation rules and the old `| count()` aggregations.** They need a window of events
  and a clock. A test file of single events cannot express them honestly.
- **`expand`.** The placeholder values live in a configuration rulefire does not have.
- **Rule collections** (several YAML documents in one file, `action: global`). They are an
  old format; the SigmaHQ repository at the pinned commit has none.
- **Field mappings.** Events are matched on the field names the rule uses. A test event for
  a Sysmon rule is written with Sysmon's names. Mapping to ECS or a vendor schema is what
  pySigma's pipelines are for, and mixing it in would make a failing test ambiguous: is the
  rule wrong, or the mapping?
- **Logsource filtering in tests.** A test file names its rule, so the logsource is not
  consulted. `rulefire scan` runs every rule over every event for the same reason, and says
  so.

## Consequences

- `rulefire check` lists the rules it cannot evaluate. At the pinned SigmaHQ commit there are
  no correlation rules and no collections; the only rules it refuses are the ones using
  `expand`, which are the 25 in `rules-placeholder` and 2 in `rules-emerging-threats`.
- Teams whose events use another schema write their test events in the rule's field names.
  That is extra work, and it is also what keeps a test about the rule rather than about a
  pipeline.
