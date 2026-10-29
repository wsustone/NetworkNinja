# Rule packs

Rules are data, not code (ADR 0003). A rule pack is a TOML file that sets
alert thresholds, switches rules on and off, and declares allowed values for
enumerated PDU fields. Packs layer — base DIS pack → exercise profile → site
overrides — and the last pack to touch a rule or field wins.

The base pack `rulepacks/dis-base.toml` is compiled into `nn-server`; layer
files on top with `--rulepack FILE` (repeatable, later files win). A bad
pack is rejected at startup with a `file:line` error and nothing runs.

The parser is a deliberately small TOML subset: `[section]` and
`[[array-of-tables]]` headers, `key = value`, `#` comments, basic strings,
integers, floats, booleans and single-line arrays. No multi-line strings,
inline tables or dates.

```toml
[pack]
id = "site-alpha"        # required; alerts cite it as site-alpha/rule-name
version = 1              # required, positive integer
name = "Site Alpha"      # optional, defaults to id
source = "..."           # optional: where the numbers came from
description = "..."      # optional

[defaults]
enum_repeat_seconds = 60.0   # min gap between repeats of the same violation
tick_interval = 0.25         # how often time-based checks run

[rules.entity-timeout]
enabled = true               # optional; "severity = off" also disables
severity = "warning"         # warning | critical | off
heartbeat = 5.0              # threshold overrides; each rule has its own set

# Rules: entity-timeout (heartbeat, timeout_multiplier),
#        id-conflict (conflict_grace),
#        position-jump (jump_min_tolerance, assumed_dr_threshold,
#                       jump_dr_multiplier, jump_timing_slack)

[[enum]]
field = "entity-state.force_id"   # a field from the registry below
allowed = "0-8"                   # integer, "lo-hi", "a, b-c", or [1, 2, "3-9"]
severity = "warning"              # optional; "off" removes a lower layer's check
```

## Field registry

- `header.protocol_version`, `header.pdu_type`, `header.protocol_family` —
  checked on **every** PDU, including types not deep-decoded.
- `entity-state.force_id`, `entity-state.marking.character_set`,
  `entity-state.dead_reckoning.algorithm`
- `entity-state.entity_type.*` and `entity-state.alternative_entity_type.*`:
  `kind`, `domain`, `country`, `category`, `subcategory`, `specific`, `extra`
- `fire.descriptor.munition_type.*`, `detonation.descriptor.munition_type.*`
  (same seven subfields)
- `detonation.result`
- `stop-freeze.reason`, `stop-freeze.frozen_behavior`

## Semantics

- A `[[enum]]` entry replaces the lower layer's check **for the same field**;
  `severity = "off"` removes it entirely.
- `[rules.<name>]` keys merge per key — a site pack can change just
  `timeout_multiplier` and inherit the rest.
- Enum violations are point events: they fire once and repeat at most every
  `enum_repeat_seconds`, per field per entity. They do not stay open.
- Every alert carries the id of the pack that contributed the effective rule
  or check, shown in the console as `pack/rule-id`.

## Still to come

Generated (not hand-authored) SISO-REF-010 enumeration tables, pack signing
like license files, and delivery in offline update bundles — see the spec.
