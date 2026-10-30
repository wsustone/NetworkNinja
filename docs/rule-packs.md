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

## PDU capture tiers

With `nn-server serve --capture FILE`, these entries decide how much Entity
State traffic is persisted (ADR 0009):

```toml
[[capture]]
type = "1.2"        # entity type prefix, kind first ("*" = any type)
min_speed = 0.0     # optional, m/s: only while moving at least this fast
every = 0           # seconds between kept reports per entity and sender;
                    # 0 = every PDU, "off" = none
```

- The matching entry with the highest `min_speed` wins, then the longest
  `type` prefix. Observed speed therefore outranks declared type.
- A later pack replaces an entry with the same `type` and `min_speed`;
  other entries from lower layers stay.
- Always kept regardless of tier: Fire, Detonation, Start/Resume,
  Stop/Freeze, Remove Entity, and every report from an entity with an
  open alert. Undecoded PDU types are never captured.
- The base pack's tiers are at the end of `rulepacks/dis-base.toml`.

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
