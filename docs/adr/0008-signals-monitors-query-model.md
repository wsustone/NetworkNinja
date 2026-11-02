# 0008: Signals, monitors and one query model

Date: 2026-10-29 · Status: Proposed

## Context

The pitch is "Datadog for simulation networks" (spec, README). What
Datadog and Splunk actually sell reduces to four layers:

1. **Signals** — metrics and events, every one tagged with the same
   dimensions (host, service, …).
2. **Monitors** — a saved query over signals with a condition, window and
   group-by, producing one alert per group.
3. **Alert lifecycle** — firing/resolved, acknowledge, mute, routes.
4. **Dashboards** — widgets bound to the *same* queries monitors use, so
   "I see it on a chart" → "alert me on it" is one step.

Where we stand after milestones 1–4:

- Metrics (`nn_state::Metrics`) are one-second buckets of PDU/byte/error
  counts split by PDU type and site only, 10 minutes in memory, gone on
  restart.
- Events are in SQLite (ADR 0005) with `kind/rule/entity/severity/
  exercise/message`, but `/api/log` only filters and tails; nothing
  aggregates ("which sender produces the most violations?").
- Alerts come from three behavioural rules written in Rust plus the
  packs' `[[enum]]` checks (ADR 0003). A user cannot define a check of
  their own without a new build.
- The dashboard is one fixed page.

Our structural difference from Datadog and Splunk: their customers must
instrument their own systems before anything is monitorable. DIS is a
published standard with a fixed schema, so **we are the source of the
errors** — nobody writes a log line. That makes a guided builder over a
small, typed query model the right interface, not a query language
(Splunk's SPL is where most users bounce). HLA later fits the same
model: federate ≈ sender, object class ≈ entity type, attribute update /
interaction ≈ PDU.

## Decision

### 1. Signals carry one set of dimensions

Every metric sample, event and alert is tagged from this set (absent
tags are simply omitted):

| Tag | Values | Source |
| --- | --- | --- |
| `exercise` | DIS exercise id | PDU header |
| `site`, `app` | entity id fields | primary entity of the PDU |
| `entity` | `S:A:E` | primary entity of the PDU |
| `sender` | `ip:port` | datagram source |
| `pdu_type` | `EntityState`, `Fire`, … | PDU header |
| `kind`, `domain`, `force` | DIS enumerations | Entity State |
| `pack`, `rule` | rule pack id and rule / field path | engine |
| `severity` | `warning`, `critical` | engine |

Metric catalogue (names are stable API, like Datadog's `system.cpu.*`):

| Metric | Unit | Dimensions |
| --- | --- | --- |
| `pdu.count` | PDUs | exercise, pdu_type, site, kind, domain, sender (kind/domain: ADR 0009) |
| `bytes.count` | bytes | sender |
| `datagram.count` | datagrams | sender |
| `decode.errors` | errors | sender |
| `entity.active` | entities (gauge) | exercise, site, kind, force |
| `entity.heartbeat_mean`, `entity.heartbeat_jitter` | s (gauge) | exercise, entity, sender |
| `entity.dr_error` | m (gauge) | exercise, entity |
| `sender.clock_skew` | s (gauge) | sender |
| `capture.drops` | datagrams | — |
| `alerts.open` | alerts (gauge) | exercise, rule, severity |

Storage: the one-second in-memory buckets stay the hot path and grow the
`sender` split and the gauges above. Every 10 s the loop writes rollups
(count/sum/min/max per series) to SQLite — `series(id, name, tags)` and
`samples(series, at, n, sum, min, max)` — with a default retention of
7 days (`metrics_retention` in `config.toml`, ADR 0007). Queries read
memory for the last 10 minutes and SQLite beyond it, so a dashboard can
show the whole exercise, not the last ten minutes. Events get `sender`
and `pack` columns so they aggregate on the same tags.

### 2. One query object, no query language

```json
{
  "signal": "metric",            // or "event"
  "name": "pdu.count",           // metric name; for events: kind or rule, "*" for all
  "where": {"exercise": 1, "site": 7},
  "by": ["sender"],              // 0..n dimensions → one series/group each
  "agg": "rate",                 // sum | avg | min | max | count | rate
  "window": 60,                  // seconds per point (timeseries) or the whole span (toplist)
  "from": 1793371000, "to": 1793374600
}
```

`GET /api/query` (query-string or JSON body) answers with
`{"series":[{"tags":{…},"points":[[t,v],…]}]}` or, when `window` spans
the whole range, `{"groups":[{"tags":{…},"value":v}]}`. The same object
is what a monitor evaluates and what a dashboard widget draws. The
dashboard builds it with pickers; nobody types it.

### 3. Three tiers of rules

- **Standard rules — ours, in packs.** Enumerations generated from
  SISO-REF-010; structural checks (lengths, header fields); behavioural
  rules per PDU family, each citing the IEEE/SISO clause: the three we
  ship, then timestamp skew per sender, v6/v7 mixed in one exercise,
  Detonation without a matching Fire, Fire from an unknown shooter,
  Entity State after Remove, a frozen exercise with moving entities,
  exercise-id mismatch on a port. Rules that need state stay in Rust;
  packs carry their thresholds and severities as today.
- **Declarative pack checks** — extend `[[enum]]` with siblings that need
  no code: `[[range]]` on numeric fields (altitude, speed by kind,
  non-empty marking), `[[expect]]` whitelists (allowed sites/apps,
  expected entity population per site).
- **User monitors** — the Datadog monitor, stored as a pack layer
  (`monitors.toml` in the data directory, edited through the dashboard,
  copyable to another site):

```toml
[[monitor]]
id = "site7-silent"
name = "Site 7 federate silent"
type = "absence"                  # threshold | absence | event-count | composite
signal = "metric"
metric = "pdu.count"
where = { exercise = 1, site = 7, pdu_type = "EntityState" }
by = ["sender"]
for = 15.0                        # seconds the condition must hold (kills flapping)
severity = "critical"

[[monitor]]
id = "noisy-sender"
type = "event-count"
signal = "event"
name = "enum-violation"
by = ["sender"]
window = 300
condition = ">= 20"
severity = "warning"
```

One evaluator runs monitors on the engine tick over the same metric
buckets and event store the API reads. Alert key = monitor id + group
tags, so a `by = ["sender"]` monitor opens one alert per sender. Monitor
alerts flow through the existing `Alert`/`AlertEvent` path: ack, mute,
event log, Hub broadcast all work unchanged. The builder previews a
monitor before saving: "would have fired 3 times in the last 10 min".
Anomaly-against-exercise-baseline is a later monitor type, not part of
this ADR. Note the pack parser has no inline tables today; `where` is
the one place that needs them, or it becomes dotted keys
(`where.site = 7`).

### 4. Alert lifecycle additions

`for` durations on every rule, routes per severity or monitor (syslog /
CEF, a LAN webhook, audible in the dashboard), and grouping by monitor +
tags in the alert feed. Nothing else changes; ADR 0007's read-only trial
gate applies to monitor editing as to ack and mute.

### 5. Dashboards for grouping errors

- **Phase A — fixed views, no builder.** Views that match how exercise
  control thinks: *by sender/federate* (the conformance view from the
  spec: who is non-compliant, which rules, how often, when last), *by
  rule*, *by site*, and a *timeline*. Every count click-filters the event
  log and selects the entity. Backed by
  `GET /api/events/summary?by=sender,rule&since=…`.
- **Phase B — user dashboards.** A grid of widgets (timeseries, toplist,
  counter, table, event stream, map), each bound to a query object from
  §2, saved as a JSON file in the data directory and importable. Shipped
  templates: Exercise overview, Federate health, Conformance, Warfare.

## Options considered and rejected

- **A query language** (SPL-, PromQL- or SQL-like): huge surface, steep
  learning curve, injection risk on a shared dashboard. Our schema is
  fixed, so pickers over a typed object do the job; the object is still
  text (TOML/JSON) for power users and export.
- **An external time-series store** (Prometheus, InfluxDB, ClickHouse):
  a second process to install and secure on an air-gapped host; breaks
  the single-binary promise. SQLite rollups cover a single monitor; the
  Enterprise central server (spec) is where a real TSDB may belong.
- **Making every rule declarative:** stateful behavioural rules (dead
  reckoning, interleaved senders, freeze handling) need code; Datadog's
  own integrations are code too. Keep code for semantics, data for
  thresholds, checks and monitors.
- **OpenTelemetry as the internal model:** heavyweight for one process;
  an OTLP/syslog *export* of signals can come later as a route.

## Implementation checklist

Slices 1 and 2 are ready to execute; 3–5 are sequenced but not yet
broken down.

### Slice 1 — tagged metrics, `/api/query`, persistence

**Done (2026-10-30).** Decisions taken while building it:

- Per-entity gauges (heartbeat mean/jitter, DR error) live in 10 s slots,
  not 1 s buckets: at the 10,000-entity target a 1 s ring of them would
  hold millions of entries. DR error is recorded per Entity State report
  and folded into its slot; heartbeat stats are sampled once per slot.
- Gauges fold in two steps: series within a time cell add up (each
  series' mean in that cell), then cells in a point average. So `sum`
  of `entity.active` by site is "entities on that site" whether the cell
  is a 1 s bucket or a 10 s disk row. Counters zero-fill empty points;
  gauges leave gaps. `rate` on a gauge is rejected.
- `/api/query` takes a query string only (`where.DIM=…`, the dotted form
  §3 already suggests); the JSON body waits for the monitor editor.
  Responses echo the query and carry the metric's unit.
- The serve loop owns the metrics, so the HTTP thread asks it for the
  matching memory cells over a channel and reads SQLite itself for every
  slot before the last flush; the loop never waits on disk.
- Rollups are written for live capture only: a replay's timestamps are the
  recording's, and would land in today's history. A clean exit flushes the
  partial last slot.
- Retention is `serve --metrics-retention DAYS` (default 7) until the ADR
  0007 `config.toml` exists; swept on start and hourly.
- Not yet: `sender.clock_skew` and `capture.drops` (no source for either
  yet), and events gaining `sender`/`pack` columns (slice 2, item 1).

1. `nn_state::Metrics`: add a `sender` split to `Bucket` and the gauges
   `entity.active` (by exercise/site/kind/force) and per-entity
   heartbeat mean/jitter and DR error sampled once per second; tags as
   a small `Tags` struct, not strings, to keep buckets cheap.
2. `nn_state::metrics::query(&Query) -> Vec<Series>` over the in-memory
   buckets: `where`, `by`, `agg`, `window`. Unit tests against generator
   ground truth, the pattern the existing metrics tests use.
3. `store.rs`: `series` + `samples` tables; a 10 s rollup flush from the
   `serve` loop; retention sweep on start and hourly; `query` falls
   through to SQLite for ranges older than memory.
4. `web.rs`: `GET /api/query` (authenticated), the JSON shape in §2;
   request validation with clear error messages like packs; tests in
   `crates/server/tests/web.rs`.
5. Dashboard: the traffic chart reads `/api/query`, with a split picker
   (type / site / sender) and a window picker (10 min / 1 h / run).
6. `AGENTS.md` and `docs/spec.md` (State and metrics) updated; README
   milestone 2 row.

### Slice 2 — conformance view and event aggregation

**Done (2026-10-30).** Decisions taken while building it:

- Every alert now names the sender it is attributed to (`Alert::sender`):
  the PDU's source for enum checks and position jumps, the entity's last
  sender for a timeout, and for an ID conflict the *later* of the two
  senders to appear — the one that took an ID already in use. The message
  still names both.
- `events` also gained `state`, so the summary counts firings, not
  resolutions. Stores from before this slice are migrated in place; their
  rows count, with sender `unknown` and state read from the JSON.
- Decode errors count as violations under rule `decode-error` (pack
  `decoder`), so a sender emitting malformed PDUs shows up in the same
  table as one breaking rules.
- `by` also takes `pack`, `severity` and `exercise`; `entity=` filters to
  one entity (the detail panel's per-rule counts). When grouping by sender
  the response lists every live sender with the `site:app` pairs it
  claims, so compliant senders appear as clean rows, not missing ones.
- Open-alert counts come from the live engine, pushed to the Hub every
  state tick with the sender claims; history comes from the store, or from
  the in-memory log when there is no `--db`.
- `/api/log` gained `sender=`; the dashboard's event-log filter now
  matches every space-separated term, sender included, which is what a
  conformance cell click uses.

1. `store.rs`: add `sender` and `pack` columns to `events` (ALTER TABLE
   on open when missing) with indexes; `main.rs` fills them for every
   alert and decode error.
2. `GET /api/events/summary?by=sender|rule|site|entity&since=&exercise=`
   returning groups with counts per severity, first/last seen, open
   alert count; `by` accepts up to two dimensions for a pivot.
3. Dashboard "Conformance" tab: sender table (ip:port → sites/apps it
   claims) with one column per rule, counts, last violation, open
   alerts; by-rule and by-site pivots; a cell click filters the event
   log and selects the entity where there is one.
4. Entity detail panel shows the entity's violation counts from the
   same endpoint.
5. Tests for the summary query and endpoint; docs + README milestone 3
   row ("conformance view").

### Later slices

3. Monitors: `[[monitor]]` parsing in `nn_rules::pack`, the evaluator,
   `monitors.toml` layer, `/api/monitors` CRUD, builder UI with preview.
4. Standard rules by PDU family, starting with SISO-REF-010 generation
   and the behavioural rules listed in §3.
5. Dashboard builder, saved dashboards, templates; alert routes.
   Done so far: `GET/PUT/DELETE /api/dashboards` (a `dashboards` table in
   the `--db` store, in-memory without it) and a "Dashboards" tab whose
   widgets bind to §2 query objects and are built picker-only with a
   live preview. Widget kinds: timeseries, toplist and counter over
   `/api/query`; status tiles (a query plus a warn/critical threshold,
   "bad above" or "bad below"; thresholds also colour counters and draw
   on timeseries); an event stream over the live feed (alerts, decode
   errors, info, filtered by state, severity and words, with ack); and a
   violations table over `/api/events/summary` (one or two dimensions).
   Every group, row and event clicks through to the entity or the
   filtered log. Shipped templates: "Exercise overview", "Conformance &
   health" and "Error hunt". The board has one time range and point in
   time for every widget (a range select, step buttons and a scrubber
   that pauses the board in the past; metric widgets re-query the
   rollups, the event stream reads the store through `/api/log?from&to`,
   and the violations table passes `until` so alerts open *now* don't
   count for a window that ended earlier). Template variables (a
   dimension per variable, e.g. sender or site, with values from live
   data) filter every widget whose metric carries that dimension and
   substitute `$name` in where-filters. In edit mode a widget's title
   bar drags it to a new place and its corner resizes it (1–3 columns ×
   1–3 rows of a fixed-height grid; charts fill their cell). Still open:
   alert routes, and "create monitor from widget" once slice 3 lands.
   The map stays its own view, not a widget.

## Consequences

- Positive: one query object serves charts, monitors and the summary
  views, so each new metric is instantly chartable and alertable; users
  get their own monitors without a build; errors are grouped by the
  party that caused them, which is the conformance view the Pro tier is
  sold on; metrics survive restarts.
- Negative: the metric names and query shape become public API we must
  keep stable; SQLite grows a second write path (rollups) and a
  retention job; per-sender and per-entity series multiply memory at
  the 10,000-entity target, so gauges are sampled at 1 Hz and rolled to
  10 s on disk, and the performance tests in milestone 2 must cover it.
- Open: whether monitors are a Pro feature or Base with a count cap;
  anomaly/baseline monitors; whether `pdus` capture (ADR 0005) feeds
  per-PDU drill-down from the conformance view.
