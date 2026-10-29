# 0005: Event and run storage in embedded SQLite

Date: 2026-10-28 · Status: Accepted

## Context

The event log (ADR: log entries at `/api/log`, persisted as JSONL via
`--log`) proves the shape of what we need: alerts, decode errors and server
events with sequence numbers and timestamps. But a ring buffer and a
append-only file don't answer the real questions — "show every
position-jump on 1:1:2 this week", "what happened in yesterday's run",
"which entities keep timing out". Those need indexed, searchable history.

Recording/replay (milestone 5) and after-action analysis need the same
store: PDUs + events + recording metadata in one place, queryable.

The catch: the workspace has zero external dependencies, deliberately —
one self-contained binary, air-gapped sites, SBOM-friendly builds.

## Options

- **Keep JSONL + hand-rolled index.** No new deps, but we would slowly
  re-invent a database — badly. Searching needs real indexing; we would
  write it ourselves and maintain it forever.
- **Pure-Rust KV store (redb, sled).** No SQL, no full-text search, no
  ecosystem tooling to inspect the files. Fits "single binary" but buys
  little over the JSONL.
- **SQLite via `rusqlite` with the `bundled` feature.** Real SQL and FTS5
  full-text search — exactly "search through logs". `bundled` compiles the
  C source at build time, so the artifact is still one static binary with
  no runtime dependency. `.db` files open in every sqlite tool on earth,
  which helps offline support tickets. Cost: our first external deps
  (`rusqlite`, `libsqlite3-sys`), ~1 MB of code, C compilation in CI on all
  three platforms.

## Decision

SQLite, embedded via `rusqlite` with `bundled`. The zero-dependency posture
was about distribution simplicity and auditability, not about never
linking anything; a vendored, statically-compiled SQLite keeps both. This
is the first accepted external dependency — it needs its own line in the
SBOM and the CI supply-chain checks when those exist (milestone 7).

Layout (one `.db` per monitor, WAL mode):

- `events(seq, at, kind, pack, rule, entity, exercise, severity, message, json)` —
  the log, FTS5 over `message`.
- `pdus(at, source, exercise, pdu_type, site, entity, json)` — opt-in full
  capture for after-action work.
- `recordings(id, name, started_at, duration, exercise, packs, metadata)` —
  milestone 5's index.
- `runs(id, started_at, ended_at, packs)` — boundaries between serve runs.

The in-memory ring buffer and `--log` JSONL stay as the hot path; SQLite is
the persistent store behind `/api/log` and the future recordings UI. If
linking C ever becomes a hard constraint, `redb` is the fallback noted
above — the API boundary (`EventStore` trait) keeps that swap cheap.

## Consequences

- `/api/log` queries move from "tail of a ring buffer" to indexed SQL:
  filter by kind, rule, entity, exercise, time range, full-text message.
- The dashboard's event feed becomes "tail + search", Datadog-style.
- Build grows `rusqlite` + `libsqlite3-sys` (bundled); CI already covers
  Linux/Windows/macOS — the bundled C build must pass on all three.
- Open: retention policy (size caps, vacuum); whether PDU capture defaults
  on per exercise profile (spec says recording is opt-in).
