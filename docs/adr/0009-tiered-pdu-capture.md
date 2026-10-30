# 0009: Tiered PDU capture by entity type and speed

Date: 2026-10-30 · Status: Accepted

## Context

ADR 0005 reserved a `pdus` table for opt-in full capture, and the spec
says no PDU payloads are persisted by default. Full capture of everything
is the wrong default even when capture is on. Most of an exercise's
traffic is heartbeats from slow or parked entities, so it costs a lot of
disk and adds little. Fast movers are different. Aircraft and munitions
can cross a kilometre between heartbeats, and position-jump and
dead-reckoning analysis needs every report from them. Metrics (ADR 0008)
already give the slow aggregate view, so the per-PDU store only has to
hold detail where detail matters.

The store must also never flood the host's disk, and writing it must never
slow packet capture down.

## Decision

**Tiers are pack data.** Rule packs gain `[[capture]]` entries:

```toml
[[capture]]
type = "1.2"        # entity type prefix, kind first; "*" = any
min_speed = 0.0     # optional, m/s: applies only at or above this speed
every = 0           # seconds between kept reports per entity and sender;
                    # 0 = every PDU, "off" = none
```

They layer like `[[enum]]`: a later pack replaces an entry with the same
`type` and `min_speed`. For an Entity State, the matching entry with the
highest `min_speed` wins, then the longest type prefix. Observed speed
therefore beats declared type: a truck doing 60 m/s is a fast mover. The
base pack keeps every report from air (1.2), space (1.5), munitions (2)
and anything faster than 50 m/s. Land platforms get one report per 5 s,
or per 1 s above 15 m/s. Surface and subsurface get 5 s, life forms 10 s,
and anything else 30 s.

**Always kept, regardless of tier:**
- Fire, Detonation, Start/Resume, Stop/Freeze and Remove Entity. They are
  rare, and they are the events.
- Every report from an entity while it has an open alert, so the PDUs
  around a fault are there for review.

PDU types the decoder doesn't deep-decode are not captured. Signal and
voice traffic would dominate the volume and isn't analysed yet.

**Storage.** `serve --capture FILE` writes to its own SQLite file,
separate from the event store. That lets it be deleted, moved or handled
under its own classification marking without touching the event log. Each
row keeps the PDU's exact wire bytes (`raw` BLOB) plus at, sender,
exercise, type, entity and the tier that kept it. Rows are indexed by
entity and time. Capture follows live traffic only; a replay already is a
recording.

**Never flood the disk.**
- `--capture-budget MB` (default 1024) caps the file's live pages,
  indexes included, measured from SQLite's own page counts.
- Past the cap, the oldest tenth of the rows goes, repeatedly, until usage
  is back under 90% of the budget. Freed pages are reused, so the file
  stops growing at about the budget plus the WAL.
- A writer thread owns the connection and commits every 0.5 s. If it falls
  behind, the bounded queue drops whole batches and counts them, so the
  capture loop never waits on disk.
- `/api/capture` reports budget, used, rows, written, skipped, dropped and
  evicted.

**Reading.** `GET /api/pdus?ex=&id=&from=&to=&limit=` returns stored PDUs
oldest first, with Entity State position, speed and appearance decoded,
for track drill-down.

**Entity-type filters on metrics.** `pdu.count` gains `kind` and `domain`
tags (ADR 0008 §1), so charts and monitors can filter or split by entity
type. Entity State carries the type; other PDUs take their primary
entity's type from the table.

## Options considered and rejected

- **Capture everything, rely on retention by age.** A busy exercise fills
  any age-based window unpredictably. A byte budget is what an operator
  can actually promise a host.
- **Thin by a fixed decimation rate.** That loses exactly the reports
  that matter for fast movers. Type and speed are what distinguish signal
  from heartbeat noise.
- **Write from the capture loop.** One slow fsync would stall packet
  capture. The writer thread with a lossy queue keeps receive-only
  capture first.
- **Store decoded JSON (ADR 0005's sketch).** It is 3–5× larger and
  lossy for undecoded fields. Wire bytes decode on read and replay
  exactly.

## Consequences

- Positive: full fidelity where analysis needs it, and a bounded,
  predictable disk cost. Tiers are tunable per exercise or site without a
  build. Alerts leave their evidence behind.
- Negative: eviction is oldest-first across all tiers, so a long run can
  lose old fast-mover detail before old heartbeats. Priority eviction is
  possible later if users need it. The `skipped` counter restarts when the
  capture source switches.
- Open: change-triggered capture for slow movers (keep a report when
  heading, appearance or DR algorithm changes); a free-disk-space floor;
  exporting a time slice of the capture as `.nnrec` or pcap (milestone 5);
  a dashboard view of an entity's captured track.
