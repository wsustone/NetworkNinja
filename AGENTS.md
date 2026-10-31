# NetworkNinja — operational notes

## Build/test (always verify before committing)

```sh
export PATH="$HOME/.cargo/bin:$PATH"   # some shells don't source .zshenv
cargo build --release
cargo test --workspace
cargo fmt --all
cargo clippy --workspace --all-targets # must be warning-free
```

## Gotchas

- `target/release/nn-server` is **stale after source edits** — rebuild before
  telling the user to run new flags (this burned us on `--db`).
- `grep -c` prints 0 and exits 1 on no matches — don't chain `&&` after
  counting clippy warnings; it silently skips later commands.
- Runtime files (`events.db*`, `events.jsonl`, `.nn/`) and the local SISO
  copy (`siso/`) are gitignored — don't re-add them. Don't commit them.
  Check `git status` before every commit and stage paths explicitly: a
  `git add -A` on a branch cut before the ignore rule landed swept `.nn/`
  logs and SISO-REF-010.xml into #13.
- Dashboard = port 8080 (or `--http`); live UDP capture commonly on 3000;
  test instances on 3008/3009 + 8098/8099.

## Common run

One switch for everything (server + four vendor generators, plus a faulty
vendor in `demo`), in the background, state and logs under `.nn/`:

```sh
scripts/nn up [demo|clean]   # build, start; dashboard on 127.0.0.1:8080
scripts/nn status | logs [NAME] | down
```

`NN_UDP`, `NN_HTTP`, `NN_DB`, `NN_SISO` (default `siso/SISO-REF-010.xml`
if present), `NN_ARGS` override; use other ports and `NN_DB` for test runs
so they don't write into the user's `events.db`. By hand:

```sh
./target/release/nn-server serve --port 3000 --db events.db --runs .
./target/release/nn-generator --target 127.0.0.1:3000 --duration 600 \
  --all-faults --all-controls --fire-every 10
```

Several generators at once (each its own sockets, like separate simulators):
give each a non-overlapping site range, e.g. `--site-base 1 --sites 2` and
`--site-base 3 --sites 2 --application 7`; overlapping ranges are real ID
conflicts. `--all-faults`/`--all-controls` use the first/second site.
Vendor profiles (`--profile standard|legacy|body-axis|gateway`,
`--list-profiles`) are legitimate variation; `scripts/multi-vendor.sh
[TARGET] [SECS] [-- flags]` runs all four side by side and must stay silent.
Entity State orientation is true geocentric Euler (`geo::heading_to_euler`),
so body-axis DR (algorithm 6) round-trips through `dr::body_to_world`.

Recordings: `--record x.nnrec` while serving; pick it from the header
run dropdown (`--runs DIR` for `/api/runs`); scrub bar + `--speed`.
Accounts: `nn-server passwd FILE --user U --pass P`, then `serve --users
FILE`. Passwords are PBKDF2-HMAC-SHA256 (`user:pbkdf2:salt:hash` lines);
older `user:salt:hash` SHA-1 lines still verify — re-run `passwd` to
upgrade one. Login is `POST /api/login` with a form body; the session
token goes in `Authorization: Bearer` (`?token=` only for `/ws`), idles
out after 12 h, and `POST /api/logout` ends it. TLS (ADR 0006): `nn-server cert nn [--host NAME]` writes
`nn.crt` + `nn.key` (refuses to overwrite), then `serve --cert nn.crt --key
nn.key` → HTTPS + WSS on the `--http` port; no flags = plaintext as before.
TLS WebSockets share one rustls session between the reader/writer threads
(`TlsReader`/`TlsWriter` in `web.rs`) since it can't be `try_clone`d.
Entity detail: `GET /api/entity?ex=N&id=S:A:E` returns the row's fields
plus type breakdown, first seen, DR algorithm, appearance, mute and a
per-sender list (reports, heartbeat mean/jitter) — rebuilt each state tick
into `Hub::details`, kept out of the delta feed on purpose. The dashboard
polls it for the selected row's panel under the entity table.
Metrics + `/api/query` (ADR 0008 slice 1): series are a `Metric` + typed
`Tags` in `nn_state::metrics`; per-entity gauges (heartbeat, DR error) live
in 10 s slots, the rest in 1 s buckets. `Monitor::tick` samples gauges.
The serve loop owns the metrics, so `Hub::query` asks it for memory cells
over `QueryReq` and reads the SQLite `series`/`samples` rollups for slots
before the last flush. Rollups are written every 10 s **live only** (not
during replay) and on clean exit; `--metrics-retention DAYS` (default 7).
Query string: `name=pdu.count&where.site=7&by=sender&agg=rate&window=10&from=&to=`.
PDU capture (ADR 0009): `serve --capture cap.db --capture-budget MB` (live
only, opt-in). `[[capture]]` tiers in packs (`type` prefix, `min_speed`,
`every`; highest min_speed then longest prefix wins) are applied by
`nn_rules::Capture` inside `Monitor::ingest`; `pdustore.rs` writes on its
own thread and evicts oldest rows by SQLite page counts. Inspect with
`/api/capture`, `/api/pdus?ex=&id=&from=&to=`, or `sqlite3 cap.db`.

Tier S structure (ADR 0010): `nn_decode::structure::check(rest_of_datagram)`
runs on every PDU span in `Monitor::ingest`, decoded or not, and feeds
`Engine::check_structure` → point events `pdu-structure` / `pdu-padding` /
`pdu-family` (deduped per rule, PDU type and sender for `enum_repeat_seconds`).
Layouts: one table entry per type, offsets absolute from the PDU start
(header included). Generator: `--all-types SECS` sends a minimal valid PDU
of every type not otherwise generated; `--defect KIND:TYPE[@T]` and
`--all-defects` inject the structural faults from the first site.

Tier E (ADR 0010): `serve --siso FILE` loads SISO-REF-010 XML (`nn_rules::Siso`,
hand-rolled scanner) and layers its `pack()` between the base pack and
`--rulepack`s (`Merged::load_with`). The XML is **not** in the repo (SISO's
licence and freshness); tests use `crates/rules/tests/fixtures/siso-mini.xml`,
and `NN_SISO=path cargo test -p nn-rules --test siso` runs the full-file check.
Raw enumerated fields of undecoded types: `nn_decode::fields` (offset, UID,
a SISO-valid default the generator writes). `--defect bad-enum:TYPE`.

SIMAN handshakes (ADR 0010 step 5): `nn_rules::siman::Handshakes` pairs
requests with answers on raw bytes (`Engine::check_siman` per PDU, overdue
ones in `Engine::tick`), rule `siman-handshake`, pack threshold
`response_timeout` (12 s). Broadcasts and a simulation's requests about its
own entities owe no answer. Generator: `--siman-every SECS` (first site asks
the second), faults `--no-response/--wrong-ack/--orphan-response SITE[@T]`,
preset `--all-handshake-faults`. Test scenarios that send a directed
Remove Entity or Stop/Freeze must also send the Acknowledge.

Radio (ADR 0010 step 5): `nn_rules::radio::Radios` keyed by (exercise,
Radio Reference ID, Radio Number), on raw bytes (`Engine::check_radio`,
timeouts in `Engine::tick`, frozen time excluded); rule `radio`,
`[rules.radio]` heartbeats/multiplier/idle_transmit/signal_slack. Signals
for an unknown radio are only reported after a stationary timeout (144 s)
of watching. Generator `--radio-every SECS`, faults `--hot-mic`,
`--orphan-signal`, `--bad-signal`, `--drop-transmitter SITE[@T]`, preset
`--all-radio-faults` (4 sites). Coverage's minimal Transmitter reports
"transmitting" so its minimal Signal is legitimate.

Listening (docs/capture.md): `nn_capture::Listeners` runs one reader thread
per `UdpConfig` (port, groups, interface, `share` = SO_REUSEADDR/PORT,
receive buffer, default 8 MB) into one channel; `serve --config nn.toml`
(`[serve]` + `[[listen]]`, `nn_server::config`), `--listen
PORT[:GROUP,...][@IFACE]`, `--share`, `--receive-buffer MB`,
`nn-server interfaces`; `/api/inputs` and the dashboard inputs line.
`share` is for broadcast/multicast only: unicast reaches one sharer.
Generator `--iface`/`--ttl` pick the multicast send interface.
Live editing: `Listeners::add/replace/remove` (replace rolls back on
failure); commands `input_add|input_update|input_remove|inputs_save` over
the WebSocket or `POST /api/inputs` → `Switch::Inputs` in the serve loop;
outcome in `/api/inputs` `last_change`; `config::save_listeners` rewrites
only `[[listen]]` blocks (+ `.bak`). `Datagram.listener` tags each datagram;
the monitor drops same-sender identical bytes within `echo_window` and
raises `duplicate-delivery` (listener-overlap vs network-duplicate);
`Monitor::via` feeds the entity detail's sender "via".

Wave 0: entity timeouts are per entity, `RuleConfig::timeout_for(kinematics)`
/ `timeout_of(rec)`: DR algorithm Static or no speed → `stationary_heartbeat`
(60 s, HBT_STATIONARY) × multiplier, else `heartbeat`. Never use the bare
`config.timeout()` for a real entity. Entity State Update (67) is decoded;
`Monitor::merge_update` turns it into a full Entity State from the entity's
last report (header keeps type 67), so table and rules need no ESU cases.
Generator: `parked_per_site`, `stationary_heartbeat`, `entity_state_update`,
profile `economical`. Test entities with zero velocity are stationary now:
give them a speed when a test needs the 12 s timeout.

## Timing and identity semantics (October 2026 review fixes)

- Live datagrams carry `monotonic` (`nn_capture::steady_now()`, a steady clock
  anchored to wall time at first read); the monitor runs rules on it, falling
  back to `received_at` for pcap/recordings. Live `tick` calls must use
  `steady_now()` too, never `SystemTime::now()`, or the two clocks mix.
  The recorder writes the steady stamp.
- Byte-identical PDUs from a second sender within `duplicate_window` (pack
  threshold on `id-conflict`, default 1 s) are dropped before the rules and
  counted in `pdu.duplicates` / `Monitor::duplicates`.
- Freezes are scoped by receiving ID (`EntityTable::scoped`); read an
  entity's freeze state with `table.state_for(&key)`, not `exercises`.
- 65535 wildcards expand via `table::id_matches`; Detonation ends its
  `munition_id` entity; a timeout alert survives the entity's expiry.
- Padded PDUs decode (length field may exceed the body); short ones don't.

## Conformance (ADR 0008 slice 2)

`Alert::sender` is who an alert is pinned on (see the ADR for the rules).
`events` has `sender`/`pack`/`state` columns, added by `ALTER TABLE` on
open for old files. `summary.rs` is pure aggregation (unit-tested);
`Hub::events_summary` feeds it store rows (or the ring without `--db`) plus
`conformance_state(&m)` pushed each tick. Try:
`curl 'localhost:8080/api/events/summary?by=sender,rule&since=0'`.

## Architecture map

`crates/` — capture (UDP/pcap), decode (DIS codec), state (entities+geo),
rules (alert engine+packs), recorder (.nnrec), server (`web.rs` hand-rolled
HTTP/WS + `store.rs` SQLite + `auth.rs` accounts + `main.rs` CLI),
generator (synthetic traffic: `world.rs` shared simulation, `families/` one
module per DIS protocol family with its faults, `wire.rs` encoding/bundling;
`tests/golden.rs` pins output byte for byte — a deliberate traffic change
updates its hashes in the same commit; ADR 0010). Decisions in `docs/adr/`, spec in
`docs/spec.md`. Dashboard is the single-file `web/index.html` compiled
into the binary via `include_str!` — restart `serve` to pick up edits.
