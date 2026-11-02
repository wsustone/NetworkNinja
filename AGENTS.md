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
Fields that repeat per record (EE Emitter Name / Function per system, Beam
Function per beam) are `fields::repeated_fields()`, each a `values(body)`
walker; `FieldSpec::values` returns every occurrence and an enum check flags
the first outside its set. The siso-mini fixture defines the generator's
emitter (1800 / 4 / 4); `--bad-emitter-enums` writes 65535 / 255.

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

Heartbeats: `nn_decode::heartbeat` is the table (type, symbol, default,
clause, pack key; `own_rule` for Entity State/ESU/radio/DE Fire, which their
own rules handle). Rule `heartbeat` (`nn_rules::heartbeats`) times out any
other object (type + first identifier) after heartbeat × multiplier; final
reports (Designator power 0, EDS with no records) and removed/deactivated
entities owe nothing; frozen time pauses. `[rules.heartbeat] iff = 20`.
The generator's `--all-types` sends heartbeat types at their heartbeat;
`--defect stop-heartbeat:TYPE`.

Entity lifecycle (`nn_rules::lifecycle`, rule `entity-lifecycle`): after a
Remove Entity the entity owes one Entity State with appearance Deactivated
within `final_report_window` (12 s); active again after Deactivated, or
Deactivated reports past the window, is a zombie; DR Static with speed;
same-sender type/force/marking change; ESU for an entity never seen in full
(after a 144 s startup grace). The generator now sends that final report on
Remove (golden hashes changed for it); faults `--no-final-report`,
`--zombie`, `--static-moving`, `--type-change`, `--orphan-update`, preset
`--all-lifecycle-faults`. Test scenarios that remove entities must send the
final Deactivated report. Use `cargo test --no-fail-fast` when checking a
change: plain `cargo test` stops at the first failing test binary.

Fire/Detonation (`nn_rules::warfare`, rule `fire-detonation`): shots keyed
by (exercise, Event ID); a munition Fire's Detonation is due within
`max_flight` (180 s; expendables exempt); a munition Detonation with no Fire
is judged only after `max_flight` of watching and names mines/demolitions as
legitimate; Fire/Detonation must agree on firer and munition type; v7 PDU
Status FTI/DTI must agree with the descriptor kind (2 munition, 8
expendable). Generator faults `--no-detonation`, `--detonation-mismatch`,
`--wrong-fire-type`, `--orphan-detonation T`, preset `--all-warfare-faults`.

Interactions (`nn_rules::interactions`, raw bytes via `Engine::check_interactions`):
rule `directed-energy` (DE Fire heartbeat `de_heartbeat` 0.5 s while Flags bit
0 is on; one Fire after the first DE Fire, a Detonation after the last),
`entity-damage` (no EDS after Deactivated; a repair with no records must clear
the platform's appearance damage bits within `repair_window`), `collision`
(both parties within `collision_window`, pinned on the silent one; one per
event and PDU type). Munition domain runs 0-12 (12 = directed energy).
Generator `--collision-every/--damage-every/--de-every SECS`, faults
`--one-sided-collision`, `--duplicate-collision`, `--stale-appearance`,
`--eds-after-remove ID`, `--de-dropout`, `--de-no-fire`, preset
`--all-interaction-faults`. A deliberate repeat must differ in bytes, or echo
detection (`duplicate-delivery`) drops it before the rules see it.
Wave 1 wrap-up: `fire-detonation` also flags a fired mine (munition category
Fixed, 3) and an Entity Impact far from the target (`impact_tolerance`);
`collision` flags nobody moving (`collision_speed`, COLLISION_THRSH; Collision
velocity at 32); DE Fire / EDS records must be aimpoints / 4500. Rule
`attribute` (`nn_rules::attribute::check`, given the PDUs either side in the
datagram) covers 5.3.6.3 and Coupled PDU Extension. PDU Status is header byte
**10** (8-9 is the length). Coverage's minimal Collision moves and its
Attribute holds a record (set in `minimal()`, so defects keep them).
Faults `--mine-fired`, `--impact-miss`, `--still-collision`,
`--bad-de-record`, `--bad-attribute`, `--missing-extension`.

Electromagnetic Emission (`nn_rules::emission`, rule `emission`, Wave 2): emitter
systems keyed by (exercise, entity, Emitter Number), heartbeat `ee_heartbeat`
per *system* (EE is `own_rule` in the heartbeat table now, so `[rules.heartbeat]`
has no EE key); identity, reserved/duplicate numbers, high density, CW/pulsed,
Track/Jam targets, Deactivated-twice, Destroyed-but-emitting. EE bytes: systems
from 28 (20-byte header: name @4, function @6, number @7), beams 52 + 8 per
target (PRF @16, PW @20, targets @45, high density @46, status @47).
Generator `--emission-every SECS` (an AN/APG-63 for 30 s), eight faults, preset
`--all-emission-faults`; `SimEntity.destroyed` sets appearance Damage 3.

Designator (`nn_rules::designator`, rule `designator`): keyed by (exercise,
designating entity); heartbeat and Power-0-final stay with `heartbeat`. Adds
spot-offset (0:0:0 with an offset), unknown-target (after grace),
stale-target / designator-gone (an entity ceased to exist while Power > 0,
no Power 0 within `final_report_window`). Bytes: designating @12, designated
@20, power f32 @28, spot offset @36, location @48, DR algorithm @72 (UID 44,
in `fields`). Generator `--designator-every SECS` (30 s at 5 s heartbeat);
it switches off properly when either entity goes; faults `--spot-offset`,
`--unknown-designated`, `--target-gone`, `--designator-gone`, preset
`--all-designator-faults`. Entities "cease to exist" via `final_due`.

Explanations (alerts work): every `Alert` carries `kind` (the finding type)
and `facts` (named evidence, in order); JSON adds `rule_name`, `finding` and
`facts` (`[[name, value], ...]`). **Not `kind`** in JSON: log entries already
use `kind` for alert/error/info. `nn_rules::explain` is the catalog (title,
impact, causes, fix) per (rule name, finding), `*` for a rule-wide entry
(heartbeat's findings are PDU type names), served at `/api/explain`.
`tests/explain.rs` runs every preset on all four vendor profiles and fails on
any unexplained finding: add a catalog entry with every new finding type.
Fault presets live in `nn_generator::presets` (`Presets::all()`, `schedule`)
so tests build the same runs as the CLI. Every finding fills `facts`: each
tracker's `Finding` has a `facts` field (warfare's helper adds the shot's
firer / Event ID / munition / indicator, attribute's wrapper the PDU's own
fields) and `Engine::point_event` takes them. `tests/explain.rs` also fails
on any preset alert raised without facts.
Dashboard Issues panel: tabs Problems (default) / Entities / Log
(`boardView` in localStorage). A problem groups per-entity issues by
(exercise, check `rule`, `finding`, simulation = entity site:app); its card
title comes from `/api/explain` (`titleOf`), expands (keys in
`localStorage.nn_expanded`) to message + facts, impact, causes, fix,
affected-entity chips, clause (parsed from the message by `CITE`), and
"ack all" / "mute this check". The timeline counts firings seen since the
page loaded (the `/api/log` backlog plus live), 2-minute bars over an hour.
Sender names (`nn_server::names`): `[[sender]]` blocks (`name` + `address`
"ip" / "ip:port" or `simulation` "site:app" / "site"), most specific wins.
`GET /api/senders`; `POST /api/senders {"cmd":"sender_set", address|simulation,
name}` (empty name removes) saves via `config::save_senders` when started with
`--config`, else lasts until restart. Handled in `Hub`, not the serve loop.
The dashboard names senders by IP (source ports change on restart).
Fix report (`nn_server::report`): `GET /api/report?sim=S:A[&exercise=&since=
&format=md|csv]` groups the simulation's alert firings (entity site:app) and
its senders' decode errors (senders whose claims include it) by check and
finding, from the store (`alert_entries`) or the in-memory log. Card button
"fix report for S:A" opens it (copy Markdown, download .md / .csv).
PDU evidence: `AlertEvent::pdu` (`Arc<[u8]>`) is the PDU that raised a firing;
`Monitor::ingest` attaches it to every firing raised while checking that PDU
(`attach_pdu`), none for timeouts (silence). `Hub::log_alert` logs and keeps
it by seq (ring of `LOG_CAP`, plus the store's `evidence` table with --db);
alert JSON gets `"pdu": LEN`. `GET /api/evidence?seq=N` (`nn_server::evidence`)
returns named header fields, enumerated fields or the decoder's view, and a
hex dump. Log alerts with `hub.log_alert(e)`, not `log("alert", ...)`.

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
