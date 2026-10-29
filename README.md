# NetworkNinja

Live observability for distributed simulation: metrics, alerts and dashboards for DIS traffic (HLA later). Think Datadog for simulation networks.

NetworkNinja catches exercise-breaking network and simulation faults live, such as a dropped simulator, a duplicated Entity ID or an entity that teleports, instead of leaving them for the after-action review.

## Status

The core loop works end to end on the console: synthetic or captured DIS traffic in, the three MVP alerts out.

| Milestone | Status |
| --- | --- |
| 1. Generator + capture + decoder | Mostly done: codec, UDP and multicast capture, pcap and pcapng import, generator with every fault and control. Still to do: live libpcap capture, kernel drop counters, cargo-fuzz harness, dis-rs comparison (ADR 0001). |
| 2. Entity state, metrics and monitor health | Core done: entity table per exercise and sender, heartbeat statistics, rolling PDU/byte/error rates, freeze periods, dead reckoning (algorithms 1–9), ECEF ↔ lat/lon. Still to do: performance measurement against the targets, kernel drop counts. |
| 3. Rule packs + three alert rules | Rules done and proven against the generator (below). Still to do: the rule-pack format and loader, SISO-REF-010 enumeration checks. |
| 4–7 | Not started. |

**What the tests prove** (`cargo test --workspace`):

- Each injected fault raises exactly one alert, on the right entity: timeout within 0.6 s of the 12 s deadline, ID conflict by the original sender's next report, position jump on the very next report.
- Control scenarios raise nothing: clean Remove Entity, simulators restarting on new ports, and a 20 s freeze (with simulators that keep heartbeating and ones that go silent).
- Only running exercise time counts towards a timeout; frozen time doesn't.
- A 30-minute clean run with 75 entities raises nothing.
- Entity counts and rolling rates match generator ground truth exactly.
- Disabling any suppression (freeze, restart grace, dead reckoning) makes the tests fail.

## Docs

- [MVP spec](docs/spec.md): scope, architecture, alert rules, rule packs, record and replay, security, business model, milestones
- [Architecture diagram](docs/architecture.svg)
- [Architecture decision records](docs/adr/)

## Planned layout

```
crates/
  capture/    passive UDP socket and libpcap capture, drop counters
  decode/     DIS v6/v7 decoding (dis-rs), PDU splitting
  state/      per-entity state and rolling metrics
  rules/      rule-pack loader and alert engine
  recorder/   native recording format, pcap import/export, replay
  server/     single binary: WebSocket API and embedded dashboard
  generator/  synthetic DIS traffic with fault injection
web/          dashboard frontend (TypeScript, MapLibre) — not started
rulepacks/    base DIS rule pack — not started
```

## Build and test

Requires a recent stable Rust (1.87 or later). There are no external crate dependencies yet. CI runs fmt, clippy and the tests on Linux and Windows for every push.

```
cargo build --release
cargo test --workspace
```

## Try it

Terminal 1, the console listener (`--alerts-only` hides the per-PDU lines):

```
./target/release/nn-server listen --port 3000 --alerts-only
```

Terminal 2, synthetic traffic with every fault and control scenario:

```
./target/release/nn-generator --target 127.0.0.1:3000 --duration 60 \
    --all-faults --all-controls --fire-every 7
```

Or generate a pcap and replay it without a network:

```
./target/release/nn-generator --pcap demo.pcap --truth demo-truth.json --all-faults --all-controls
./target/release/nn-server replay demo.pcap --quiet
```

Expected: an ID-conflict alert on 1:1:2, a position-jump on 1:1:3 (resolving a few seconds later), and an entity-timeout on 1:1:1, and nothing for the removed entity, the restarted site or the freeze.

Both tools take `--help`. The generator prints ground truth (PDU counts by type, faults and their times) as JSON; the listener's final summary should match it. `replay` reads pcap and pcapng.

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
