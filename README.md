# NetworkNinja

Live observability for distributed simulation: metrics, alerts and dashboards for DIS traffic (HLA later). Think Datadog for simulation networks.

NetworkNinja catches exercise-breaking network and simulation faults live, such as a dropped simulator, a duplicated Entity ID or an entity that teleports, instead of leaving them for the after-action review.

## Status

**Milestone 1 (generator + capture + decoder): mostly done.**

| Item | Status |
| --- | --- |
| DIS v6/v7 codec: header for every PDU type, full decode of Entity State, Fire, Detonation, Start/Resume, Stop/Freeze, Remove Entity | Done |
| Multi-PDU datagram splitting; errors counted, never silent | Done |
| Hostile-input robustness test (300k mutated/random inputs, no panic) | Done |
| UDP socket capture: broadcast, multicast join on a chosen interface | Done |
| pcap import/export (Ethernet, Linux cooked, raw IP; VLAN tags) | Done |
| Synthetic generator: heartbeats, DR-threshold updates, Fire/Detonation, all faults and controls, ground-truth JSON | Done |
| End-to-end tests: generator → pcap and generator → live UDP, totals match ground truth exactly | Done |
| Live libpcap capture (SPAN port), pcapng import, kernel drop counters, cargo-fuzz harness | To do |
| Swap the in-house codec for (or validate it against) dis-rs | To do (see ADR 0001) |

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

Requires a recent stable Rust. There are no external crate dependencies yet.

```
cargo build --release
cargo test --workspace
```

## Try it

Terminal 1, the console listener:

```
./target/release/nn-server listen --port 3000
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

Both tools take `--help`. The generator prints ground truth (PDU counts by type, faults and their times) as JSON; the listener's final summary should match it exactly.

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
