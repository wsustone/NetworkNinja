# NetworkNinja

Live observability for distributed simulation: metrics, alerts and dashboards for DIS traffic (HLA later). Think Datadog for simulation networks.

NetworkNinja catches exercise-breaking network and simulation faults live, such as a dropped simulator, a duplicated Entity ID or an entity that teleports, instead of leaving them for the after-action review.

## Status

Pre-MVP. The spec is done and code has not started. Next up: **milestone 1**, the synthetic traffic generator plus capture and decode.

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

## Build

```
cargo build
cargo test
```

## License

Proprietary. All rights reserved. See [LICENSE](LICENSE).
