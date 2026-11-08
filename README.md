# NetworkNinja

Live observability for distributed simulation: metrics, alerts and dashboards for DIS traffic (HLA later). Think Datadog for simulation networks.

NetworkNinja catches exercise-breaking network and simulation faults live, such as a dropped simulator, a duplicated Entity ID or an entity that teleports, instead of leaving them for the after-action review.

## Status

Testable end to end: DIS traffic in (live UDP, multicast, pcap, recordings), checks against the
standard and the exercise's SISO enumerations, explained alerts, dashboards and monitors out.
Releases for Windows, macOS and Linux are on the [Releases](https://github.com/wsustone/NetworkNinja/releases)
page; per-PDU coverage is in [docs/pdu-coverage.md](docs/pdu-coverage.md).

| Milestone | Status |
| --- | --- |
| 1. Generator + capture + decoder | Done: codec for v6 and v7, UDP and multicast capture on chosen interfaces, pcap and pcapng import, a generator with valid traffic and faults for every check, a mutation fuzzer over the decoder and every rule. Still to do: live libpcap capture, kernel drop counters, a dis-rs comparison (ADR 0001). |
| 2. Entity state, metrics and monitor health | Done: entity table per exercise and sender, dead reckoning (algorithms 1–9), freeze handling, tagged metrics and one query API (ADR 0008) with SQLite rollups, per-sender clock skew, tiered PDU capture (ADR 0009), a monitor health panel (queue stalls, kernel drops on Linux as `capture.drops`, CPU, memory). Still to do: performance measurement against the targets. |
| 3. Rule packs + alert rules | Well past the MVP's three rules: structure, enumerations (SISO-REF-010 read from SISO's own XML with `--siso`), heartbeats, entity lifecycle, fire/detonation, collisions and damage, emissions, designators, IFF, radio, SIMAN handshakes, logistics, transfer ownership, aggregates, timestamps and PDU Status, each citing its clause and explained in the dashboard. Still to do: IsGroupOf, the rest of the [deep-check plan](docs/deep-check-plan.md), pack signing. |
| 4. Dashboard + map | Done: live entities, map with offline assets, alerts grouped into explained problems with fixes and fix reports, sender names, PDU evidence, dashboards (templates, variables, custom time windows, drag to zoom, shareable links), user monitors, accounts and HTTPS. Still to do: proper vector tiles. |
| 5. Record and replay | Recording (`--record`) and replay into the dashboard with seek and speed; pcap import. Still to do: replay onto the network (an opt-in feature). |
| 6. Demo | `scripts/nn up demo`: four vendor profiles side by side plus a faulty vendor that runs every fault. |
| 7. Release readiness | Release builds with checksums, no runtime dependencies, macOS signed and notarized. Still to do: Windows signing (SignPath review pending), license files, SBOM, audit log, diagnostic bundle, air-gapped install guide. |

**What the tests prove** (`cargo test --workspace`):

- Each injected fault raises exactly its own finding, on the right entity or sender, and nothing else.
- Clean traffic from four vendor profiles (absolute and relative timestamps, body-axis dead reckoning, a gateway) raises nothing, on v6 and v7.
- Control scenarios raise nothing: clean removals, simulators restarting on new ports, freezes with simulators that keep heartbeating and ones that go silent.
- Only running exercise time counts towards a timeout; frozen time doesn't.
- Entity counts and rolling rates match generator ground truth exactly.
- Every alert any preset raises has an explanation and its evidence.
- Malformed and hostile datagrams and pcap files never crash the monitor, and its state stays bounded.

## Docs

- [MVP spec](docs/spec.md): scope, architecture, alert rules, rule packs, record and replay, security, business model, milestones
- [Rule pack format](docs/rule-packs.md): thresholds, toggles and enumeration checks as data
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
web/          embedded dashboard page (single-file today; TypeScript + MapLibre to come)
rulepacks/    base DIS rule pack (dis-base.toml, compiled into nn-server)
```

## Platforms

- **Monitor (server):** Windows, macOS and Linux, one self-contained binary each. CI builds and tests all three on every push.
- **Viewers:** the dashboard (milestone 4) is a responsive web page, so it works in any modern browser on a desktop, tablet or phone, with nothing to install.
- Phones and tablets are viewers, not capture hosts: capturing exercise traffic needs a machine on the exercise LAN.

## Download

Ready-to-run builds for Linux (x86_64, static), Windows (x86_64) and macOS (universal) are on
the [Releases](https://github.com/wsustone/NetworkNinja/releases) page
([latest](https://github.com/wsustone/NetworkNinja/releases/latest)): unpack one and follow
its `QUICKSTART.md` ([packaging/QUICKSTART.md](packaging/QUICKSTART.md)). Until signed builds
ship (see the [code signing policy](#code-signing-policy)), the quick start explains the macOS
and Windows warnings.

To cut a release, set the workspace version in `Cargo.toml`, then push a matching tag
(`git tag v0.1.0 && git push origin v0.1.0`). The Release workflow builds every platform and
creates a draft release with the archives and `SHA256SUMS.txt`; check it, then publish it.
The published release is what the Releases page (and wsustone.com's download link) serves.

## Get the code

```
git clone https://github.com/wsustone/NetworkNinja.git
cd NetworkNinja
```

Install Rust from https://rustup.rs (Windows also needs the Visual Studio C++ build tools the installer offers). Then:

## Build and test

Requires a recent stable Rust (1.87 or later). There are no external crate dependencies yet. CI runs fmt, clippy and the tests on Linux, Windows and macOS for every push.

```
cargo build --release
cargo test --workspace
```

## Try it

The quickest way: one command starts the server and a whole multi-vendor exercise in the
background, and one stops it (macOS and Linux; on Windows use Git Bash or WSL).

```sh
scripts/nn up        # server + 4 vendor generators + a "faulty vendor"; dashboard at http://127.0.0.1:8080
scripts/nn status    # what's running
scripts/nn logs      # follow the server log (or: logs standard | legacy | body-axis | gateway | faulty)
scripts/nn down      # stop everything
```

`scripts/nn up clean` starts the four vendors without the faulty one: a conforming exercise, so
the dashboard should stay quiet. In the default `demo`, the faulty vendor (sites 9–12) runs every
fault, PDU defect, handshake fault and radio fault, and starts over every 5 minutes. Put a copy of
SISO-REF-010.xml (free from sisostandards.org) at `siso/SISO-REF-010.xml` to add enumeration checks.

To listen to a real exercise (several ports, multicast groups, a particular network card, or a
port a simulator on the same machine already uses), see [docs/capture.md](docs/capture.md) and
start from [`nn.example.toml`](nn.example.toml): `nn-server serve --config nn.toml`.

To run the pieces by hand instead:

On Windows, the binaries are `target\release\nn-server.exe` and `nn-generator.exe`; the first `listen` may trigger a firewall prompt (allow it on private networks).

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

The same traffic into the dashboard instead of the console:

```
./target/release/nn-server serve --port 3000        # then open http://127.0.0.1:8080
./target/release/nn-generator --target 127.0.0.1:3000 --all-faults --all-controls
```

The page shows live entities (positions converted to lat/lon), a one-second state feed and the alert stream, each alert citing its rule pack. `--http` changes the bind; it stays on localhost until configured.

Both tools take `--help`. The generator prints ground truth (PDU counts by type, faults and their times) as JSON; the listener's final summary should match it. `replay` reads pcap and pcapng.

## Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by [SignPath Foundation](https://signpath.org).
Windows builds are signed through SignPath Foundation, and macOS builds with the maintainer's
Apple Developer ID; both are built from this repository by the
[Release workflow](.github/workflows/release.yml) on GitHub-hosted runners
([packaging/SIGNING.md](packaging/SIGNING.md)). Only `nn-server` and `nn-generator`, built from
this project's own source, are signed.

- Committers and reviewers: [Juston Morgan](https://github.com/wsustone)
- Approvers (each release's signing request): [Juston Morgan](https://github.com/wsustone)

Privacy: this program will not transfer any information to other networked systems unless
specifically requested by the user or the person installing or operating it. `nn-server` only
listens on the ports and serves the dashboard you configure; `nn-generator` sends test traffic
only to the target you give it.

## License

Copyright 2026 Juston Morgan. Licensed under the [Apache License, Version 2.0](LICENSE); see also [NOTICE](NOTICE).
