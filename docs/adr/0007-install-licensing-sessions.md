# 0007: Installed service, offline license file, member sessions

Date: 2026-10-29 · Status: Proposed

## Context

ADR 0002 decided *what* we sell: an on-prem term license checked fully
offline, never phoning home, with expiry that warns and then runs on
through a grace period. It left *how* for milestone 7. Meanwhile the
pieces an installed product needs have landed one at a time:

- local accounts (`--users`, `passwd`) with PBKDF2 passwords, expiring
  bearer sessions and sign-out;
- TLS on the management port (ADR 0006) with a `cert` subcommand;
- SQLite event storage per run (ADR 0005).

Today all of it is driven by a long `serve` command line that someone
has to keep running in a terminal. A customer install must survive a
reboot, be configurable by a site admin who is not us, and prove it is
licensed without any network. This ADR fixes how install, license,
accounts and TLS fit together so milestone 7 is a build, not a design.

Three layers, three owners:

| Layer | Question it answers | Owner |
| --- | --- | --- |
| License | May this install run, with which tier/limits, until when? | Vendor (us) |
| Accounts + sessions | Who is watching; who acked this alert? | Customer's admin |
| TLS | Can anyone on the LAN read tokens and credentials? | Customer's admin |

## Decision

### Install: one binary that installs itself as a service

- `nn-server install` registers the binary as a background service that
  starts at boot: a systemd unit on Linux, a launchd daemon on macOS, a
  Windows service via the service control manager. `nn-server uninstall`
  reverses it. No installer framework in the MVP; a signed zip/tarball
  per platform carries the binary, the install guide and checksums.
  MSI/RPM/DEB come later if buyers ask.
- A **config file** replaces the flag list: `config.toml` in the same
  no-dependency TOML subset rule packs use. Sections: `capture` (port,
  bind, multicast, iface), `dashboard` (bind, cert, key, users), `storage`
  (db, runs, record), `rules` (packs). Flags still override the file, so
  development and tests keep working unchanged.
- One **data directory** per install holds `config.toml`, `users`,
  `license`, `cert.pem`/`key.pem`, `events.db` and recordings:
  `/etc/networkninja` + `/var/lib/networkninja` on Linux,
  `/Library/Application Support/NetworkNinja` on macOS,
  `%ProgramData%\NetworkNinja` on Windows. The key file and users file
  are created mode 0600 (owner-only ACL on Windows).
- `nn-server setup` is the **first-run** step, interactive or fully
  flag-driven for scripted installs: management bind address; TLS
  (generate self-signed for the given hosts, or import the site PKI's
  cert and key); the first admin account; the license file. It writes
  `config.toml`, then `install` starts the service. Air-gapped admins work
  from a console or SSH, so this stays CLI-first; a browser setup wizard
  is not planned.

### License: an Ed25519-signed file checked locally

- A license is a small TOML payload signed with a vendor key we never
  ship. The file is ASCII-armoured so it survives email, chat and
  sneakernet: `-----BEGIN NETWORKNINJA LICENSE-----`, base64 of
  `payload || signature`, `-----END ...`. Signing uses Ed25519 from
  `aws-lc-rs`, already in the binary for TLS and PBKDF2; no new crate.
  The binary embeds the vendor public keys with key ids, so a key can be
  rotated by shipping a release that trusts both old and new.
- Payload fields: `id`, `customer`, `site`, `tier` (base|pro|enterprise),
  `seats` (concurrent dashboard sessions), `limits` (entities, sensors),
  `addons` (custom message set ids), `issued`, `expires`, `grace_days`
  (default 30). Everything is in the clear so the customer can read what
  they bought; only the signature is opaque.
- Checked at startup and every hour. Expiry **warns** 30 days out (health
  panel, event log, console) and **runs on** through the grace period
  with a banner; after grace the install drops to Base features and
  keeps capturing. Monitoring is never cut off mid-exercise (ADR 0002).
- Offline hosts have wrong clocks. The check uses the later of the system
  clock and the last timestamp persisted in `events.db`, so turning the
  clock back does not extend a license, and a clock that is merely wrong
  degrades to a warning rather than a lockout.
- **No license at all → 30-day trial.** Full Base features with a
  "TRIAL — N days left" banner. The trial starts the first time `serve`
  runs; the start is recorded in `events.db` and floored by the same
  last-timestamp rule as expiry, so wiping the clock does not restart it
  (wiping the data directory does, which we accept: the trial is a
  convenience, not the copy protection). When the 30 days are up the
  dashboard goes **read-only** — viewers still see entities, alerts and
  the map, but ack, mute, replay and recording are disabled — and the
  banner says how to add a license. Capture, rules and the event log keep
  running: monitoring is never cut off (ADR 0002). Adding a license file
  lifts the limits without a restart at the next hourly check, or at once
  via `nn-server license FILE`.
- `seats` caps live sessions: a login past the cap gets `409 seats in
  use`; an admin can sign other sessions out. Upselling seats or tier is
  a new file, not a new install (ADR 0002).
- A vendor-only `nn-license` tool (separate crate, never in the customer
  bundle) issues and signs files and keeps a register of what was sold.

### Accounts and sessions: roles, admin from the dashboard

- Users file lines gain a role: `user:pbkdf2:salt:hash:role` with roles
  `admin` (accounts, config, license, recordings), `operator` (ack, mute,
  replay) and `viewer` (read-only). Lines without a role read as
  `operator`, so existing files keep working.
- Admins manage accounts from the dashboard (`/api/users`) so the CLI
  `passwd` is for bootstrap and recovery only. Sessions stay in memory
  (a restart signs everyone out) with the 12 h idle limit; `/api/sessions`
  lets an admin list and revoke them, which also serves the seat cap.
- Logins, sign-outs, account and config changes, license events and acks
  are already `info`/`alert` entries in the event log; `--db` makes that
  the audit log the spec asks for. The one addition is a `kind = "audit"`
  so it can be filtered and exported on its own.

### TLS stays as ADR 0006

`setup` either generates a self-signed pair for the hosts the admin
names or imports the site PKI's cert and key. Sites with their own CA
need no device setup; others trust `cert.pem` once per viewing device.
A NetworkNinja-run CA is deferred until a customer without PKI finds
that painful.

## Options considered and rejected

- **Hardware-locked licenses** (MAC/CPU id): break on VM moves and
  hardware refresh, create support load on air-gapped sites. Site-named
  licenses plus the seat cap are enough deterrent for this market.
- **License server on the customer LAN** (FlexLM-style): a second thing
  to install and keep up; overkill until Enterprise's central server
  exists, which can then take this role.
- **JWT/JOSE for the license**: pulls in a JSON stack and an alphabet of
  algorithms to get wrong; a fixed Ed25519 signature over TOML is smaller
  and matches the rest of the codebase.
- **Browser-based first-run wizard**: nicer, but the admin is at a
  console on an air-gapped host anyway, and the CLI path is needed for
  scripted installs regardless.

## Implementation checklist (milestone 7 slices)

1. `config.toml` loader using the rule-pack TOML parser; flags override.
2. `nn-server setup` and `install`/`uninstall` for Linux (systemd) first,
   then macOS and Windows.
3. `license` module: armour, Ed25519 verify against embedded keys,
   payload parse, status (valid/warning/grace/expired/trial/trial-ended),
   trial start + clock-rollback floor from `events.db`; `nn-license`
   vendor tool.
4. Health panel + `/api/health` show license status; banner states;
   read-only gate on ack/mute/replay/record when the trial has ended.
5. Seat cap in `Auth::issue`; `/api/sessions` list/revoke (admin).
6. Roles in the users file; `/api/users` (admin); dashboard account page.
7. `kind = "audit"` entries and an export.
8. Install guide for air-gapped sites and the operator runbook.

## Consequences

- Positive: the whole install is one binary plus one directory; nothing
  phones home; a site admin can set it up from the console in minutes; a
  license is human-readable and provably ours; upsells are a file.
- Negative: we own three service-manager integrations and their quirks;
  a stolen vendor signing key is a product-wide incident (keep it on
  offline hardware, rotate via key ids); in-memory sessions mean a
  service restart signs everyone out; a trial can be restarted by
  deleting the data directory, which we accept for this market.
