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
- Runtime files (`events.db*`, `events.jsonl`) are gitignored — don't
  re-add them. Don't commit them.
- Dashboard = port 8080 (or `--http`); live UDP capture commonly on 3000;
  test instances on 3008/3009 + 8098/8099.

## Common run

```sh
./target/release/nn-server serve --port 3000 --db events.db --runs .
./target/release/nn-generator --target 127.0.0.1:3000 --duration 600 \
  --all-faults --all-controls --fire-every 10
```

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

## Architecture map

`crates/` — capture (UDP/pcap), decode (DIS codec), state (entities+geo),
rules (alert engine+packs), recorder (.nnrec), server (`web.rs` hand-rolled
HTTP/WS + `store.rs` SQLite + `auth.rs` accounts + `main.rs` CLI),
generator (synthetic traffic). Decisions in `docs/adr/`, spec in
`docs/spec.md`. Dashboard is the single-file `web/index.html` compiled
into the binary via `include_str!` — restart `serve` to pick up edits.
