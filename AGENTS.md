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
FILE` — plaintext until TLS (ADR 0006).

## Architecture map

`crates/` — capture (UDP/pcap), decode (DIS codec), state (entities+geo),
rules (alert engine+packs), recorder (.nnrec), server (`web.rs` hand-rolled
HTTP/WS + `store.rs` SQLite + `auth.rs` accounts + `main.rs` CLI),
generator (synthetic traffic). Decisions in `docs/adr/`, spec in
`docs/spec.md`. Dashboard is the single-file `web/index.html` compiled
into the binary via `include_str!` — restart `serve` to pick up edits.
