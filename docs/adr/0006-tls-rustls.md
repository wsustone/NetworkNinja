# 0006: TLS via rustls + self-signed certs

Status: accepted

## Context

Milestone 4's exit test wants "TLS and local accounts for several
viewers." Local accounts landed first (0005-era `--users` file, token
sessions, per-user attribution) — but credentials and session tokens
ride plaintext HTTP/WebSocket today. LAN-only is acceptable for field
use; shipping a product asks for `wss://`.

The server is a hand-rolled HTTP/1.1 + RFC 6455 stack over raw
`TcpStream` — there is no hyper/axum underneath to enable TLS "for
free." Whatever we pick must wrap our own streams.

## Options

- **rustls + rustls-pemfile + rcgen** — pure-Rust TLS: accept
  `TcpStream` → `rustls::ServerConnection` → `StreamOwned` implements
  `Read+Write`, so `handle_conn`/`ws_serve` become generic over the
  stream type. `rcgen` powers an `nn-server cert FILE` subcommand that
  emits a self-signed cert+key pair for field use; real deployments
  bring their own PEMs via `--cert/--key`.
  Pros: single-binary, air-gap-safe, no OpenSSL; certs are files the
  operator controls. Cons: second/third/fourth external crates;
  ring/aws-lc carry C/asm crypto (ends the "pure Rust" claim); we own
  cert lifecycle (expiry, rotation).
- **native-tls** — OS TLS (Schannel/Secure Transport/OpenSSL).
  Pros: platform trust stores. Cons: per-OS linkage nightmares on
  air-gapped hosts; cert handling differs per platform. Rejected.
- **Reverse proxy only** — nginx/Caddy/stunnel in front. Pros: zero
  code. Cons: fails the exit test; operators without existing
  infrastructure can't deploy; auth-deferral smell. Rejected.
- **Do nothing / document plaintext** — rejected: tokens and ack
  attribution are already worth protecting.

## Decision

rustls + rustls-pemfile + rcgen. `serve --cert FILE --key FILE` enables
TLS on the same port (HTTPS + WSS; the page already upgrades to `wss`
when loaded over `https`). No TLS → unchanged behavior.

Implementation checklist (next slice):

1. deps: `rustls` (aws-lc-rs default), `rustls-pemfile`, `rcgen`
2. `web.rs`: `handle_conn`/`ws_serve`/`read_request`/`read_frame`
   generic over `S: Read + Write`
3. `main.rs`: `--cert/--key` flags → `rustls::ServerConfig` → wrap each
   accepted `TcpStream` in `StreamOwned` before `handle_conn`
4. `nn-server cert OUT` subcommand → self-signed PEM pair via rcgen
5. Tests: handshake over `wss` via a local cert; plaintext still works
   without `--cert`

## Consequences

- Positive: meets the M4 exit test; single-binary story intact;
  `wss` protects tokens and creds; cert tooling included.
- Negative: three crates + crypto audit surface; cert expiry is ours;
  no mTLS/client certs (later if needed).
