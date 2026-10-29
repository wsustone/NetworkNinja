# 0001: Rust, with dis-rs for decoding

Date: 2026-10-28 · Status: Accepted, amended (see addendum)

## Context

The monitor must decode high PDU rates without drops, ship as one self-contained binary for air-gapped sites, and survive malformed or hostile input. Writing a DIS parser from scratch is slow and error-prone.

## Decision

Build the server side in Rust. Use the dis-rs crate for DIS v6/v7 decoding. Skip a Python prototype; milestone 1 produces a working console tool directly.

## Consequences

- Single static binary, memory safety and predictable performance.
- Dependency risk: dis-rs must cover every DIS v6 and v7 PDU type at least to header level. Verify in milestone 1; fall back to a thin custom decoder for headers and the six deep-decoded PDUs if needed.
- dis-rs's license must allow commercial distribution. Check before the first release.

## Addendum, 2026-10-28: in-house codec for milestone 1

The first build environment could not reach crates.io, so milestone 1 uses a small in-house codec (`crates/decode`) with no dependencies: the header for every PDU type plus full encode/decode of the six deep-decoded PDUs. This is the fallback named above, built early.

It keeps the same public shape a dis-rs wrapper would have, so the choice stays open. Next step: when dis-rs is available, cross-check both decoders against the same captures and keep whichever covers more PDU types reliably. A wrapper may still use dis-rs for the PDU types the in-house codec does not deep-decode.
