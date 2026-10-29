# 0001: Rust, with dis-rs for decoding

Date: 2026-10-28 · Status: Accepted

## Context

The monitor must decode high PDU rates without drops, ship as one self-contained binary for air-gapped sites, and survive malformed or hostile input. Writing a DIS parser from scratch is slow and error-prone.

## Decision

Build the server side in Rust. Use the dis-rs crate for DIS v6/v7 decoding. Skip a Python prototype; milestone 1 produces a working console tool directly.

## Consequences

- Single static binary, memory safety and predictable performance.
- Dependency risk: dis-rs must cover every DIS v6 and v7 PDU type at least to header level. Verify in milestone 1; fall back to a thin custom decoder for headers and the six deep-decoded PDUs if needed.
- dis-rs's license must allow commercial distribution. Check before the first release.
