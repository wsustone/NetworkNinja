# 0003: Rules are data, delivered as rule packs

Date: 2026-10-28 · Status: Accepted

## Context

Every DIS PDU family has its own valid values and behaviour, enumerations change with each SISO-REF-010 release, and customers need site-specific checks. Hard-coding rules would force a product release for every change.

## Decision

Express rules as declarative, versioned, signed rule packs loaded at startup:

- The base DIS pack covers every PDU type in v6 and v7. Enumeration checks are generated from SISO-REF-010; structural and behavioural rules are hand-authored from IEEE 1278.1/1278.2.
- Packs layer: standard pack → exercise profile → site overrides.
- HLA packs are generated later from FOM XML; custom message-set packs are a licensed add-on.

## Consequences

- New rules and SISO updates ship as pack updates, not new builds.
- Every alert can cite the pack and rule that fired, which also powers the conformance view.
- Decided: packs are a small TOML subset parsed with no dependencies (docs/rule-packs.md). Still open: whether to adopt or extend an existing schema, and compiling packs to a binary form.
- Open: whether SISO terms allow redistributing SISO-REF-010 data inside packs.
