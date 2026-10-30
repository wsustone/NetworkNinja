# 0010: Generic DIS conformance: tiered PDU support and a conformance generator

Date: 2026-10-30 · Status: Proposed

## Context

NetworkNinja is not built for one exercise or one vendor. Many companies will point it at their
own DIS traffic to find errors from senders. That changes two things.

1. **We can't choose the PDU types.** Any of the 72 types in IEEE 1278.1 may arrive. A type we
   can't read is a type we can't check. Today we deep-decode 6 of them and check only the header
   of the rest.
2. **False alarms cost more than misses.** A tool that flags one vendor's legitimate choices gets
   uninstalled. Examples: DIS v6 instead of v7, bundling, body-axis dead reckoning,
   heartbeating while frozen, a duplicating gateway. Every check has to be proven quiet on legal
   variation, not just loud on the error.

The generator today is one ~800-line loop. It drives land vehicles in circles and injects the
faults our three behavioural rules need. It can't grow to 72 PDU types, and it has no notion of
"legal but unusual". Two generator processes can't run together either: both use sites 1…N and
application 1, so they produce genuine ID conflicts.

**Reference.** The working reference is **IEEE P1278.1/D16 Rev 18 (May 2012)**, the last draft
before the published IEEE 1278.1-2012. It is publicly hosted but marked "unapproved draft", ©
IEEE. Clause 5 holds the usage rules, clause 6 the data representation and records, clause 7 the
PDU layouts, clause 9 Live Entity, and Annex E dead reckoning. SISO-REF-010 (free from SISO)
supplies the enumerations.

## Decision

### 1. Support every PDU type, in tiers

| Tier | Checks | Scope |
| --- | --- | --- |
| **H** Header | Version, family, type, exercise, framing | All types (done) |
| **S** Structure | Length correct for the type, including records whose count the PDU declares; truncation, overrun and padding | **All 72 types**, from one table of fixed sizes and count-driven records |
| **E** Enumerations | Every enumerated field against SISO-REF-010 | Generated from SISO-REF-010; extends the pack `[[enum]]` registry |
| **D** Deep | Full decode, cross-field consistency, behavioural rules | Family by family, most common first |

Tier S is the broad, cheap win. Most real sender bugs are structural or bad enumerations, and
both can be caught in every type without deep-decoding all 72.

[docs/pdu-coverage.md](../pdu-coverage.md) lists all 72 types with their usage and layout
clauses, and tracks each type's tiers. It is updated in the same change that adds support.

### 2. Every check cites the standard

A company told "your sender is wrong" will ask "says who?". Each check carries the clause it
enforces. Clause numbers come from D16 Rev 18 and are marked as such until verified against the
published standard. The repository carries clause numbers and our own descriptions of fields. It
never carries the draft, extracted text, or copied passages.

### 3. A definition of done per PDU type

1. Decoder: structural check (S); deep decode and encode with round-trip tests when it reaches D.
2. Primary entity, so metrics, conformance attribution and capture tiers work.
3. Enumerated fields in the `[[enum]]` registry (E).
4. A capture decision: keep, thin or skip. Signal and Intercom Signal must not flood the store.
5. The generator emits it, valid and with defects.
6. A place in the dashboard: event log, entity detail, or a family view.

### 4. The generator becomes a conformance test bed

- **World (core):** clock, sites → applications → senders, entities with types and motion models,
  freeze state, seeded RNG, ground truth.
- **Families:** one module per DIS protocol family, each emitting valid PDUs of its types:
  - Entity Information/Interaction: motion models and Entity State sending.
  - Warfare: engagements with tracked munitions.
  - Radio: nets of Transmitter, Signal and Receiver.
  - Simulation Management: a manager actor with its own sender.
  - Emissions: emitters and IFF attached to platforms.
  - and so on.
- **Wire layer** (not a DIS family), between world and sink: bundling, gateway duplication,
  padding, malformed PDUs, v6/v7 mixing, sender clock skew.
- **Defect catalogue:** every check has a defect the generator can inject. Each defect is tagged
  by class (structural, enumeration, semantic, behavioural, protocol), cites its clause, and
  records its expected alert, so tests assert detection directly. The catalogue is also the
  customer-facing list of checks.
- **Vendor profiles:** named bundles of legitimate variation, e.g. v6, bundled, body-axis DR,
  5 s or 30 s heartbeats, silent when frozen, behind a gateway.

### 5. Several generators at once

Each process gets `--site-base N` and `--application N`, so separate processes don't share
entity IDs. Each process is its own set of sockets, so it looks like a separate simulator. A
scenario file (TOML) can later describe several applications with their profiles, families and
defects, for one-process reproducible runs. Two acceptance tests hold the line:

- A multi-vendor run with no defects raises **nothing**.
- The same run with defects injected raises **exactly** those defects, on the right senders.

## Order of work

1. Restructure the generator into world, families and wire, with no behaviour change: every
   existing test passes untouched. Add `--site-base` and `--application`.
2. Tier S for all 72 types, plus the generator emitting a minimal valid PDU of every type and the
   structural defects.
3. Generate SISO-REF-010 enumerations (tier E), with enumeration defects.
4. Vendor profiles and the multi-process harness: the silence and exact-detection tests.
5. Tier D family by family, most common first: Simulation Management handshakes, Radio,
   Emissions/IFF, Entity Damage Status and Collision, then the rest. Each brings its semantic
   defects.

## Options considered and rejected

- **Deep-decode everything before shipping anything.** That means months before a customer with
  Radio or IFF traffic gets any value. Tiers give every type structural checks first.
- **Keep extending the single generator loop.** It already mixes motion, emission, faults and
  wire concerns. Each new PDU type would touch all of them.
- **Fuzzed traffic instead of a defect catalogue.** Fuzzing finds decoder crashes (a cargo-fuzz
  harness is still planned for milestone 1), but it can't say which alert a defect should raise.
  The catalogue can.
- **Rely on dis-rs or Open-DIS as the layout source.** Useful cross-checks (ADR 0001), but a
  conformance tool must be traceable to the standard itself.

## Consequences

- Positive: every PDU type gets checked on day one of each tier. Each check is traceable to a
  clause and proven by a generator defect. Legitimate variation is tested as hard as errors. The
  generator becomes a product asset: a customer can see exactly what is checked and replay it.
- Negative: the coverage table and defect catalogue must be kept current. Clause numbers carry a
  "draft" caveat until checked against the published standard. Structure tables for 72 types are
  a large, careful data-entry job that needs review.
- Open:
  - **DIS v6 traffic:** layouts come from IEEE 1278.1-1995 and 1278.1a-1998, which we don't
    have. Where v7 changed a layout, v6 PDUs need their own structure entries.
  - **Published standard:** access to IEEE 1278.1-2012 is being arranged (2026-10-30). Work
    continues from D16 Rev 18 until then; once it arrives, every cited clause gets checked and
    the "draft" caveat comes off, or the citation is corrected.
  - **Vendor-specific extensions:** experimental codes 129–255 and private variable-parameter
    records get header checks only for now.
