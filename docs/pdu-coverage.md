# DIS PDU coverage

Every PDU type in IEEE 1278.1 (v7), and how far NetworkNinja supports it (ADR 0010).
Clause numbers are from the working reference, IEEE P1278.1/D16 Rev 18 (May 2012),
the last draft before IEEE 1278.1-2012; verify against the published standard before
quoting a clause to a customer. Codes are the PDU Type field value.

Tiers: **H** header and framing checked · **S** structure (length, record counts) checked ·
**E** enumerated fields checked against SISO-REF-010 · **D** deep decode, cross-field and
behavioural checks · **G** the generator emits it, valid and with defects.

**S** is `crates/decode/src/structure.rs`: one layout per type, with its fixed size and a walk
over the counts and record lengths it declares. "✓ v7" means DIS v7 only; on v6 those types
get header checks until the IEEE 1278.1a-1998 layouts are confirmed (ADR 0010, open
questions). IsGroupOf's GED record size comes from SISO-REF-010, so until tier E its records
only have to divide the remaining length evenly. Gridded Data stops walking at a Grid Data
representation it doesn't know.

**E** is SISO-REF-010, loaded at run time with `serve --siso FILE` (the XML SISO publishes;
it is not shipped). "✓" means every enumerated field at a fixed offset is checked
(`crates/decode/src/fields.rs`, the UIDs the draft cites); fields inside variable records
(EE beams, Variable Parameters, datums) are not yet. The deep-decoded types check the fields
the decoder exposes, including entity type kind, country, platform domain and category.

**D** "handshake" means the request/answer pairing of IEEE 1278.1 5.6.5 and 5.12.4 is
checked (`crates/rules/src/siman.rs`, rule `siman-handshake`): a request to a specific
simulation must be answered within `response_timeout`, an Acknowledge must carry the right
flag, and an Acknowledge or Action Response must answer a request. Their datum records are not
decoded yet.

**D** "radio" means Transmitter, Signal and Receiver are checked against each other and over
time (`crates/rules/src/radio.rs`, rule `radio`): Signals need a transmitting Transmitter,
Transmitter and Receiver heartbeats are held to HBT_PDU_TRANSMITTER / HBT_STATIONARY /
HBT_PDU_RECEIVER, Signal fields must agree (5.8.4.3.2), a radio keeps one audio encoding, and
a radio keyed with no Signal for `idle_transmit` is flagged. Modulation parameters, antenna
patterns and frequency overlap are not checked yet.

**G** "min" means `nn-generator --all-types SECS` sends a minimal valid PDU of the type (every
count zero, optional fields absent) and `--defect KIND:TYPE` can bend it into each structural
fault; "✓" means real traffic with behaviour.

Update this table in the same change that adds support. What comes next for each type is in
[deep-check-plan.md](deep-check-plan.md).

| Code | PDU | Family | Usage | Layout | H | S | E | D | G |
| ---: | --- | --- | --- | --- | :-: | :-: | :-: | :-: | :-: |
| 1 | Entity State | Entity Information/Interaction (1) | 5.3.2 | 7.2.2 | ✓ | ✓ | partial | partial | ✓ |
| 4 | Collision | Entity Information/Interaction (1) | 5.3.3 | 7.2.3 | ✓ | ✓ | ✓ | partial | ✓ |
| 66 | Collision-Elastic | Entity Information/Interaction (1) | 5.3.4 | 7.2.4 | ✓ | ✓ v7 | – | partial | min |
| 67 | Entity State Update | Entity Information/Interaction (1) | 5.3.5 | 7.2.5 | ✓ | ✓ v7 | – | partial | ✓ |
| 72 | Attribute | Entity Information/Interaction (1) | 5.3.6 | 7.2.6 | ✓ | ✓ v7 | – | ✓ | min |
| 2 | Fire | Warfare (2) | 5.4.3 | 7.3.2 | ✓ | ✓ | partial | partial | ✓ |
| 3 | Detonation | Warfare (2) | 5.4.4 | 7.3.3 | ✓ | ✓ | partial | partial | ✓ |
| 68 | Directed Energy Fire | Warfare (2) | 5.4.5 | 7.3.4 | ✓ | ✓ v7 | ✓ | partial | ✓ |
| 69 | Entity Damage Status | Warfare (2) | 5.4.6 | 7.3.5 | ✓ | ✓ v7 | – | partial | ✓ |
| 5 | Service Request | Logistics (3) | 5.5.5 | 7.4.2 | ✓ | ✓ | ✓ | – | min |
| 6 | Resupply Offer | Logistics (3) | 5.5.6 | 7.4.3 | ✓ | ✓ | – | – | min |
| 7 | Resupply Received | Logistics (3) | 5.5.7 | 7.4.4 | ✓ | ✓ | – | – | min |
| 8 | Resupply Cancel | Logistics (3) | 5.5.8 | 7.4.5 | ✓ | ✓ | – | – | min |
| 9 | Repair Complete | Logistics (3) | 5.5.10 | 7.4.6 | ✓ | ✓ | ✓ | – | min |
| 10 | Repair Response | Logistics (3) | 5.5.11 | 7.4.7 | ✓ | ✓ | ✓ | – | min |
| 11 | Create Entity | Simulation Management (5) | 5.6.5.2 | 7.5.2 | ✓ | ✓ | – | handshake | ✓ |
| 12 | Remove Entity | Simulation Management (5) | 5.6.5.3 | 7.5.3 | ✓ | ✓ | partial | partial | ✓ |
| 13 | Start/Resume | Simulation Management (5) | 5.6.5.4 | 7.5.4 | ✓ | ✓ | partial | partial | ✓ |
| 14 | Stop/Freeze | Simulation Management (5) | 5.6.5.5 | 7.5.5 | ✓ | ✓ | partial | partial | ✓ |
| 15 | Acknowledge | Simulation Management (5) | 5.6.5.6 | 7.5.6 | ✓ | ✓ | ✓ | handshake | ✓ |
| 16 | Action Request | Simulation Management (5) | 5.6.5.7 | 7.5.7 | ✓ | ✓ | ✓ | handshake | ✓ |
| 17 | Action Response | Simulation Management (5) | 5.6.5.8 | 7.5.8 | ✓ | ✓ | ✓ | handshake | ✓ |
| 18 | Data Query | Simulation Management (5) | 5.6.5.9 | 7.5.9 | ✓ | ✓ | – | handshake | ✓ |
| 19 | Set Data | Simulation Management (5) | 5.6.5.10 | 7.5.10 | ✓ | ✓ | – | handshake | ✓ |
| 20 | Data | Simulation Management (5) | 5.6.5.11 | 7.5.11 | ✓ | ✓ | – | handshake | ✓ |
| 21 | Event Report | Simulation Management (5) | 5.6.5.12 | 7.5.12 | ✓ | ✓ | ✓ | – | min |
| 22 | Comment | Simulation Management (5) | 5.6.5.13 | 7.5.13 | ✓ | ✓ | – | – | min |
| 23 | Electromagnetic Emission | Distributed Emission Regeneration (6) | 5.7.3 | 7.6.2 | ✓ | ✓ | ✓ | – | min |
| 24 | Designator | Distributed Emission Regeneration (6) | 5.7.4 | 7.6.3 | ✓ | ✓ | ✓ | – | min |
| 29 | Underwater Acoustic | Distributed Emission Regeneration (6) | 5.7.5 | 7.6.4 | ✓ | ✓ v7 | ✓ | – | min |
| 28 | IFF | Distributed Emission Regeneration (6) | 5.7.6 | 7.6.5 | ✓ | ✓ v7 | – | – | min |
| 30 | Supplemental Emission/Entity State | Distributed Emission Regeneration (6) | 5.7.7 | 7.6.6 | ✓ | ✓ v7 | – | – | min |
| 25 | Transmitter | Radio Communications (4) | 5.8.3 | 7.7.2 | ✓ | ✓ | ✓ | radio | ✓ |
| 26 | Signal | Radio Communications (4) | 5.8.4 | 7.7.3 | ✓ | ✓ | – | radio | ✓ |
| 27 | Receiver | Radio Communications (4) | 5.8.5 | 7.7.4 | ✓ | ✓ | ✓ | radio | ✓ |
| 31 | Intercom Signal | Radio Communications (4) | 5.8.6 | 7.7.5 | ✓ | ✓ v7 | – | – | min |
| 32 | Intercom Control | Radio Communications (4) | 5.8.7 | 7.7.6 | ✓ | ✓ v7 | ✓ | – | min |
| 33 | Aggregate State | Entity Management (7) | 5.9.2.2 | 7.8.2 | ✓ | ✓ v7 | ✓ | – | min |
| 34 | IsGroupOf | Entity Management (7) | 5.9.3 | 7.8.3 | ✓ | ✓ v7 | ✓ | – | min |
| 35 | Transfer Ownership | Entity Management (7) | 5.9.4 | 7.8.4 | ✓ | ✓ v7 | ✓ | – | min |
| 36 | IsPartOf | Entity Management (7) | 5.9.5 | 7.8.5 | ✓ | ✓ v7 | – | – | min |
| 37 | Minefield State | Minefield (8) | 5.10.2 | 7.9.2 | ✓ | ✓ v7 | ✓ | – | min |
| 38 | Minefield Query | Minefield (8) | 5.10.3 | 7.9.3 | ✓ | ✓ v7 | – | – | min |
| 39 | Minefield Data | Minefield (8) | 5.10.4 | 7.9.4 | ✓ | ✓ v7 | – | – | min |
| 40 | Minefield Response NACK | Minefield (8) | 5.10.5 | 7.9.5 | ✓ | ✓ v7 | – | – | min |
| 41 | Environmental Process | Synthetic Environment (9) | 5.11.2.2 | 7.10.2 | ✓ | ✓ v7 | ✓ | – | min |
| 42 | Gridded Data | Synthetic Environment (9) | 5.11.2.3 | 7.10.3 | ✓ | ✓ v7 | ✓ | – | min |
| 43 | Point Object State | Synthetic Environment (9) | 5.11.3.2 | 7.10.4 | ✓ | ✓ v7 | ✓ | – | min |
| 44 | Linear Object State | Synthetic Environment (9) | 5.11.3.3 | 7.10.5 | ✓ | ✓ v7 | ✓ | – | min |
| 45 | Areal Object State | Synthetic Environment (9) | 5.11.3.4 | 7.10.6 | ✓ | ✓ v7 | ✓ | – | min |
| 51 | Create Entity-R | Simulation Management with Reliability (10) | 5.12.4.2 | 7.11.2 | ✓ | ✓ v7 | ✓ | handshake | min |
| 52 | Remove Entity-R | Simulation Management with Reliability (10) | 5.12.4.3 | 7.11.3 | ✓ | ✓ v7 | ✓ | handshake | min |
| 53 | Start/Resume-R | Simulation Management with Reliability (10) | 5.12.4.4 | 7.11.4 | ✓ | ✓ v7 | ✓ | handshake | min |
| 54 | Stop/Freeze-R | Simulation Management with Reliability (10) | 5.12.4.5 | 7.11.5 | ✓ | ✓ v7 | ✓ | handshake | min |
| 55 | Acknowledge-R | Simulation Management with Reliability (10) | 5.12.4.6 | 7.11.6 | ✓ | ✓ v7 | ✓ | handshake | min |
| 56 | Action Request-R | Simulation Management with Reliability (10) | 5.12.4.7 | 7.11.7 | ✓ | ✓ v7 | ✓ | handshake | min |
| 57 | Action Response-R | Simulation Management with Reliability (10) | 5.12.4.8 | 7.11.8 | ✓ | ✓ v7 | ✓ | handshake | min |
| 58 | Data Query-R | Simulation Management with Reliability (10) | 5.12.4.9 | 7.11.9 | ✓ | ✓ v7 | ✓ | handshake | min |
| 59 | Set Data-R | Simulation Management with Reliability (10) | 5.12.4.10 | 7.11.10 | ✓ | ✓ v7 | ✓ | handshake | min |
| 60 | Data-R | Simulation Management with Reliability (10) | 5.12.4.11 | 7.11.11 | ✓ | ✓ v7 | ✓ | handshake | min |
| 61 | Event Report-R | Simulation Management with Reliability (10) | 5.12.4.12 | 7.11.12 | ✓ | ✓ v7 | ✓ | – | min |
| 62 | Comment-R | Simulation Management with Reliability (10) | 5.12.4.13 | 7.11.13 | ✓ | ✓ v7 | – | – | min |
| 63 | Record-R | Simulation Management with Reliability (10) | 5.12.4.16 | 7.11.16 | ✓ | ✓ v7 | ✓ | handshake | min |
| 64 | Set Record-R | Simulation Management with Reliability (10) | 5.12.4.15 | 7.11.15 | ✓ | ✓ v7 | ✓ | handshake | min |
| 65 | Record Query-R | Simulation Management with Reliability (10) | 5.12.4.14 | 7.11.14 | ✓ | ✓ v7 | ✓ | handshake | min |
| 70 | IO Action | Information Operations (13) | 5.13.3 | 7.12.2 | ✓ | ✓ v7 | ✓ | – | min |
| 71 | IO Report | Information Operations (13) | 5.13.4 | 7.12.3 | ✓ | ✓ v7 | ✓ | – | min |
| 46 | TSPI | Live Entity (11) | 9.4.2 | 9.4.2.5 | ✓ | ✓ v7 | – | – | min |
| 47 | Appearance | Live Entity (11) | 9.4.3 | 9.4.3.5 | ✓ | ✓ v7 | – | – | min |
| 48 | Articulated Parts | Live Entity (11) | 9.4.4 | 9.4.4.5 | ✓ | ✓ v7 | – | – | min |
| 49 | LE Fire | Live Entity (11) | 9.4.5 | 9.4.5.6 | ✓ | ✓ v7 | – | – | min |
| 50 | LE Detonation | Live Entity (11) | 9.4.6 | 9.4.6.8 | ✓ | ✓ v7 | – | – | min |

Not listed: the Non-Real-Time protocol (family 12, clause 8) reuses the PDUs above under
its own time management rules. Codes 129–255 are reserved for experimental PDUs; they get
header checks only.
