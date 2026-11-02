# Plan: deep checks for every PDU family

ADR 0010 step 5 ("tier D"), planned family by family. It says, for each PDU type we don't yet
check in depth, which sender errors to watch for, which clause each one enforces, and what
could raise a false alarm. Then it puts the work in order.

Clause numbers are from IEEE P1278.1/D16 Rev 18 (the working draft, see ADR 0010). Heartbeat
and threshold defaults are from its symbolic-name table (6.1.8). Every check below gets its
generator fault and its "legal variation stays quiet" test in the same PR, as the step-5
families so far did. Status per type is in [pdu-coverage.md](pdu-coverage.md).

## Where we are

| Tier | Covered |
| --- | --- |
| H header and framing | all 72 types |
| S structure (lengths, counts, record lengths) | all 72 on v7; types 1–27 on v6 |
| E enumerations (SISO-REF-010) | 63 fixed-offset fields in 41 types, plus Entity State, Fire and Detonation fields |
| D deep | Entity State (timeout, ID conflict, position jump), Fire/Detonation (pairing, munition end), DE Fire, Entity Damage Status, Collision, Attribute, Electromagnetic Emission, Designator, IFF (v7), SIMAN and SIMAN-R handshakes, Radio (Transmitter / Signal / Receiver) |

Everything else is checked for shape and enumerations, but not for meaning.

## Kinds of check

Each check below is one of these. They differ in cost and in false-alarm risk.

- **Field**: one PDU on its own, for example a field that must be zero when another field has
  some value. Cheap and low-risk. Point event.
- **Lifecycle**: one object over time, for example a heartbeat, a field that must not change, or a
  final "off" PDU that must come. Needs per-object state. Point event, except timeouts, which are
  open alerts and resolve.
- **Cross-PDU**: two PDU types that must agree, for example a Detonation that must follow its Fire.
  Needs a short memory and a grace period for traffic sent before the monitor started.

Every lifecycle and cross-PDU check also needs these, the lessons from step 5 so far:

- **Grace at startup.** Never report "X never happened" until the monitor has watched for
  longer than the window in question.
- **Frozen time doesn't count.** Pause timers while the exercise or the entity is frozen.
- **Report once per kind per entity per window** (`Engine::point_event`).
- **Blame the right sender.** Use the PDU's own source. For a missing PDU, use the owner's last
  known address.
- **Thresholds and heartbeats live in `[rules.<family>]`**, at the standard's defaults, so a
  site can widen them.

## Wave 0: fix false alarms in what we already check (done)

These were found while writing this plan. Legitimate senders can trip both today.

| # | Problem | Fix | Clause |
| --- | --- | --- | --- |
| 0.1 | *Done.* Entity timeout uses one heartbeat (5 s × 2.4) for every entity. Stationary entities may heartbeat at HBT_STATIONARY (60 s), so a parked vehicle is wrongly timed out at 12 s. | Use the stationary heartbeat while the last report says DR algorithm Static (1), or shows zero velocity. Keep per-kind heartbeats in the pack (`HBT_ESPDU_*`, all 5 s by default). | 4.2.7, Table 4 |
| 0.2 | *Done.* Entity State Update isn't decoded, so an entity that heartbeats with ESUs between full Entity States is wrongly timed out. | Deep-decode ESU (67): location, velocity, orientation, appearance, variable parameters. It refreshes the entity like an Entity State and feeds position jump. | 5.3.5.3 c |

## Wave 1: Entity information and warfare

The PDUs every exercise uses. This wave has the most value.

### Entity State (1) and Entity State Update (67): what's left

| Check | Kind | Clause |
| --- | --- | --- |
| A removed entity (Remove Entity acknowledged) sends at least one final Entity State with appearance Deactivated, then stops | lifecycle | 5.6.5.3.4 |
| An entity sends again after its Deactivated report (zombie) | lifecycle | 5.3.2.3, 5.6.5.3.4 |
| DR algorithm Static (1) with non-zero velocity, or a moving algorithm reporting a stationary entity's position drifting | field | Annex E |
| Entity type changes mid-life from the same sender (a different simulator is a conflict, already caught) | lifecycle | 5.3.2.2 |
| Force ID or marking changes mid-life (warning) | lifecycle | 5.3.2 |
| Variable parameter count changes without an articulation reason; Attached Part "detached" with no Fire or separation | cross-PDU | 5.4.3.3 a)2 |
| ESU sent for an entity with no Entity State ever seen | cross-PDU | 5.3.5 |

**Generator faults:** zombie-after-deactivate, static-with-velocity, type-change, ESU-only entity.

**False-alarm risk:** marking changes are legitimate in some CGFs, so default to warning.

### Fire (2) and Detonation (3): cross-PDU

| Check | Kind | Clause |
| --- | --- | --- |
| A Detonation whose Event ID matches no Fire, for a munition that should have been fired. Exempt accidental, demolition and mine detonations, and non-munition explosions. | cross-PDU | 5.4.4.3 |
| A Fire with no Detonation within a munition time-of-flight bound (pack: `max_flight`) | cross-PDU | 5.4.4.3 a) |
| A Fire for a munition that must not be fired: mine, demolition, EOD, an IED not thrown | field | 5.4.3.3 a)9 |
| PDU Status Fire Type Indicator matches the descriptor (munition 0, expendable 1) | field | 5.4.3.3 a)7, b)1 |
| A Fire whose firing entity is unknown or deactivated | cross-PDU | 5.4.3 |
| A Detonation location far from the target entity's position while the result says "entity impact" | cross-PDU | 5.4.4 |

**Generator faults:** orphan-detonation, fire-without-detonation, mine-fired, wrong-FTI.

*Done:* rule `fire-detonation`, all six rows: `fixed-munition` (munition category Fixed, 3),
`impact-distance` (result Entity Impact more than `impact_tolerance` + speed × 1 s from the
target's dead-reckoned position). Generator `--mine-fired`, `--impact-miss`.

**False-alarm risk:** munitions that miss and are never detonated. That's why "no Detonation"
is a warning with a generous default, and is suppressed for expendables.

### Directed Energy Fire (68)

| Check | Kind | Clause |
| --- | --- | --- |
| Heartbeat HBT_PDU_DE_FIRE (0.5 s) while a shot is in progress | lifecycle | 5.4.5.3 |
| A Fire PDU immediately after the initial DE Fire | cross-PDU | 5.4.5.3 f) |
| A Detonation after the final DE Fire (weapon off) | cross-PDU | 5.4.5.3 |
| DE record lengths and DE record types valid (precision or area aimpoint) | field | 7.3.4 |

*Done:* rule `directed-energy` (`nn_rules::interactions::DirectedEnergy`): `dropout`, `no-fire`,
`no-detonation`, `second-fire`, keyed by (exercise, Event ID). A DE Fire with the weapon off
that never turned on (a minimal PDU) owes nothing. Generator `--de-every SECS`, faults
`--de-dropout`, `--de-no-fire`; `record-type` (aimpoint records only), `--bad-de-record`.

### Entity Damage Status (69)

| Check | Kind | Clause |
| --- | --- | --- |
| Heartbeat HBT_PDU_ENTITY_DAMAGE (10 s) after the first EDS while damaged | lifecycle | 5.4.6.3 |
| Final EDS with zero records when the damage is repaired | lifecycle | 5.4.6.3 e) |
| No EDS after the entity's Deactivated Entity State | cross-PDU | 5.4.6.3 |
| Entity State appearance Damage/Mobility/Firepower bits agree with EDS | cross-PDU | 5.4.6.3 e) |
| Each EDS carries all present damage records, so the count shouldn't drop without a repair | lifecycle | 5.4.6.3 d) |

*Done:* rule `entity-damage` (`after-deactivated`, `stale-appearance` after `repair_window`,
platforms only); the heartbeat is the `heartbeat` rule's. Generator `--damage-every SECS`,
faults `--stale-appearance`, `--eds-after-remove ID`; `record-type` (DE Damage Description
records only). The record-count row is dropped: 5.4.6.3 d) lets records be deleted, so a
falling count is legitimate.

### Collision (4) and Collision-Elastic (66)

| Check | Kind | Clause |
| --- | --- | --- |
| Both parties report: each Collision has a counterpart from the colliding entity within a short window (unless the colliding ID is ENTITY_ID_UNKNOWN) | cross-PDU | 5.3.3.4 |
| One and only one Collision per event per party (duplicates by Event ID) | lifecycle | 5.3.3.4 |
| Colliding entity unknown to the exercise but not ENTITY_ID_UNKNOWN | cross-PDU | 5.3.3.4 a) |
| Collision-Elastic answered by a Collision-Elastic (Newtonian state machine) | cross-PDU | 5.3.4, Table 6 |
| Collision speed below COLLISION_THRSH (0.1 m/s) (warning) | field | 6.1.8 |

*Done:* rule `collision`: `one-sided` (pinned on the silent party; only for a known, active
entity, so the "unknown" row is covered by saying nothing) and `duplicate` (per PDU type).
Generator `--collision-every SECS`, faults `--one-sided-collision`, `--duplicate-collision`;
`below-threshold` (Collision only: its issuer's velocity and the other's Entity State),
`--still-collision`. The Elastic state machine needs more design and is left for later.

### Attribute (72)

| Check | Kind | Clause |
| --- | --- | --- |
| Master Attribute Record Type equals every record's type, or MULTIPLES_PRESENT | field | 5.3.6.3 a)2)iii |
| Each Record Set holds at least one record, and records apply to that set's entity only | field | 5.3.6.3 a)2)iv |
| Coupled extension: PDU Status CEI set, bundled right after the PDU it extends, one instance | cross-PDU | 5.3.6.3 b)1 |
| Attribute Record PDU Type is a real PDU type, and Protocol Version matches the extended PDU | field | 5.3.6.3 a)2)i–ii |

*Done:* rule `attribute` (`crate::attribute`, per PDU with its bundle neighbours):
`master-type`, `empty`, `pdu-type`, `self-coupled`, `missing-extension`, `coupled-mismatch`,
`uncoupled-transient` (only state PDUs, those with a heartbeat, may be extended uncoupled).
Generator `--bad-attribute`, `--missing-extension`; coverage's minimal Attribute PDU now holds
one record.

**Left for later (needs more design):** the Entity State variable-parameter and Attached Part
row above, and the Collision-Elastic state machine.

## Wave 2: Distributed emission regeneration

Common in military exercises, and where field-level bugs are frequent.

### Electromagnetic Emission (23)

| Check | Kind | Clause |
| --- | --- | --- |
| Heartbeat HBT_PDU_EE (5 s) per emitter system, not per entity | lifecycle | 5.7.3.3.2 |
| Emitter Name, Function and Number don't change for a system during the exercise | lifecycle | 5.7.3.3.3 |
| Emitter Number isn't NO_EMITTER or ALL_EMITTERS; Beam Number isn't NO_BEAM or ALL_BEAMS | field | 5.7.3.3.3 |
| High Density Track/Jam selected means Number of Targets is 0; more targets than EE_HIGH_DENSITY_THRSH (10) should be high-density | field | 5.7.3.3.3 c) |
| Continuous wave means PRF and pulse width are both 0.0; a pulsed beam means both are non-zero | field | 5.7.3.3.3 d) |
| Track/Jam targets refer to known entities | cross-PDU | 5.7.3 |
| Enumerations inside beams: Emitter Name (UID 75), Function (76), Beam Function (78), jamming technique | field (tier E) | 7.6.2 |
| An emitter that stops without a final update ("emitter off" state) | lifecycle | 5.7.3.3 |

*Done:* rule `emission` (`nn_rules::emission`, systems keyed by exercise, entity and Emitter
Number): `dropout` (the heartbeat, per system), `identity-change`, `reserved-number`,
`duplicate-number`, `high-density`, `pulse-params`, `track-target` (NO_SITE/NO_APPLIC/NO_ENTITY,
or an unknown entity after the startup grace), `repeat-deactivated` (5.7.3.6), and
`destroyed-emitting` (5.7.3.3.3 b). EE left the generic `heartbeat` rule, which timed out an
entity rather than a system. Generator `--emission-every SECS`, faults `--emitter-dropout`,
`--emitter-rename`, `--reserved-beam`, `--dense-targets`, `--half-pulsed`, `--no-site-target`,
`--repeat-deactivated`, `--destroyed-emitting`, preset `--all-emission-faults`. The repeated
enumerations are checked with `--siso`: Emitter Name (UID 75) and Function (76) per system,
Beam Function (78) per beam (`nn_decode::fields::repeated_fields`); fault
`--bad-emitter-enums`. Still to do: jamming's Track/Jam emitter and beam numbers.

### Designator (24)

| Check | Kind | Clause |
| --- | --- | --- |
| Heartbeat HBT_PDU_DESIGNATOR (5 s) while active | lifecycle | 5.7.4.3 |
| A final Designator with Power 0 when deactivated, and when the designated entity ceases to exist | lifecycle | 5.7.4.3 |
| Designated entity D-SPOT_NO_ENTITY means the spot relative to the entity is 0, 0, 0 | field | 5.7.4.3 |
| Designated entity unknown to the exercise | cross-PDU | 5.7.4 |

*Done:* the heartbeat, and Power 0 as final, are the `heartbeat` rule's; rule `designator`
(`nn_rules::designator`) adds `spot-offset`, `unknown-target` (after the startup grace),
`stale-target` (designated entity gone, no Power 0 within `final_report_window`) and
`designator-gone` (designating entity gone with the designator on). The Dead Reckoning
Algorithm field (UID 44) is checked with `--siso`. Generator `--designator-every SECS`, faults
`--spot-offset`, `--unknown-designated`, `--target-gone`, `--designator-gone`, preset
`--all-designator-faults`.

### IFF (28): the largest set of rules in the clause (33 "shall"s)

| Check | Kind | Clause |
| --- | --- | --- |
| Heartbeat HBT_PDU_IFF (10 s), and it continues while the system is off | lifecycle | 5.7.6.3 g) |
| Layer 1 always present; only changed or heartbeat layers added | field | 5.7.6.3 b) |
| Change Indicator set on a change and on the next heartbeat, then cleared | lifecycle | 5.7.6.3 f) |
| System Type / Mode 5 / Mode S capability means the matching layer 3 or 4 is present | field | Table 166 |
| Layer header lengths and layer numbers valid (structure already checks lengths) | field | 7.6.5 |
| Mode codes inside layer 1 parameters valid for the system type (Annex B) | field | Annex B |

*Done (v7):* rule `iff` (`nn_rules::iff`, systems keyed by exercise, emitting entity, System
Type and System Designator): `layer-bits` (Information Layers vs the layers sent),
`layer-order`, `mode5-missing` / `modes-missing` (types 6, 7, 9, 10 need Layer 3; 9 and 11
Layer 4, while on; Annex B layer tables), `layer2-no-parameters`, `initial-unflagged`,
`change-unflagged`, `heartbeat-unflagged` (types 6 and up), `mode-mismatch` (System On/Off vs
System Mode), `after-deactivated` / `destroyed-on` (still On past IFF_PDU_FINAL, 10 s). The
heartbeat, continuing while off, is the `heartbeat` rule's. Enumerations: System Type, Name
and Mode (UIDs 82-84). Generator: `--iff-every SECS` (a Mark XIIA transponder), eight faults,
`--all-iff-faults`. Left: mode codes per system type (Annex B), types 12-14's layers, and
v6 (1278.1a layers differ).

### Underwater Acoustic (29) and SEES (30)

- **UA:** heartbeat HBT_PDU_UA (3 min); the emitter/beam rules mirror EE (names and numbers
  fixed for the exercise); APA parameter index and status enumerations.
- **SEES:** heartbeat HBT_PDU_SEES (3 min); a changed-data update carries only the parameters
  that crossed their thresholds (SEES_PS/RPM/NDA_THRSH); the originating entity is known.

## Wave 3: Interactions between simulations

### Logistics (5–10): a request/response protocol, like the SIMAN handshakes

| Check | Kind | Clause |
| --- | --- | --- |
| Service Request (resupply) answered by Resupply Offer from the named supplier | cross-PDU | 5.5.6.3 |
| Resupply Offer followed by Resupply Received or Resupply Cancel | cross-PDU | 5.5.7, 5.5.8 |
| Repair Complete only after a Service Request for repair; answered by Repair Response | cross-PDU | 5.5.10.3, 5.5.11.3 |
| Number of supply types 0 when the service isn't resupply | field | 5.5.5 e) |
| Supplier and receiver entities exist | cross-PDU | 5.5 |
| Supplier timers REPAR_SUP_T1/T2 and the resupply timers bound the waits | lifecycle | 5.5 |

The SIMAN tracker (`nn_rules::siman`) is the template: same pairing, same "addressed to one
entity" rule, same startup grace.

### Entity management (33–36)

| Check | Kind | Clause |
| --- | --- | --- |
| Aggregate State heartbeat HBT_PDU_AGGREGATE_STATE (30 s) for non-silent aggregates | lifecycle | 5.9.2.2.3 |
| An aggregate listing an entity that no longer sends Entity State, or a subaggregate with no Aggregate State | cross-PDU | 5.9.2.2.3 |
| Silent entity system: Number of Appearance records ≤ Number of Entities | field | 5.9.2.2.3 |
| IsGroupOf heartbeat HBT_PDU_ISGROUPOF (5 s); GED record size by Grouped Entity Category (needs SISO GED sizes, which tightens tier S) | lifecycle / field | 5.9.3 |
| Transfer Ownership: unacknowledged reliability required; Entity ID unchanged; one transaction per entity at a time; after a transfer, the new owner's sender reports the entity and the old one stops (no ID conflict should fire, and a lingering old owner is the finding) | cross-PDU | 5.9.4.2.1 |
| IsPartOf references known entities | cross-PDU | 5.9.5 |

Transfer Ownership interacts with the ID-conflict rule: a completed transfer is a legitimate
change of sender. Doing it right removes a real source of false conflict alarms.

### Simulation management with reliability: what's left

The handshakes are done. Left:

- **Retries:** acknowledged service retries at TI_TIMER1 (2 s) up to TI_TIMER2 (12 s); a
  requester that never retries, or retries forever.
- **Transaction IDs:** reused while still in flight.
- **Record-R sets:** Record-R carries the record sets the Record Query-R asked for.
- **Event Report-R:** event types valid in context.

### Intercom Signal (31) and Intercom Control (32)

These mirror Radio: an Intercom Signal needs an active intercom (Control "transmitting"), and
the Signal field rules are the same as for the Radio Signal PDU. Control commands must form a
valid sequence (5.8.7), and intercom parameter record lengths must be valid.

## Wave 4: Specialised families

Used by fewer exercises. Do them when a customer's traffic needs them.

| Family | Main checks | Clause |
| --- | --- | --- |
| Minefield (37–40) | State heartbeat HBT_PDU_MINEFIELD_STATE (5 s); sequence number starts at 1 and increments on change; in QRP mode Data only in answer to a Query, one mine type per Data, Number of PDUs and sequence numbers consistent across the response set, retransmit on NACK; Data filter bits match the arrays present (tier S already) | 5.10.2.3, 5.10.4.3.3, 5.10.5 |
| Synthetic environment (41–45) | Environmental Process heartbeat 15 s, Gridded Data 15 min; sequence numbers; Point/Linear/Areal update numbers increase; object type consistency; EP thresholds (EP_POS/DIMENSION_THRSH) | 5.11 |
| Information operations (70–71) | IO Action / IO Report pairing; IO records valid; no deactivated entity in an IO Report | 5.13.3.3, 5.13.4.3 |
| Live entity (46–50) | TSPI heartbeat HBT_PDU_TSPI (30 s), Appearance heartbeat 60 s; flag bits match the fields present (tier S already); LE Fire / LE Detonation event pairing as for Fire/Detonation; Live Entity IDs don't collide with DIS Entity IDs from the same site | 9.4 |

## Cross-cutting checks (any wave; cheap, high value)

| Check | Kind | Notes |
| --- | --- | --- |
| Per-type heartbeat registry | lifecycle | One table from 6.1.8 driving every family's timeout. The Entity State one becomes an instance of it. |
| Timestamps | lifecycle | A sender mixing absolute and relative timestamps; timestamps going backwards within one sender (allowing for the hour wrap); absolute timestamps far from receive time (clock skew); feeds the planned `sender.clock_skew` metric. |
| Exercise ID consistency | lifecycle | A sender whose PDUs suddenly carry another exercise ID, as a warning. |
| PDU Status bits per type | field | TEI, LVC, CEI, FTI, DTI, RAI, IAI: each meaningful only for some types, and must be 0 elsewhere (6.2.67). |
| References to unknown entities | cross-PDU | Target, colliding, designated and receiving IDs naming entities never seen, with grace. |
| Activity after Deactivated | cross-PDU | Any PDU issued by an entity after its Deactivated Entity State (EDS is explicit; the rest by implication). |

## Order and size

Each line is roughly one PR, sized like the radio PR, with its checks, generator faults,
silence and exact-detection tests, coverage-table update and docs.

1. **Wave 0**: stationary heartbeat and ESU decode. Small, and it fixes false alarms.
2. **Heartbeat registry** (cross-cutting): unlocks every lifecycle check that follows. *Done:*
   `nn_decode::heartbeat`, rule `heartbeat`, `[rules.heartbeat]`.
3. **Entity State lifecycle**: deactivation, zombie, static-with-velocity, type change. *Done:*
   rule `entity-lifecycle`.
4. **Fire ↔ Detonation pairing**, plus DE Fire. *Done:* rules `fire-detonation`,
   `directed-energy`.
5. **Entity Damage Status and Collision.** *Done:* rules `entity-damage`, `collision`; the
   Wave 1 wrap-up added the field checks and rule `attribute`.
6. **EE**: heartbeat per system, fixed identities, beam fields, beam enumerations. *Done*:
   rule `emission`, repeated-field enumerations.
7. **Designator, IFF.** *Done:* rules `designator`, `iff`.
8. **Logistics**, built on the SIMAN tracker.
9. **Entity management**, including Transfer Ownership and its interaction with ID conflict.
10. **Timestamps and PDU Status bits** (cross-cutting).
11. **Attribute, Intercom, UA/SEES.**
12. **Wave 4 families**, as customers need them.

## Decisions to make along the way

- **Severity defaults.** Most new findings are warnings. Proposed critical: data loss or
  misidentification (zombie entity, wrong type, an IFF layer missing for a declared mode).
- **"Should have happened" windows.** For example the Fire → Detonation time of flight. The
  standard rarely gives one, so ours are pack thresholds with generous defaults.
- **DIS v6.** These rules are from the 2012 draft. Where v6 (1998) differs, mainly IFF layers
  and the -R family, v6 traffic gets only the checks that hold for both until the 1278.1a-1998
  text is available.
- **Published standard.** Every clause and default here is from D16r18. Check them when
  IEEE 1278.1-2012 arrives.
