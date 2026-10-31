//! Electromagnetic Emission (ADR 0010 Wave 2; IEEE 1278.1 5.7.3), on raw
//! PDU bytes: emitter systems keyed by (exercise, emitting entity, Emitter
//! Number), each with its own heartbeat (5.7.3.3.2 e). Findings, all point
//! events of the `emission` rule:
//!
//! - `dropout`: an active system (one with an active beam) with no EE PDU
//!   for HBT_PDU_EE x HBT_TIMEOUT_MPLIER; a system goes inactive with an EE
//!   PDU whose beams are Deactivated (5.7.3.6).
//! - `identity-change`: a system's Emitter Name or Function changes
//!   (5.7.3.3.3 e 2-3).
//! - `reserved-number`: Emitter Number NO_EMITTER / ALL_EMITTERS, or Beam
//!   Number NO_BEAM / ALL_BEAMS (e 4, e 6).
//! - `duplicate-number`: two systems with one Emitter Number in a PDU, or
//!   two beams with one Beam Number in a system (e 4).
//! - `high-density`: High Density Track/Jam selected with targets listed, or
//!   more than EE_HIGH_DENSITY_THRSH targets listed without it (c, 5.7.3.7).
//! - `pulse-params`: exactly one of PRF and pulse width is zero; continuous
//!   wave is both zero (d).
//! - `track-target`: a Track/Jam record naming NO_SITE, NO_APPLIC or
//!   NO_ENTITY (e 10), or, once the monitor has watched a while, an entity
//!   the exercise doesn't know (5.7.3.7).
//! - `repeat-deactivated`: a beam reported Deactivated twice in a row; it is
//!   reported once, then left out until active again (5.7.3.6).
//! - `destroyed-emitting`: a platform whose appearance says Destroyed still
//!   has active beams after a heartbeat timeout (5.7.3.3.3 b).

use crate::interactions::Finding;
use nn_decode::EntityId;
use nn_state::{EntityKey, EntityTable};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

pub const EE: u8 = 23;
/// NO_EMITTER / NO_BEAM and ALL_EMITTERS / ALL_BEAMS (6.1.8).
const RESERVED: [u8; 2] = [0, 0xFF];
const SYSTEM_HEADER: usize = 20;
const BEAM_HEADER: usize = 52;
const TRACK_JAM: usize = 8;
/// Appearance Damage (bits 3-4) value Destroyed.
const DESTROYED: u32 = 3;

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn f32_at(b: &[u8], at: usize) -> Option<f32> {
    Some(f32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

#[derive(Debug, Clone)]
struct System {
    name: u16,
    function: u8,
    source: SocketAddr,
    last_seen: f64,
    /// Beam Number -> Deactivated, as last reported.
    beams: HashMap<u8, bool>,
    reported_silent: bool,
    /// When the monitor first saw the entity Destroyed, while this system
    /// was active.
    destroyed_since: Option<f64>,
    reported_destroyed: bool,
}

impl System {
    fn active(&self) -> bool {
        self.beams.values().any(|&off| !off)
    }
}

/// Thresholds the tracker needs from the rule config.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// HBT_PDU_EE, seconds.
    pub heartbeat: f64,
    /// HBT_TIMEOUT_MPLIER.
    pub multiplier: f64,
    /// EE_HIGH_DENSITY_THRSH, targets per beam.
    pub high_density: u8,
    /// Seconds to watch before judging track/jam targets unknown.
    pub grace: f64,
}

#[derive(Debug, Default)]
pub struct Emissions {
    systems: HashMap<(u8, EntityId, u8), System>,
    started: Option<f64>,
}

impl Emissions {
    /// An EE PDU's bytes.
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        table: &EntityTable,
        limits: &Limits,
    ) -> Vec<Finding> {
        let (Some(&exercise), Some(&EE), Some(entity), Some(&n_systems)) =
            (pdu.get(1), pdu.get(2), id_at(pdu, 12), pdu.get(25))
        else {
            return Vec::new();
        };
        let started = *self.started.get_or_insert(now);
        let key = EntityKey { exercise, id: entity };
        let mut out = Vec::new();
        let mut finding = |kind, message: String| {
            out.push(Finding {
                kind,
                key,
                sender: source,
                message: format!("{entity} emitter {message}"),
            })
        };
        let mut numbers = HashSet::new();
        let mut at = 28;
        for _ in 0..n_systems {
            let (Some(&n_beams), Some(name), Some(&function), Some(&number)) =
                (pdu.get(at + 1), u16_at(pdu, at + 4), pdu.get(at + 6), pdu.get(at + 7))
            else {
                break;
            };
            if RESERVED.contains(&number) {
                finding(
                    "reserved-number",
                    format!(
                        "number {number}: NO_EMITTER (0) and ALL_EMITTERS (255) can't number a system{}",
                        cite("5.7.3.3.3 e)4)")
                    ),
                );
            }
            if !numbers.insert(number) {
                finding(
                    "duplicate-number",
                    format!(
                        "number {number}: two emitter systems with this number in one EE PDU; each is unique for the entity{}",
                        cite("5.7.3.3.3 e)4)")
                    ),
                );
            }
            let sys = self.systems.entry((exercise, entity, number)).or_insert(System {
                name,
                function,
                source,
                last_seen: now,
                beams: HashMap::new(),
                reported_silent: false,
                destroyed_since: None,
                reported_destroyed: false,
            });
            if sys.name != name || sys.function != function {
                finding(
                    "identity-change",
                    format!(
                        "{number}: Emitter Name {} / Function {} became {name} / {function}; both stay fixed for the exercise{}",
                        sys.name,
                        sys.function,
                        cite("5.7.3.3.3 e)2-3)")
                    ),
                );
                sys.name = name;
                sys.function = function;
            }
            sys.source = source;
            sys.last_seen = now;
            sys.reported_silent = false;
            let mut beam_numbers = HashSet::new();
            let mut b = at + SYSTEM_HEADER;
            for _ in 0..n_beams {
                let (Some(&beam), Some(prf), Some(pw), Some(&targets), Some(&dense), Some(&status)) = (
                    pdu.get(b + 1),
                    f32_at(pdu, b + 16),
                    f32_at(pdu, b + 20),
                    pdu.get(b + 45),
                    pdu.get(b + 46),
                    pdu.get(b + 47),
                ) else {
                    // Tier S reports a short PDU.
                    return out;
                };
                let tag = format!("{number} beam {beam}");
                if RESERVED.contains(&beam) {
                    finding(
                        "reserved-number",
                        format!(
                            "{tag}: NO_BEAM (0) and ALL_BEAMS (255) can't number a beam{}",
                            cite("5.7.3.3.3 e)6)")
                        ),
                    );
                }
                if !beam_numbers.insert(beam) {
                    finding(
                        "duplicate-number",
                        format!("{tag}: two beams with this number in one system{}", cite("7.6.2")),
                    );
                }
                if dense == 1 && targets != 0 {
                    finding(
                        "high-density",
                        format!(
                            "{tag}: High Density Track/Jam is Selected, so Number of Targets must be 0 and no Track/Jam records follow, but it lists {targets}{}",
                            cite("5.7.3.7 a)")
                        ),
                    );
                } else if dense == 0 && targets > limits.high_density {
                    finding(
                        "high-density",
                        format!(
                            "{tag}: {targets} targets, more than EE_HIGH_DENSITY_THRSH ({}); select High Density Track/Jam instead{}",
                            limits.high_density,
                            cite("5.7.3.3.3 c)")
                        ),
                    );
                }
                if (prf == 0.0) != (pw == 0.0) {
                    finding(
                        "pulse-params",
                        format!(
                            "{tag}: PRF {prf} Hz with pulse width {pw} µs; continuous wave is both 0.0, a pulsed beam has both{}",
                            cite("5.7.3.3.3 d)")
                        ),
                    );
                }
                for t in 0..targets as usize {
                    let Some(target) = id_at(pdu, b + BEAM_HEADER + TRACK_JAM * t) else {
                        return out;
                    };
                    if target.site == 0 || target.application == 0 || target.entity == 0 {
                        finding(
                            "track-target",
                            format!(
                                "{tag}: Track/Jam target {target} uses NO_SITE, NO_APPLIC or NO_ENTITY{}",
                                cite("5.7.3.3.3 e)10)")
                            ),
                        );
                    } else if now - started >= limits.grace && table.get(&EntityKey { exercise, id: target }).is_none()
                    {
                        finding(
                            "track-target",
                            format!(
                                "{tag}: Track/Jam target {target} isn't an entity in the exercise{}",
                                cite("5.7.3.7")
                            ),
                        );
                    }
                }
                let off = status & 1 == 1;
                if off && sys.beams.get(&beam) == Some(&true) {
                    finding(
                        "repeat-deactivated",
                        format!(
                            "{tag}: reported Deactivated again; a beam is reported Deactivated once, then left out until it is active{}",
                            cite("5.7.3.6")
                        ),
                    );
                }
                sys.beams.insert(beam, off);
                b += BEAM_HEADER + TRACK_JAM * targets as usize;
            }
            if !sys.active() {
                sys.destroyed_since = None;
            }
            at = b;
        }
        out
    }

    /// Silent active systems and destroyed entities still emitting; forget
    /// long-dead systems. Frozen time doesn't count: `frozen(exercise, id)`.
    pub fn expire(
        &mut self,
        now: f64,
        limits: &Limits,
        table: &EntityTable,
        frozen: impl Fn(u8, EntityId) -> bool,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        let timeout = limits.heartbeat * limits.multiplier;
        self.systems.retain(|&(exercise, entity, number), sys| {
            let key = EntityKey { exercise, id: entity };
            let Some(rec) = table.get(&key).filter(|r| !r.removed && !r.deactivated()) else {
                // The entity is gone: so are its emitters.
                return false;
            };
            if frozen(exercise, entity) {
                sys.last_seen = now;
                sys.destroyed_since = sys.destroyed_since.map(|_| now);
                return true;
            }
            let silent = now - sys.last_seen;
            let mut push = |kind, message: String| {
                out.push(Finding {
                    kind,
                    key,
                    sender: sys.source,
                    message: format!("{entity} emitter {number}: {message}"),
                })
            };
            if sys.active() && silent > timeout && !sys.reported_silent {
                sys.reported_silent = true;
                push(
                    "dropout",
                    format!(
                        "active, but no EE PDU for {silent:.1} s (HBT_PDU_EE {} s × {}); end emissions with a Deactivated beam{}",
                        limits.heartbeat,
                        limits.multiplier,
                        cite("5.7.3.3.2 e), 5.7.3.6")
                    ),
                );
            }
            let destroyed = rec.entity_type.kind == 1 && (rec.appearance >> 3) & 0b11 == DESTROYED;
            if destroyed && sys.active() {
                let since = *sys.destroyed_since.get_or_insert(now);
                if now - since > timeout && !sys.reported_destroyed {
                    sys.reported_destroyed = true;
                    push(
                        "destroyed-emitting",
                        format!(
                            "the entity is Destroyed, but this system still has active beams {:.0} s later; turn them off with a final EE PDU{}",
                            now - since,
                            cite("5.7.3.3.3 b)")
                        ),
                    );
                }
            } else {
                sys.destroyed_since = None;
                sys.reported_destroyed = false;
            }
            silent < 600.0
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_decode::{
        DeadReckoning, DisTimestamp, EntityState, EntityType, EulerAngles, Marking, Pdu, PduBody, PduHeader, Vec3f,
        WorldCoord,
    };

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const E: EntityId = EntityId::new(1, 1, 1);
    const T: EntityId = EntityId::new(2, 1, 1);
    const LIMITS: Limits = Limits {
        heartbeat: 5.0,
        multiplier: 2.4,
        high_density: 10,
        grace: 0.0,
    };

    #[derive(Clone)]
    struct Beam {
        number: u8,
        prf: f32,
        pw: f32,
        dense: u8,
        off: bool,
        targets: Vec<EntityId>,
    }

    fn beam(number: u8) -> Beam {
        Beam {
            number,
            prf: 1000.0,
            pw: 1.0,
            dense: 0,
            off: false,
            targets: vec![T],
        }
    }

    /// An EE PDU from E: per system (number, name, beams).
    fn ee(systems: &[(u8, u16, Vec<Beam>)]) -> Vec<u8> {
        let mut b = vec![0u8; 28];
        b[0] = 7;
        b[1] = 1;
        b[2] = EE;
        b[12..18].copy_from_slice(&[0, 1, 0, 1, 0, 1]);
        b[25] = systems.len() as u8;
        for (number, name, beams) in systems {
            let mut s = vec![0u8; SYSTEM_HEADER];
            s[1] = beams.len() as u8;
            s[4..6].copy_from_slice(&name.to_be_bytes());
            s[6] = 1;
            s[7] = *number;
            for bm in beams {
                let mut r = vec![0u8; BEAM_HEADER];
                r[1] = bm.number;
                r[16..20].copy_from_slice(&bm.prf.to_be_bytes());
                r[20..24].copy_from_slice(&bm.pw.to_be_bytes());
                r[45] = bm.targets.len() as u8;
                r[46] = bm.dense;
                r[47] = bm.off as u8;
                for t in &bm.targets {
                    for v in [t.site, t.application, t.entity] {
                        r.extend(v.to_be_bytes());
                    }
                    r.extend([0, 0]);
                }
                s.extend(r);
            }
            s[0] = (s.len() / 4) as u8;
            b.extend(s);
        }
        b
    }

    fn table(appearance: u32) -> EntityTable {
        let mut t = EntityTable::default();
        for id in [E, T] {
            t.apply(
                0.0,
                src(),
                &Pdu {
                    header: PduHeader::new(7, 1, 1, DisTimestamp(0)),
                    body: PduBody::EntityState(EntityState {
                        entity_id: id,
                        force_id: 1,
                        entity_type: EntityType {
                            kind: 1,
                            ..Default::default()
                        },
                        alternative_entity_type: EntityType::default(),
                        linear_velocity: Vec3f::default(),
                        location: WorldCoord::default(),
                        orientation: EulerAngles::default(),
                        appearance: if id == E { appearance } else { 0 },
                        dead_reckoning: DeadReckoning {
                            algorithm: 1,
                            ..Default::default()
                        },
                        marking: Marking::ascii("T"),
                        capabilities: 0,
                        variable_parameters: Vec::new(),
                    }),
                },
            );
        }
        t
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn an_emitter_told_right_is_silent() {
        let t = table(0);
        let mut e = Emissions::default();
        let mut found = Vec::new();
        let mut now = 0.0;
        while now < 30.0 {
            found.extend(e.observe(now, src(), &ee(&[(1, 100, vec![beam(1), beam(2)])]), &t, &LIMITS));
            found.extend(e.expire(now + 4.0, &LIMITS, &t, |_, _| false));
            now += 5.0;
        }
        // Off: one Deactivated report, then silence.
        let off = Beam { off: true, ..beam(1) };
        let off2 = Beam { off: true, ..beam(2) };
        found.extend(e.observe(now, src(), &ee(&[(1, 100, vec![off, off2])]), &t, &LIMITS));
        found.extend(e.expire(now + 100.0, &LIMITS, &t, |_, _| false));
        // Continuous wave, high density with no targets.
        let cw = Beam {
            prf: 0.0,
            pw: 0.0,
            dense: 1,
            targets: vec![],
            ..beam(3)
        };
        found.extend(e.observe(200.0, src(), &ee(&[(2, 200, vec![cw])]), &t, &LIMITS));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn each_field_rule_is_named() {
        let t = table(0);
        let one = |b: Beam| -> Vec<String> {
            let mut e = Emissions::default();
            kinds(&e.observe(0.0, src(), &ee(&[(1, 100, vec![b])]), &t, &LIMITS))
                .into_iter()
                .map(String::from)
                .collect()
        };
        assert_eq!(one(beam(0)), ["reserved-number"]);
        assert_eq!(one(Beam { pw: 0.0, ..beam(1) }), ["pulse-params"]);
        assert_eq!(one(Beam { dense: 1, ..beam(1) }), ["high-density"]);
        assert_eq!(
            one(Beam {
                targets: vec![T; 11],
                ..beam(1)
            }),
            ["high-density"]
        );
        assert_eq!(
            one(Beam {
                targets: vec![EntityId::new(2, 0, 1)],
                ..beam(1)
            }),
            ["track-target"]
        );
        assert_eq!(
            one(Beam {
                targets: vec![EntityId::new(9, 9, 9)],
                ..beam(1)
            }),
            ["track-target"]
        );
        let mut e = Emissions::default();
        let pdu = ee(&[(255, 100, vec![beam(1), beam(1)]), (255, 100, vec![beam(2)])]);
        assert_eq!(
            kinds(&e.observe(0.0, src(), &pdu, &t, &LIMITS)),
            [
                "reserved-number",
                "duplicate-number",
                "reserved-number",
                "duplicate-number"
            ]
        );
    }

    #[test]
    fn lifecycle_rules_are_named_once() {
        let t = table(0);
        let mut e = Emissions::default();
        e.observe(0.0, src(), &ee(&[(1, 100, vec![beam(1)])]), &t, &LIMITS);
        assert_eq!(
            kinds(&e.observe(5.0, src(), &ee(&[(1, 101, vec![beam(1)])]), &t, &LIMITS)),
            ["identity-change"]
        );
        assert!(e.expire(16.0, &LIMITS, &t, |_, _| false).is_empty());
        assert_eq!(kinds(&e.expire(18.0, &LIMITS, &t, |_, _| false)), ["dropout"]);
        assert!(e.expire(19.0, &LIMITS, &t, |_, _| false).is_empty());
        // Frozen time doesn't count.
        let mut e = Emissions::default();
        e.observe(0.0, src(), &ee(&[(1, 100, vec![beam(1)])]), &t, &LIMITS);
        assert!(e.expire(100.0, &LIMITS, &t, |_, _| true).is_empty());
        assert!(e.expire(105.0, &LIMITS, &t, |_, _| false).is_empty());
        // Deactivated twice.
        let off = Beam { off: true, ..beam(1) };
        e.observe(110.0, src(), &ee(&[(1, 100, vec![off.clone()])]), &t, &LIMITS);
        assert_eq!(
            kinds(&e.observe(115.0, src(), &ee(&[(1, 100, vec![off])]), &t, &LIMITS)),
            ["repeat-deactivated"]
        );
    }

    #[test]
    fn destroyed_entities_turn_their_emitters_off() {
        let t = table(DESTROYED << 3);
        let mut e = Emissions::default();
        let mut found = Vec::new();
        for i in 0..6 {
            let now = 5.0 * i as f64;
            found.extend(e.observe(now, src(), &ee(&[(1, 100, vec![beam(1)])]), &t, &LIMITS));
            found.extend(e.expire(now + 1.0, &LIMITS, &t, |_, _| false));
        }
        assert_eq!(kinds(&found), ["destroyed-emitting"]);
    }
}
