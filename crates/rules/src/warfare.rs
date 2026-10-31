//! Fire and Detonation (ADR 0010 Wave 1; IEEE 1278.1 5.4.3, 5.4.4): does
//! each engagement's story hold together? A Fire and its Detonation share an
//! Event ID.
//!
//! Findings, all point events of the `fire-detonation` rule:
//! - *no detonation*: a munition Fire whose Detonation hasn't come within
//!   `max_flight` (5.4.4.3). Expendables (PDU Status FTI 1) are exempt.
//! - *no fire*: a munition Detonation whose Event ID matches no Fire, from a
//!   real firing entity with a real event number, once the monitor has
//!   watched for `max_flight`. Mines, demolitions and accidental detonations
//!   legitimately have none (5.4.3.3 a 9), so the message names them.
//! - *mismatch*: a Detonation whose firing entity or munition type differs
//!   from its Fire's.
//! - *type indicator*: PDU Status FTI/DTI saying munition while the
//!   descriptor's type is an expendable (kind 8), or expendable while it's a
//!   munition (kind 2) (5.4.3.3 a 7, b 1; v7 only: v6 has no PDU Status).
//! - *unknown firer*: a Fire from an entity the exercise hasn't seen, or
//!   one that is deactivated, once the monitor has watched a stationary
//!   timeout.
//! - *fixed munition*: a Fire for a munition of category Fixed (3): mines
//!   and demolitions aren't fired (5.4.3.3 a 9).
//! - *impact distance*: a Detonation with result Entity Impact (1) far from
//!   its target's dead-reckoned position (5.4.4).

use nn_decode::{Detonation, EntityId, EntityType, EventId, Fire};
use nn_state::{extrapolate, geo, EntityKey, EntityTable};
use std::collections::HashMap;
use std::net::SocketAddr;

const KIND_MUNITION: u8 = 2;
const KIND_EXPENDABLE: u8 = 8;
/// Munition Category Fixed (SISO UID 15): mines, demolitions.
const CATEGORY_FIXED: u8 = 3;
/// Detonation Result Entity Impact (SISO UID 62).
const RESULT_ENTITY_IMPACT: u8 = 1;

#[derive(Debug, Clone)]
struct Shot {
    at: f64,
    firing: EntityId,
    munition_type: EntityType,
    source: SocketAddr,
    expendable: bool,
    detonated: bool,
}

/// A warfare finding, for the engine to raise.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub key: EntityKey,
    pub sender: SocketAddr,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Warfare {
    shots: HashMap<(u8, EventId), Shot>,
    started: Option<f64>,
}

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn real(id: &EntityId) -> bool {
    let ok = |v: u16| v != 0 && v != 0xffff;
    ok(id.site) && ok(id.application) && ok(id.entity)
}

fn event(e: &EventId) -> String {
    format!("{}:{}:{}", e.site, e.application, e.event_number)
}

/// The FTI/DTI bits of a v7 PDU Status byte (bits 4-5).
fn indicator(version: u8, status: u8) -> Option<u8> {
    (version >= 7).then_some((status >> 4) & 0b11)
}

impl Warfare {
    /// A Fire PDU. `grace` is how long to watch before judging firers.
    #[allow(clippy::too_many_arguments)]
    pub fn fire(
        &mut self,
        now: f64,
        source: SocketAddr,
        exercise: u8,
        (version, status): (u8, u8),
        f: &Fire,
        table: &EntityTable,
        grace: f64,
    ) -> Vec<Finding> {
        let started = *self.started.get_or_insert(now);
        let key = EntityKey {
            exercise,
            id: f.firing_entity,
        };
        let mut out = Vec::new();
        let finding = |kind, message: String| Finding {
            kind,
            key,
            sender: source,
            message: format!("{} fire, event {}: {message}", f.firing_entity, event(&f.event_id)),
        };
        let kind = f.descriptor.munition_type.kind;
        let fti = indicator(version, status);
        match fti {
            Some(0) if kind == KIND_EXPENDABLE => out.push(finding(
                "type-indicator",
                format!(
                    "PDU Status says munition, but the type is an expendable (kind 8){}",
                    cite("5.4.3.3 a)7")
                ),
            )),
            Some(1) if kind == KIND_MUNITION => out.push(finding(
                "type-indicator",
                format!(
                    "PDU Status says expendable, but the type is a munition (kind 2){}",
                    cite("5.4.3.3 b)1")
                ),
            )),
            _ => {}
        }
        if kind == KIND_MUNITION && f.descriptor.munition_type.category == CATEGORY_FIXED {
            out.push(finding(
                "fixed-munition",
                format!(
                    "munition {} is category Fixed (a mine or demolition), which isn't fired; its Detonation alone reports it{}",
                    f.descriptor.munition_type,
                    cite("5.4.3.3 a)9")
                ),
            ));
        }
        if real(&f.firing_entity) && now - started > grace {
            match table.get(&key) {
                None => out.push(finding(
                    "unknown-firer",
                    format!("the firing entity has never reported an Entity State{}", cite("5.4.3")),
                )),
                Some(r) if r.deactivated() || r.removed => out.push(finding(
                    "unknown-firer",
                    format!("the firing entity was removed or is deactivated{}", cite("5.4.3")),
                )),
                _ => {}
            }
        }
        self.shots.insert(
            (exercise, f.event_id),
            Shot {
                at: now,
                firing: f.firing_entity,
                munition_type: f.descriptor.munition_type,
                source,
                expendable: fti == Some(1) || kind == KIND_EXPENDABLE,
                detonated: false,
            },
        );
        out
    }

    /// A Detonation PDU. `tolerance` is how far an entity impact may land
    /// from its target, plus the target's speed x 1 s.
    #[allow(clippy::too_many_arguments)]
    pub fn detonation(
        &mut self,
        now: f64,
        source: SocketAddr,
        exercise: u8,
        (version, status): (u8, u8),
        d: &Detonation,
        table: &EntityTable,
        (max_flight, tolerance): (f64, f64),
    ) -> Vec<Finding> {
        let started = *self.started.get_or_insert(now);
        let key = EntityKey {
            exercise,
            id: d.firing_entity,
        };
        let mut out = Vec::new();
        let finding = |kind, message: String| Finding {
            kind,
            key,
            sender: source,
            message: format!(
                "{} detonation, event {}: {message}",
                d.firing_entity,
                event(&d.event_id)
            ),
        };
        let kind = d.descriptor.munition_type.kind;
        let dti = indicator(version, status);
        match dti {
            Some(0) if kind == KIND_EXPENDABLE => out.push(finding(
                "type-indicator",
                format!(
                    "PDU Status says munition, but the type is an expendable (kind 8){}",
                    cite("5.4.4.3")
                ),
            )),
            Some(1) if kind == KIND_MUNITION => out.push(finding(
                "type-indicator",
                format!(
                    "PDU Status says expendable, but the type is a munition (kind 2){}",
                    cite("5.4.4.3")
                ),
            )),
            _ => {}
        }
        if d.result == RESULT_ENTITY_IMPACT && real(&d.target_entity) {
            let target = EntityKey {
                exercise,
                id: d.target_entity,
            };
            if let Some(rec) = table.get(&target).filter(|r| !r.removed && !r.deactivated()) {
                let track = &rec.sources[&rec.last_source];
                let k = &track.last;
                let at = extrapolate(k, (now - track.last_seen).max(0.0));
                let speed = (k.velocity.x as f64)
                    .hypot(k.velocity.y as f64)
                    .hypot(k.velocity.z as f64);
                let off = geo::distance(&at, &d.location);
                let allowed = tolerance + speed;
                if off > allowed {
                    out.push(finding(
                        "impact-distance",
                        format!(
                            "result Entity Impact on {}, but it detonated {off:.0} m from the target's dead-reckoned position (allowed {allowed:.0} m){}",
                            d.target_entity,
                            cite("5.4.4")
                        ),
                    ));
                }
            }
        }
        // Only munition detonations (DTI 0, or v6) pair with a Fire.
        if dti.is_some_and(|x| x != 0) {
            return out;
        }
        match self.shots.get_mut(&(exercise, d.event_id)) {
            Some(s) => {
                s.detonated = true;
                if s.firing != d.firing_entity {
                    out.push(finding(
                        "mismatch",
                        format!("its Fire came from {}{}", s.firing, cite("5.4.4")),
                    ));
                }
                if s.munition_type != d.descriptor.munition_type {
                    out.push(finding(
                        "mismatch",
                        format!(
                            "munition type {}, but its Fire said {}{}",
                            d.descriptor.munition_type,
                            s.munition_type,
                            cite("5.4.4")
                        ),
                    ));
                }
            }
            None if real(&d.firing_entity) && d.event_id.event_number != 0 && now - started > max_flight => {
                out.push(finding(
                    "no-fire",
                    format!(
                        "no Fire with this Event ID: if this munition was fired, its Fire is missing; mines, demolitions and accidental detonations have none{}",
                        cite("5.4.4.3")
                    ),
                ))
            }
            None => {}
        }
        out
    }

    /// Munition Fires whose Detonation is overdue; forget settled shots.
    pub fn expire(&mut self, now: f64, max_flight: f64) -> Vec<Finding> {
        let mut out = Vec::new();
        self.shots.retain(|&(exercise, ev), s| {
            let age = now - s.at;
            if age <= max_flight {
                return true;
            }
            if !s.detonated && !s.expendable {
                out.push(Finding {
                    kind: "no-detonation",
                    key: EntityKey { exercise, id: s.firing },
                    sender: s.source,
                    message: format!(
                        "{} fire, event {}: no Detonation within {max_flight:.0} s{}",
                        s.firing,
                        event(&ev),
                        cite("5.4.4.3")
                    ),
                });
            }
            false
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_decode::{BurstDescriptor, Vec3f, WorldCoord};

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const FIRER: EntityId = EntityId::new(1, 1, 1);
    const EV: EventId = EventId {
        site: 1,
        application: 1,
        event_number: 7,
    };

    fn descriptor(kind: u8) -> BurstDescriptor {
        BurstDescriptor {
            munition_type: EntityType {
                kind,
                domain: 1,
                country: 225,
                ..Default::default()
            },
            warhead: 0,
            fuse: 0,
            quantity: 1,
            rate: 0,
        }
    }

    fn fire(kind: u8) -> Fire {
        Fire {
            firing_entity: FIRER,
            target_entity: EntityId::default(),
            munition_id: EntityId::default(),
            event_id: EV,
            fire_mission_index: 0,
            location: WorldCoord::default(),
            descriptor: descriptor(kind),
            velocity: Vec3f::default(),
            range: 0.0,
        }
    }

    fn det(kind: u8, event: EventId) -> Detonation {
        Detonation {
            firing_entity: FIRER,
            target_entity: EntityId::default(),
            munition_id: EntityId::default(),
            event_id: event,
            velocity: Vec3f::default(),
            location: WorldCoord::default(),
            descriptor: descriptor(kind),
            location_in_entity: Vec3f::default(),
            result: 5,
            variable_parameters: Vec::new(),
        }
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn expendables_owe_no_detonation_and_v6_has_no_indicator() {
        let table = EntityTable::default();
        let mut w = Warfare::default();
        // A flare (kind 8) with FTI expendable: nothing owed, no finding.
        assert!(w.fire(0.0, src(), 1, (7, 1 << 4), &fire(8), &table, 1e9).is_empty());
        assert!(w.expire(500.0, 180.0).is_empty());
        // v6 has no PDU Status: a flare is just a flare.
        assert!(w.fire(600.0, src(), 1, (6, 0), &fire(8), &table, 1e9).is_empty());
        // v7, FTI munition on a flare: the indicator is wrong.
        assert_eq!(
            kinds(&w.fire(700.0, src(), 1, (7, 0), &fire(8), &table, 1e9)),
            ["type-indicator"]
        );
    }

    #[test]
    fn non_munition_detonations_and_early_orphans_are_not_judged() {
        let mut w = Warfare::default();
        let other = EventId { event_number: 9, ..EV };
        // DTI 2 (non-munition explosion): no Fire expected.
        assert!(w
            .detonation(
                500.0,
                src(),
                1,
                (7, 2 << 4),
                &det(2, other),
                &EntityTable::default(),
                (180.0, 100.0)
            )
            .is_empty());
        // A munition detonation with no Fire, before the monitor has
        // watched max_flight: not judged; after: reported.
        let mut w = Warfare::default();
        assert!(w
            .detonation(
                0.0,
                src(),
                1,
                (7, 0),
                &det(2, other),
                &EntityTable::default(),
                (180.0, 100.0)
            )
            .is_empty());
        assert_eq!(
            kinds(&w.detonation(
                200.0,
                src(),
                1,
                (7, 0),
                &det(2, other),
                &EntityTable::default(),
                (180.0, 100.0)
            )),
            ["no-fire"]
        );
    }

    #[test]
    fn mines_are_not_fired() {
        let table = EntityTable::default();
        let mut w = Warfare::default();
        let mut mine = fire(2);
        mine.descriptor.munition_type.category = 3;
        assert_eq!(
            kinds(&w.fire(0.0, src(), 1, (7, 0), &mine, &table, 1e9)),
            ["fixed-munition"]
        );
    }

    #[test]
    fn entity_impacts_land_near_the_target() {
        use nn_decode::{DeadReckoning, DisTimestamp, EntityState, EulerAngles, Marking, Pdu, PduBody, PduHeader};
        let target = EntityId::new(2, 1, 1);
        let mut table = EntityTable::default();
        let at = WorldCoord {
            x: 6_378_137.0,
            y: 0.0,
            z: 0.0,
        };
        table.apply(
            0.0,
            src(),
            &Pdu {
                header: PduHeader::new(7, 1, 1, DisTimestamp(0)),
                body: PduBody::EntityState(EntityState {
                    entity_id: target,
                    force_id: 2,
                    entity_type: EntityType::default(),
                    alternative_entity_type: EntityType::default(),
                    // 20 m/s along y: 40 m on by the time of the detonation.
                    linear_velocity: Vec3f {
                        x: 0.0,
                        y: 20.0,
                        z: 0.0,
                    },
                    location: at,
                    orientation: EulerAngles::default(),
                    appearance: 0,
                    dead_reckoning: DeadReckoning {
                        algorithm: 2,
                        ..Default::default()
                    },
                    marking: Marking::ascii("T"),
                    capabilities: 0,
                    variable_parameters: Vec::new(),
                }),
            },
        );
        let hit = |y: f64| Detonation {
            target_entity: target,
            location: WorldCoord { y, ..at },
            result: 1,
            ..det(2, EV)
        };
        let mut w = Warfare::default();
        // On the target's dead-reckoned position: fine.
        assert!(w
            .detonation(2.0, src(), 1, (7, 0), &hit(40.0), &table, (180.0, 100.0))
            .is_empty());
        // Where it was when last reported, 40 m back: within tolerance.
        assert!(w
            .detonation(2.0, src(), 1, (7, 0), &hit(0.0), &table, (180.0, 100.0))
            .is_empty());
        // A kilometre off.
        assert_eq!(
            kinds(&w.detonation(2.0, src(), 1, (7, 0), &hit(1040.0), &table, (180.0, 100.0))),
            ["impact-distance"]
        );
    }

    #[test]
    fn firers_are_judged_after_the_grace() {
        let table = EntityTable::default();
        let mut w = Warfare::default();
        assert!(w.fire(0.0, src(), 1, (7, 0), &fire(2), &table, 144.0).is_empty());
        assert_eq!(
            kinds(&w.fire(200.0, src(), 1, (7, 0), &fire(2), &table, 144.0)),
            ["unknown-firer"]
        );
    }
}
