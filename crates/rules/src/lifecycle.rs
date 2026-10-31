//! Entity State lifecycle (ADR 0010 Wave 1; IEEE 1278.1 5.3.2, 5.3.5,
//! 5.6.5.3): is each entity's life told consistently, from its first report
//! to its last?
//!
//! Findings, all point events of the `entity-lifecycle` rule:
//! - *no final report*: after a Remove Entity, the entity must send at least
//!   one more Entity State with appearance Deactivated (5.6.5.3.4); none
//!   within `final_report_window` (12 s) is reported, attributed to the
//!   entity's simulation.
//! - *zombie*: an entity that reports active again after its Deactivated
//!   report, or keeps reporting Deactivated for longer than the window (a
//!   simulator still sending a dead entity, or an Entity ID reused).
//! - *static with velocity*: DR algorithm Static (1) with a speed: receivers
//!   won't extrapolate it, so it freezes on their displays (Annex E).
//! - *type change*: one sender changing an entity's type mid-life (5.3.2;
//!   two senders with different types are already an ID conflict).
//! - *force or marking change*: a warning; some simulations relabel.
//! - *update before full report*: an Entity State Update for an entity no
//!   full Entity State has described (5.3.5): receivers can't place it.
//!   Only once the monitor has watched for a stationary timeout, since the
//!   full report may predate it.

use nn_decode::{appearance, EntityId, EntityState, EntityType};
use nn_state::EntityKey;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Above this speed (m/s) a Static entity is moving.
const STATIC_SPEED: f64 = 0.1;

#[derive(Debug, Clone)]
struct Life {
    /// Per sender: the type, force and marking it last reported.
    seen: HashMap<SocketAddr, (EntityType, u8, String)>,
    last_source: SocketAddr,
    last_seen: f64,
    /// When its first Deactivated report arrived.
    deactivated_at: Option<f64>,
    /// A Remove Entity arrived at this time; a Deactivated report is owed.
    removed_at: Option<f64>,
}

/// A lifecycle finding, for the engine to raise.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub key: EntityKey,
    pub sender: SocketAddr,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Lifecycle {
    lives: HashMap<EntityKey, Life>,
    started: Option<f64>,
}

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

impl Lifecycle {
    /// A full Entity State (or an update merged into one).
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        exercise: u8,
        es: &EntityState,
        window: f64,
    ) -> Vec<Finding> {
        self.started.get_or_insert(now);
        let key = EntityKey {
            exercise,
            id: es.entity_id,
        };
        let mut out = Vec::new();
        let f = |kind, message: String| Finding {
            kind,
            key,
            sender: source,
            message: format!("{}: {message}", es.entity_id),
        };
        let deactivated = es.appearance & appearance::DEACTIVATED != 0;
        let marking = es.marking.text();
        let life = self.lives.entry(key).or_insert_with(|| Life {
            seen: HashMap::new(),
            last_source: source,
            last_seen: now,
            deactivated_at: None,
            removed_at: None,
        });
        life.last_source = source;
        life.last_seen = now;
        match (life.deactivated_at, deactivated) {
            (None, true) => {
                life.deactivated_at = Some(now);
                life.removed_at = None;
            }
            (Some(_), false) => {
                life.deactivated_at = None;
                out.push(f(
                    "zombie",
                    format!(
                        "reports active again after its Deactivated report: a simulator still sending a removed entity, or the Entity ID reused{}",
                        cite("5.6.5.3.4")
                    ),
                ));
            }
            (Some(at), true) if now - at > window => {
                // Once per stretch: restart the clock.
                life.deactivated_at = Some(now);
                out.push(f(
                    "zombie",
                    format!(
                        "still reporting {:.0} s after its Deactivated report; a deactivated entity sends no more Entity States{}",
                        now - at,
                        cite("5.6.5.3.4")
                    ),
                ));
            }
            _ => {}
        }
        if es.dead_reckoning.algorithm == 1 {
            let v = &es.linear_velocity;
            let speed = ((v.x * v.x + v.y * v.y + v.z * v.z) as f64).sqrt();
            if speed > STATIC_SPEED {
                out.push(f(
                    "static-with-velocity",
                    format!(
                        "DR algorithm Static with a speed of {speed:.1} m/s: receivers won't move it{}",
                        cite("Annex E")
                    ),
                ));
            }
        }
        let now_seen = (es.entity_type, es.force_id, marking.clone());
        if let Some((t, force, mark)) = life.seen.insert(source, now_seen) {
            if t != es.entity_type {
                out.push(f(
                    "type-change",
                    format!("type changed from {t} to {}{}", es.entity_type, cite("5.3.2")),
                ));
            }
            if force != es.force_id {
                out.push(f(
                    "force-change",
                    format!("force ID changed from {force} to {}{}", es.force_id, cite("5.3.2")),
                ));
            }
            if mark != marking {
                out.push(f(
                    "marking-change",
                    format!("marking changed from '{mark}' to '{marking}'{}", cite("5.3.2")),
                ));
            }
        }
        out
    }

    /// A Remove Entity for these entities: each owes a Deactivated report.
    pub fn removed(&mut self, now: f64, keys: &[EntityKey]) {
        for k in keys {
            if let Some(life) = self.lives.get_mut(k) {
                if life.deactivated_at.is_none() {
                    life.removed_at.get_or_insert(now);
                }
            }
        }
    }

    /// An Entity State Update the monitor couldn't merge: no full report has
    /// described this entity.
    pub fn orphan_update(
        &mut self,
        now: f64,
        source: SocketAddr,
        exercise: u8,
        id: EntityId,
        grace: f64,
    ) -> Option<Finding> {
        let started = *self.started.get_or_insert(now);
        (now - started > grace).then(|| Finding {
            kind: "update-before-full-report",
            key: EntityKey { exercise, id },
            sender: source,
            message: format!(
                "{id}: Entity State Update with no Entity State ever giving its type: receivers can't place it{}",
                cite("5.3.5")
            ),
        })
    }

    /// Removals whose Deactivated report is overdue; forget old lives.
    pub fn expire(&mut self, now: f64, window: f64) -> Vec<Finding> {
        let mut out = Vec::new();
        for (key, life) in self.lives.iter_mut() {
            if let Some(at) = life.removed_at {
                if now - at > window {
                    life.removed_at = None;
                    out.push(Finding {
                        kind: "no-final-report",
                        key: *key,
                        sender: life.last_source,
                        message: format!(
                            "{}: removed, but sent no final Entity State with appearance Deactivated within {window:.0} s{}",
                            key.id,
                            cite("5.6.5.3.4")
                        ),
                    });
                }
            }
        }
        // Ten minutes unheard (the entity table's expiry): gone, forgotten.
        self.lives
            .retain(|_, l| now - l.last_seen < 600.0 || l.removed_at.is_some());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_decode::{DeadReckoning, EulerAngles, Marking, Vec3f, WorldCoord};

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }

    fn es(force: u8, marking: &str, deactivated: bool) -> EntityState {
        EntityState {
            entity_id: EntityId::new(1, 1, 1),
            force_id: force,
            entity_type: EntityType::default(),
            alternative_entity_type: EntityType::default(),
            linear_velocity: Vec3f::default(),
            location: WorldCoord::default(),
            orientation: EulerAngles::default(),
            appearance: if deactivated { appearance::DEACTIVATED } else { 0 },
            dead_reckoning: DeadReckoning {
                algorithm: 1,
                ..Default::default()
            },
            marking: Marking::ascii(marking),
            capabilities: 0,
            variable_parameters: Vec::new(),
        }
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn force_and_marking_changes_are_named() {
        let mut l = Lifecycle::default();
        assert!(l.observe(0.0, src(), 1, &es(1, "A", false), 12.0).is_empty());
        assert_eq!(
            kinds(&l.observe(5.0, src(), 1, &es(2, "B", false), 12.0)),
            ["force-change", "marking-change"]
        );
        // Another sender's first report isn't a change.
        let other: SocketAddr = "10.0.0.2:3000".parse().unwrap();
        assert!(l.observe(6.0, other, 1, &es(3, "C", false), 12.0).is_empty());
    }

    #[test]
    fn deactivation_ends_a_life_and_the_removal_it_owed() {
        let key = EntityKey {
            exercise: 1,
            id: EntityId::new(1, 1, 1),
        };
        let mut l = Lifecycle::default();
        l.observe(0.0, src(), 1, &es(1, "A", false), 12.0);
        l.removed(1.0, &[key]);
        // The final report arrives in time: nothing owed.
        assert!(l.observe(2.0, src(), 1, &es(1, "A", true), 12.0).is_empty());
        assert!(l.expire(20.0, 12.0).is_empty());
        // A second Deactivated report soon after is fine; still sending
        // long after is a zombie.
        assert!(l.observe(5.0, src(), 1, &es(1, "A", true), 12.0).is_empty());
        assert_eq!(kinds(&l.observe(30.0, src(), 1, &es(1, "A", true), 12.0)), ["zombie"]);
    }
}
