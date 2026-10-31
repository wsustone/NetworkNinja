//! Interactions between entities (ADR 0010 Wave 1), on raw PDU bytes:
//! Directed Energy Fire engagements (5.4.5), Entity Damage Status (5.4.6)
//! and Collisions (5.3.3, 5.3.4). Each is a small tracker raising findings
//! for its own rule: `directed-energy`, `entity-damage`, `collision`.

use nn_decode::{appearance, EntityId, EventId};
use nn_state::{EntityKey, EntityTable};
use std::collections::HashMap;
use std::net::SocketAddr;

/// A finding, for the engine to raise under the tracker's rule.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub key: EntityKey,
    pub sender: SocketAddr,
    pub message: String,
}

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

fn event_at(b: &[u8], at: usize) -> Option<EventId> {
    Some(EventId {
        site: u16_at(b, at)?,
        application: u16_at(b, at + 2)?,
        event_number: u16_at(b, at + 4)?,
    })
}

fn ev(e: &EventId) -> String {
    format!("{}:{}:{}", e.site, e.application, e.event_number)
}

// ------------------------------------------------------- directed energy

/// Seconds after the first / final DE Fire within which its single Fire /
/// Detonation must come ("immediately following", 5.4.5.3 f).
pub const DE_PAIR_WINDOW: f64 = 2.0;

#[derive(Debug, Clone)]
struct Shot {
    firer: EntityId,
    source: SocketAddr,
    on: bool,
    /// The weapon has been on: only then is a Fire owed.
    ever_on: bool,
    last_de: f64,
    started: f64,
    ended: Option<f64>,
    fires: u32,
    detonated: bool,
    reported: Vec<&'static str>,
}

/// DE engagements by (exercise, Event ID): DE Fire PDUs while the weapon is
/// on (Flags bit 0) heartbeat at HBT_PDU_DE_FIRE; one Fire follows the
/// first, one Detonation the last (5.4.5.3).
#[derive(Debug, Default)]
pub struct DirectedEnergy {
    shots: HashMap<(u8, EventId), Shot>,
}

impl DirectedEnergy {
    /// A DE Fire (68), Fire (2) or Detonation (3) PDU's bytes.
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8]) -> Vec<Finding> {
        let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match pdu_type {
            68 => {
                let (Some(firer), Some(event), Some(flags)) = (id_at(pdu, 12), event_at(pdu, 18), u16_at(pdu, 76))
                else {
                    return out;
                };
                let on = flags & 1 == 1;
                let s = self.shots.entry((exercise, event)).or_insert(Shot {
                    firer,
                    source,
                    on: false,
                    ever_on: false,
                    last_de: now,
                    started: now,
                    ended: None,
                    fires: 0,
                    detonated: false,
                    reported: Vec::new(),
                });
                if on && !s.ever_on {
                    s.started = now;
                    s.ever_on = true;
                }
                if !on && s.on {
                    s.ended = Some(now);
                }
                s.on = on;
                s.last_de = now;
                s.source = source;
            }
            2 | 3 => {
                let Some(event) = event_at(pdu, 30) else { return out };
                let Some(s) = self.shots.get_mut(&(exercise, event)) else {
                    return out;
                };
                if pdu_type == 2 {
                    s.fires += 1;
                    if s.fires == 2 {
                        out.push(Finding {
                            kind: "second-fire",
                            key: EntityKey { exercise, id: s.firer },
                            sender: source,
                            message: format!(
                                "{} DE engagement {}: a second Fire PDU; only one Fire/Detonation pair per DE engagement{}",
                                s.firer,
                                ev(&event),
                                cite("5.4.5.3 f)")
                            ),
                        });
                    }
                } else {
                    s.detonated = true;
                }
            }
            _ => {}
        }
        out
    }

    /// Overdue heartbeats, Fires and Detonations. `heartbeat` is
    /// HBT_PDU_DE_FIRE, `multiplier` HBT_TIMEOUT_MPLIER.
    pub fn expire(&mut self, now: f64, heartbeat: f64, multiplier: f64) -> Vec<Finding> {
        let mut out = Vec::new();
        let timeout = heartbeat * multiplier;
        self.shots.retain(|&(exercise, event), s| {
            let key = EntityKey { exercise, id: s.firer };
            let mut report = |s: &mut Shot, kind: &'static str, message: String| {
                if !s.reported.contains(&kind) {
                    s.reported.push(kind);
                    out.push(Finding {
                        kind,
                        key,
                        sender: s.source,
                        message: format!("{} DE engagement {}: {message}", s.firer, ev(&event)),
                    });
                }
            };
            if s.on && now - s.last_de > timeout {
                let gap = now - s.last_de;
                report(
                    s,
                    "dropout",
                    format!(
                        "weapon on, but no DE Fire for {gap:.1} s (heartbeat HBT_PDU_DE_FIRE {heartbeat} s × {multiplier}); receivers mark the shot off{}",
                        cite("5.4.5.3 b)")
                    ),
                );
            }
            if s.ever_on && s.fires == 0 && now - s.started > DE_PAIR_WINDOW {
                report(
                    s,
                    "no-fire",
                    format!("no Fire PDU followed its first DE Fire{}", cite("5.4.5.3 f)")),
                );
            }
            if let Some(end) = s.ended {
                if !s.detonated && now - end > DE_PAIR_WINDOW {
                    report(
                        s,
                        "no-detonation",
                        format!(
                            "no Detonation followed its final DE Fire (weapon off){}",
                            cite("5.4.5.3 f)")
                        ),
                    );
                }
            }
            // Settled, or long dead: forget it.
            let idle = now - s.last_de;
            !(idle > 60.0 && (!s.on || idle > 600.0))
        });
        out
    }
}

// ------------------------------------------------------- damage status

/// Damage, mobility-kill and firepower-kill bits of a platform's appearance.
const DAMAGE_BITS: u32 = 0b11 << 3 | 1 << 1 | 1 << 2;

/// Entity Damage Status reports (5.4.6.3): none after the entity's
/// Deactivated report, and a "repaired" report (no damage records) must be
/// matched by an appearance without damage within `window`.
#[derive(Debug, Default)]
pub struct Damage {
    /// Entities reported repaired, awaiting a clean appearance: since when.
    repaired: HashMap<EntityKey, (f64, SocketAddr)>,
}

impl Damage {
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], table: &EntityTable) -> Vec<Finding> {
        let (Some(&exercise), Some(69), Some(id), Some(n)) = (pdu.get(1), pdu.get(2), id_at(pdu, 12), u16_at(pdu, 22))
        else {
            return Vec::new();
        };
        let key = EntityKey { exercise, id };
        let rec = table.get(&key);
        if rec.is_some_and(|r| r.deactivated()) {
            return vec![Finding {
                kind: "after-deactivated",
                key,
                sender: source,
                message: format!(
                    "{id}: Entity Damage Status after the entity's Deactivated Entity State{}",
                    cite("5.4.6.3")
                ),
            }];
        }
        if n == 0 && rec.is_some_and(|r| r.entity_type.kind == 1) {
            self.repaired.insert(key, (now, source));
        } else {
            self.repaired.remove(&key);
        }
        Vec::new()
    }

    /// Repairs whose entity still shows damage after `window`.
    pub fn expire(&mut self, now: f64, window: f64, table: &EntityTable) -> Vec<Finding> {
        let mut out = Vec::new();
        self.repaired.retain(|key, (at, source)| {
            let Some(rec) = table.get(key) else { return false };
            let damaged = rec.appearance & DAMAGE_BITS != 0 && rec.appearance & appearance::DEACTIVATED == 0;
            if !damaged {
                return false;
            }
            if now - *at <= window {
                return true;
            }
            out.push(Finding {
                kind: "stale-appearance",
                key: *key,
                sender: *source,
                message: format!(
                    "{}: repaired per Entity Damage Status, but its appearance still shows damage {:.0} s later{}",
                    key.id,
                    now - *at,
                    cite("5.4.6.3 e)")
                ),
            });
            false
        });
        out
    }
}

// ------------------------------------------------------------ collisions

#[derive(Debug, Clone)]
struct Report {
    at: f64,
    pdu_type: u8,
    answered: bool,
}

/// Collisions (5.3.3.4) and Collision-Elastic (5.3.4): both parties report
/// (unless the other is ENTITY_ID_UNKNOWN or not an entity in the
/// exercise), once per collision event.
#[derive(Debug, Default)]
pub struct Collisions {
    /// (exercise, issuing, colliding) → the report.
    reports: HashMap<(u8, EntityId, EntityId), Report>,
    /// (exercise, PDU type, issuing, Event ID) → when, to catch repeats.
    events: HashMap<(u8, u8, EntityId, EventId), f64>,
}

impl Collisions {
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], window: f64) -> Vec<Finding> {
        let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
            return Vec::new();
        };
        if pdu_type != 4 && pdu_type != 66 {
            return Vec::new();
        }
        let (Some(issuing), Some(colliding), Some(event)) = (id_at(pdu, 12), id_at(pdu, 18), event_at(pdu, 24)) else {
            return Vec::new();
        };
        let name = nn_decode::pdu_type_name(pdu_type);
        let mut out = Vec::new();
        if let Some(t) = self.events.insert((exercise, pdu_type, issuing, event), now) {
            if now - t <= window {
                out.push(Finding {
                    kind: "duplicate",
                    key: EntityKey { exercise, id: issuing },
                    sender: source,
                    message: format!(
                        "{issuing}: a second {name} for collision event {}; one per collision event{}",
                        ev(&event),
                        cite("5.3.3.4")
                    ),
                });
            }
        }
        // The other party's report answers this one, and this one answers it.
        let answered = match self.reports.get_mut(&(exercise, colliding, issuing)) {
            Some(r) => {
                r.answered = true;
                true
            }
            None => false,
        };
        self.reports.insert(
            (exercise, issuing, colliding),
            Report {
                at: now,
                pdu_type,
                answered,
            },
        );
        out
    }

    /// One-sided collisions: the colliding entity (a known, active entity of
    /// the exercise) hasn't reported its side within `window`.
    pub fn expire(&mut self, now: f64, window: f64, table: &EntityTable) -> Vec<Finding> {
        let mut out = Vec::new();
        let unknown = EntityId::new(0, 0, 0);
        self.reports.retain(|&(exercise, issuing, colliding), r| {
            if now - r.at <= window {
                return true;
            }
            let other = EntityKey { exercise, id: colliding };
            let party = table.get(&other).filter(|rec| !rec.removed && !rec.deactivated());
            if !r.answered && colliding != unknown {
                if let Some(rec) = party {
                    let name = nn_decode::pdu_type_name(r.pdu_type);
                    out.push(Finding {
                        kind: "one-sided",
                        key: other,
                        sender: rec.last_source,
                        message: format!(
                            "{colliding}: {issuing} reported a {name} with it, but it sent none within {window:.0} s; both parties report a collision{}",
                            cite(if r.pdu_type == 4 { "5.3.3.4" } else { "5.3.4" })
                        ),
                    });
                }
            }
            false
        });
        self.events.retain(|_, t| now - *t <= window);
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
    const A: EntityId = EntityId::new(1, 1, 1);
    const B: EntityId = EntityId::new(2, 1, 1);
    const EV: EventId = EventId {
        site: 1,
        application: 1,
        event_number: 7,
    };

    fn put_id(b: &mut [u8], at: usize, v: [u16; 3]) {
        for (i, x) in v.iter().enumerate() {
            b[at + 2 * i..at + 2 * i + 2].copy_from_slice(&x.to_be_bytes());
        }
    }

    /// Zeroed bytes of a PDU: header exercise 1 and `pdu_type`.
    fn pdu(pdu_type: u8, len: usize) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0] = 7;
        b[1] = 1;
        b[2] = pdu_type;
        b
    }

    fn de_fire(on: bool) -> Vec<u8> {
        let mut b = pdu(68, 88);
        put_id(&mut b, 12, [A.site, A.application, A.entity]);
        put_id(&mut b, 18, [EV.site, EV.application, EV.event_number]);
        b[76..78].copy_from_slice(&(on as u16).to_be_bytes());
        b
    }

    /// A Fire (2) or Detonation (3): only the Event ID matters here.
    fn shot(pdu_type: u8) -> Vec<u8> {
        let mut b = pdu(pdu_type, 96);
        put_id(&mut b, 30, [EV.site, EV.application, EV.event_number]);
        b
    }

    fn collision(issuing: EntityId, colliding: EntityId, event: u16) -> Vec<u8> {
        let mut b = pdu(4, 60);
        put_id(&mut b, 12, [issuing.site, issuing.application, issuing.entity]);
        put_id(&mut b, 18, [colliding.site, colliding.application, colliding.entity]);
        put_id(&mut b, 24, [issuing.site, issuing.application, event]);
        b
    }

    fn eds(id: EntityId, records: u16) -> Vec<u8> {
        let mut b = pdu(69, 24);
        put_id(&mut b, 12, [id.site, id.application, id.entity]);
        b[22..24].copy_from_slice(&records.to_be_bytes());
        b
    }

    /// A table holding `id` as a land platform with `appearance`.
    fn table(entries: &[(EntityId, u32)]) -> EntityTable {
        let mut t = EntityTable::default();
        for &(id, appearance) in entries {
            let es = EntityState {
                entity_id: id,
                force_id: 1,
                entity_type: EntityType {
                    kind: 1,
                    domain: 1,
                    ..Default::default()
                },
                alternative_entity_type: EntityType::default(),
                linear_velocity: Vec3f::default(),
                location: WorldCoord::default(),
                orientation: EulerAngles::default(),
                appearance,
                dead_reckoning: DeadReckoning {
                    algorithm: 1,
                    ..Default::default()
                },
                marking: Marking::ascii("T"),
                capabilities: 0,
                variable_parameters: Vec::new(),
            };
            t.apply(
                0.0,
                src(),
                &Pdu {
                    header: PduHeader::new(7, 1, 1, DisTimestamp(0)),
                    body: PduBody::EntityState(es),
                },
            );
        }
        t
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn a_de_shot_told_right_is_silent() {
        let mut de = DirectedEnergy::default();
        let mut found = de.observe(0.0, src(), &de_fire(true));
        found.extend(de.observe(0.0, src(), &shot(2)));
        let mut t = 0.5;
        while t < 3.0 {
            found.extend(de.observe(t, src(), &de_fire(true)));
            found.extend(de.expire(t, 0.5, 2.4));
            t += 0.5;
        }
        found.extend(de.observe(3.0, src(), &de_fire(false)));
        found.extend(de.observe(3.0, src(), &shot(3)));
        found.extend(de.expire(100.0, 0.5, 2.4));
        assert!(found.is_empty(), "{found:?}");
        // A lone DE Fire with the weapon off (a minimal one) owes nothing.
        let mut de = DirectedEnergy::default();
        assert!(de.observe(0.0, src(), &de_fire(false)).is_empty());
        assert!(de.expire(100.0, 0.5, 2.4).is_empty());
    }

    #[test]
    fn de_dropouts_missing_fires_and_detonations_are_named_once() {
        let mut de = DirectedEnergy::default();
        de.observe(0.0, src(), &de_fire(true));
        assert!(de.expire(1.0, 0.5, 2.4).is_empty());
        assert_eq!(kinds(&de.expire(2.5, 0.5, 2.4)), ["dropout", "no-fire"]);
        assert!(de.expire(3.0, 0.5, 2.4).is_empty());

        let mut de = DirectedEnergy::default();
        de.observe(0.0, src(), &de_fire(true));
        de.observe(0.0, src(), &shot(2));
        assert_eq!(kinds(&de.observe(0.2, src(), &shot(2))), ["second-fire"]);
        de.observe(0.5, src(), &de_fire(false));
        assert!(de.expire(2.0, 0.5, 2.4).is_empty());
        assert_eq!(kinds(&de.expire(3.0, 0.5, 2.4)), ["no-detonation"]);
    }

    #[test]
    fn collisions_want_both_parties_once() {
        let t = table(&[(A, 0), (B, 0)]);
        let mut c = Collisions::default();
        // Both report: silent.
        assert!(c.observe(0.0, src(), &collision(A, B, 1), 5.0).is_empty());
        assert!(c.observe(0.1, src(), &collision(B, A, 1), 5.0).is_empty());
        assert!(c.expire(10.0, 5.0, &t).is_empty());
        // A reports twice, B never.
        assert!(c.observe(20.0, src(), &collision(A, B, 2), 5.0).is_empty());
        assert_eq!(kinds(&c.observe(20.5, src(), &collision(A, B, 2), 5.0)), ["duplicate"]);
        let found = c.expire(30.0, 5.0, &t);
        assert_eq!(kinds(&found), ["one-sided"]);
        assert_eq!(found[0].key.id, B);
        // ENTITY_ID_UNKNOWN, or something that isn't an entity here: nothing.
        c.observe(40.0, src(), &collision(A, EntityId::new(0, 0, 0), 3), 5.0);
        c.observe(40.0, src(), &collision(A, EntityId::new(9, 9, 9), 4), 5.0);
        assert!(c.expire(50.0, 5.0, &t).is_empty());
    }

    #[test]
    fn repairs_must_clear_the_appearance() {
        let damaged = 2 << 3;
        let mut d = Damage::default();
        let t = table(&[(A, damaged)]);
        assert!(d.observe(0.0, src(), &eds(A, 0), &t).is_empty());
        assert!(d.expire(5.0, 6.0, &t).is_empty());
        assert_eq!(kinds(&d.expire(7.0, 6.0, &t)), ["stale-appearance"]);
        // Cleared in time: silent.
        d.observe(10.0, src(), &eds(A, 0), &t);
        assert!(d.expire(20.0, 6.0, &table(&[(A, 0)])).is_empty());
        // Damage reported after the entity's Deactivated report.
        let t = table(&[(B, appearance::DEACTIVATED)]);
        assert_eq!(kinds(&d.observe(30.0, src(), &eds(B, 1), &t)), ["after-deactivated"]);
    }
}
