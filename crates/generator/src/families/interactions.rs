//! Interactions (families 1 and 2; IEEE 1278.1 5.3.3, 5.4.5, 5.4.6), each
//! on its own schedule:
//! - `collision_every`: two entities collide and each reports it with a
//!   Collision PDU naming the other (5.3.3.4).
//! - `damage_every`: an entity is damaged: an Entity Damage Status with one
//!   damage record, heartbeating every 10 s, and its appearance shows the
//!   damage; 30 s later it is repaired: a final report with no records and
//!   an Entity State with a clean appearance at once (5.4.6.3).
//! - `de_every`: an entity fires a 3 s directed-energy shot: a DE Fire with
//!   the weapon on and a single Fire, DE Fires every 0.5 s, then a DE Fire
//!   with the weapon off and a single Detonation (5.4.5.3).
//!
//! Faults (on the next interaction): only one party reports a collision
//! (`one-sided-collision`) or one reports it twice (`duplicate-collision`);
//! a repair leaves the appearance damaged (`stale-appearance`); a damage
//! report for a removed entity (`eds-after-remove ID`); a DE shot's DE Fires
//! stop mid-shot (`de-dropout`) or it has no Fire (`de-no-fire`).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind, Target, TICK};
use nn_decode::structure::minimal_body;
use nn_decode::*;

const REPAIR_AFTER: f64 = 30.0;
const EDS_HEARTBEAT: f64 = 10.0;
const DE_SHOT: f64 = 3.0;
const DE_HEARTBEAT: f64 = 0.5;

#[derive(Default)]
pub(crate) struct Interactions {
    next_collision: f64,
    next_damage: f64,
    next_de: f64,
    events: u16,
    /// Damaged entity (index), when damaged, last report.
    damaged: Option<(usize, f64, f64)>,
    /// DE shot: firer (index), Event ID, start, last DE Fire.
    shot: Option<(usize, EventId, f64, f64)>,
    one_sided: bool,
    duplicate: bool,
    stale: bool,
    dropout: bool,
    no_fire: bool,
}

fn put(b: &mut [u8], at: usize, bytes: &[u8]) {
    b[at - HEADER_LEN..at - HEADER_LEN + bytes.len()].copy_from_slice(bytes);
}

fn id_bytes(id: EntityId) -> Vec<u8> {
    [id.site, id.application, id.entity]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect()
}

fn event_bytes(e: EventId) -> Vec<u8> {
    [e.site, e.application, e.event_number]
        .iter()
        .flat_map(|v| v.to_be_bytes())
        .collect()
}

fn raw(tick: &Tick, pdu_type: u8, body: Vec<u8>) -> Pdu {
    Pdu {
        header: tick.header(pdu_type),
        body: PduBody::Other(body),
    }
}

/// A Collision; `mass` (kg) lets a repeat differ from the first report, as a
/// sender's second report would, rather than being a byte-identical echo.
fn collision(tick: &Tick, issuing: EntityId, colliding: EntityId, event: EventId, mass: f32) -> Pdu {
    let mut b = minimal_body(4).expect("Collision layout");
    put(&mut b, 12, &id_bytes(issuing));
    put(&mut b, 18, &id_bytes(colliding));
    put(&mut b, 24, &event_bytes(event));
    put(&mut b, 44, &mass.to_be_bytes());
    raw(tick, 4, b)
}

/// An Entity Damage Status with `records` damage records (40-byte DE Damage
/// Description records, type 4500), or none: repaired.
fn damage_status(tick: &Tick, id: EntityId, records: u16) -> Pdu {
    let mut b = minimal_body(69).expect("EDS layout");
    put(&mut b, 12, &id_bytes(id));
    put(&mut b, 22, &records.to_be_bytes());
    for _ in 0..records {
        let mut r = vec![0u8; 40];
        r[0..4].copy_from_slice(&4500u32.to_be_bytes());
        r[4..6].copy_from_slice(&40u16.to_be_bytes());
        b.extend(r);
    }
    raw(tick, 69, b)
}

fn de_munition() -> EntityType {
    EntityType {
        kind: 2,
        domain: 12, // directed energy
        country: 225,
        category: 1,
        subcategory: 1,
        specific: 0,
        extra: 0,
    }
}

fn de_fire(tick: &Tick, firer: EntityId, event: EventId, on: bool) -> Pdu {
    let mut b = minimal_body(68).expect("DE Fire layout");
    put(&mut b, 12, &id_bytes(firer));
    put(&mut b, 18, &event_bytes(event));
    let t = de_munition();
    put(&mut b, 24, &[t.kind, t.domain, 0, 225, t.category, t.subcategory, 0, 0]);
    put(&mut b, 76, &(on as u16).to_be_bytes());
    raw(tick, 68, b)
}

fn burst() -> BurstDescriptor {
    BurstDescriptor {
        munition_type: de_munition(),
        warhead: 0,
        fuse: 0,
        quantity: 1,
        rate: 0,
    }
}

impl Interactions {
    fn event(&mut self, site: u16, app: u16) -> EventId {
        self.events = self.events.wrapping_add(1);
        // Clear of the warfare family's event numbers.
        EventId {
            site,
            application: app,
            event_number: 30_000 + self.events,
        }
    }
}

/// Two live entities, preferably on different sites.
fn pair(w: &mut World) -> Option<(usize, usize)> {
    let live: Vec<usize> = (0..w.entities.len())
        .filter(|&i| w.entities[i].sending && !w.entities[i].parked)
        .collect();
    if live.len() < 2 {
        return None;
    }
    let a = live[(w.rng.next_u64() as usize) % live.len()];
    let others: Vec<usize> = live
        .iter()
        .copied()
        .filter(|&i| w.entities[i].id.site != w.entities[a].id.site)
        .collect();
    let pool = if others.is_empty() {
        live.into_iter().filter(|&i| i != a).collect::<Vec<_>>()
    } else {
        others
    };
    Some((a, pool[(w.rng.next_u64() as usize) % pool.len()]))
}

impl Family for Interactions {
    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        match (ev.kind, ev.target) {
            (EventKind::OneSidedCollision, _) => self.one_sided = true,
            (EventKind::DuplicateCollision, _) => self.duplicate = true,
            (EventKind::StaleAppearance, _) => self.stale = true,
            (EventKind::DeDropout, _) => self.dropout = true,
            (EventKind::DeNoFire, _) => self.no_fire = true,
            (EventKind::EdsAfterRemove, Target::Entity(id)) => {
                out.push((w.sender(id.site), damage_status(tick, id, 1)));
            }
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let (t, cfg) = (tick.t, w.cfg);
        if w.frozen {
            return;
        }
        let app = cfg.application;
        // Collisions.
        if let Some(every) = cfg.collision_every {
            if t + 1e-9 >= self.next_collision + every {
                self.next_collision = t;
                if let Some((a, b)) = pair(w) {
                    let (ia, ib) = (w.entities[a].id, w.entities[b].id);
                    let ea = self.event(ia.site, app);
                    out.push((w.sender(ia.site), collision(tick, ia, ib, ea, 20_000.0)));
                    if std::mem::take(&mut self.duplicate) {
                        out.push((w.sender(ia.site), collision(tick, ia, ib, ea, 21_000.0)));
                    }
                    if !std::mem::take(&mut self.one_sided) {
                        let eb = self.event(ib.site, app);
                        out.push((w.sender(ib.site), collision(tick, ib, ia, eb, 20_000.0)));
                    }
                }
            }
        }
        // Damage and repair.
        if let Some((i, since, last)) = self.damaged {
            let id = w.entities[i].id;
            if !w.entities[i].sending {
                self.damaged = None;
            } else if t - since >= REPAIR_AFTER {
                out.push((w.sender(id.site), damage_status(tick, id, 0)));
                if !std::mem::take(&mut self.stale) {
                    w.entities[i].damaged = false;
                    // An appearance change is reported at once (5.3.2.3).
                    w.entities[i].last_sent = f64::NEG_INFINITY;
                }
                self.damaged = None;
            } else if t - last >= EDS_HEARTBEAT {
                out.push((w.sender(id.site), damage_status(tick, id, 1)));
                self.damaged = Some((i, since, t));
            }
        } else if let Some(every) = cfg.damage_every {
            if t + 1e-9 >= self.next_damage + every {
                self.next_damage = t;
                if let Some((a, _)) = pair(w) {
                    let id = w.entities[a].id;
                    w.entities[a].damaged = true;
                    w.entities[a].last_sent = f64::NEG_INFINITY;
                    out.push((w.sender(id.site), damage_status(tick, id, 1)));
                    self.damaged = Some((a, t, t));
                }
            }
        }
        // Directed energy.
        if let Some((i, event, start, last)) = self.shot {
            let id = w.entities[i].id;
            if t - start >= DE_SHOT {
                out.push((w.sender(id.site), de_fire(tick, id, event, false)));
                let det = Detonation {
                    firing_entity: id,
                    target_entity: EntityId::default(),
                    munition_id: EntityId::default(),
                    event_id: event,
                    velocity: Vec3f::default(),
                    location: w.entities[i].kinematics(w.motion_time).0,
                    descriptor: burst(),
                    location_in_entity: Vec3f::default(),
                    result: 1,
                    variable_parameters: Vec::new(),
                };
                out.push((
                    w.sender(id.site),
                    Pdu {
                        header: tick.header(pdu_type::DETONATION),
                        body: PduBody::Detonation(det),
                    },
                ));
                self.shot = None;
            } else if t - last >= DE_HEARTBEAT - TICK / 2.0 {
                out.push((w.sender(id.site), de_fire(tick, id, event, true)));
                self.shot = Some((i, event, start, t));
            }
        } else if let Some(every) = cfg.de_every {
            if t + 1e-9 >= self.next_de + every {
                self.next_de = t;
                if let Some((a, b)) = pair(w) {
                    let (id, target) = (w.entities[a].id, w.entities[b].id);
                    let event = self.event(id.site, app);
                    out.push((w.sender(id.site), de_fire(tick, id, event, true)));
                    if !std::mem::take(&mut self.no_fire) {
                        let fire = Fire {
                            firing_entity: id,
                            target_entity: target,
                            munition_id: EntityId::default(),
                            event_id: event,
                            fire_mission_index: 0,
                            location: w.entities[a].kinematics(w.motion_time).0,
                            descriptor: burst(),
                            velocity: Vec3f::default(),
                            range: 0.0,
                        };
                        out.push((
                            w.sender(id.site),
                            Pdu {
                                header: tick.header(pdu_type::FIRE),
                                body: PduBody::Fire(fire),
                            },
                        ));
                    }
                    if std::mem::take(&mut self.dropout) {
                        // One more DE Fire, then nothing: no final report.
                        self.shot = None;
                    } else {
                        self.shot = Some((a, event, t, t));
                    }
                }
            }
        }
    }
}
