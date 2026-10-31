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
//! stop mid-shot (`de-dropout`) or it has no Fire (`de-no-fire`); both
//! parties to a collision stand still (`still-collision`); a DE Fire carries
//! a damage record instead of an aimpoint (`bad-de-record`).
//!
//! And the Attribute PDU faults, now, from the first site: an Attribute PDU
//! whose records don't match its master type (`bad-attribute`), and a
//! Comment PDU flagged as coupled with no Attribute PDU after it
//! (`missing-extension`, v7).

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
    still: bool,
    bad_record: bool,
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

/// A Collision by an entity moving at `velocity`; `mass` (kg) lets a repeat
/// differ from the first report, as a sender's second report would, rather
/// than being a byte-identical echo.
fn collision(
    tick: &Tick,
    (issuing, velocity): (EntityId, Vec3f),
    colliding: EntityId,
    event: EventId,
    mass: f32,
) -> Pdu {
    let mut b = minimal_body(4).expect("Collision layout");
    put(&mut b, 12, &id_bytes(issuing));
    put(&mut b, 18, &id_bytes(colliding));
    put(&mut b, 24, &event_bytes(event));
    let v: Vec<u8> = [velocity.x, velocity.y, velocity.z]
        .iter()
        .flat_map(|c| c.to_be_bytes())
        .collect();
    put(&mut b, 32, &v);
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

/// A DE Fire; while the weapon is on it carries one DE Precision Aimpoint
/// record (type 4000, 88 bytes; 6.2.21.3), or, `bad`, a Damage Description
/// record (4500) where the aimpoint belongs.
fn de_fire(tick: &Tick, firer: EntityId, event: EventId, on: bool, bad: bool) -> Pdu {
    let mut b = minimal_body(68).expect("DE Fire layout");
    put(&mut b, 12, &id_bytes(firer));
    put(&mut b, 18, &event_bytes(event));
    let t = de_munition();
    put(&mut b, 24, &[t.kind, t.domain, 0, 225, t.category, t.subcategory, 0, 0]);
    put(&mut b, 76, &(on as u16).to_be_bytes());
    if on {
        put(&mut b, 86, &1u16.to_be_bytes());
        let mut r = vec![0u8; 88];
        r[0..4].copy_from_slice(&(if bad { 4500u32 } else { 4000 }).to_be_bytes());
        r[4..6].copy_from_slice(&88u16.to_be_bytes());
        b.extend(r);
    }
    raw(tick, 68, b)
}

/// An Attribute PDU (7.2.6) from `site`'s simulation extending EE PDUs,
/// uncoupled: one record set holding Blanking Sector and Angle Deception
/// records (SISO 3500, 3501) under a Master Attribute Record Type of 3500.
fn bad_attribute(tick: &Tick, site: u16, app: u16) -> Pdu {
    let mut b = minimal_body(72).expect("Attribute layout");
    put(&mut b, 12, &[site.to_be_bytes(), app.to_be_bytes()].concat());
    put(&mut b, 22, &[23, tick.header(72).protocol_version]);
    put(&mut b, 24, &3500u32.to_be_bytes());
    put(&mut b, 30, &1u16.to_be_bytes());
    for v in [site, app, 0, 2] {
        b.extend(v.to_be_bytes());
    }
    for t in [3500u32, 3501] {
        b.extend(t.to_be_bytes());
        b.extend(8u16.to_be_bytes());
        b.extend([0, 0]);
    }
    raw(tick, 72, b)
}

/// A Comment PDU flagged as coupled (PDU Status CEI, bit 3) with no
/// Attribute PDU after it.
fn coupled_comment(tick: &Tick, site: u16, app: u16) -> Pdu {
    let mut b = minimal_body(22).expect("Comment layout");
    put(&mut b, 12, &id_bytes(EntityId::new(site, app, 0)));
    let mut pdu = raw(tick, 22, b);
    pdu.header.pdu_status |= 1 << 3;
    pdu
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

/// Two parked (stationary) entities, for `still-collision`.
fn parked_pair(w: &World) -> Option<(usize, usize)> {
    let mut parked = (0..w.entities.len()).filter(|&i| w.entities[i].sending && w.entities[i].parked);
    Some((parked.next()?, parked.next()?))
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
            (EventKind::StillCollision, _) => self.still = true,
            (EventKind::BadDeRecord, _) => self.bad_record = true,
            (EventKind::BadAttribute, _) => {
                let site = w.manager_site();
                out.push((w.sender(site), bad_attribute(tick, site, w.cfg.application)));
            }
            (EventKind::MissingExtension, _) => {
                let site = w.manager_site();
                out.push((w.sender(site), coupled_comment(tick, site, w.cfg.application)));
            }
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
                let still = std::mem::take(&mut self.still);
                let found = if still { parked_pair(w) } else { pair(w) };
                if let Some((a, b)) = found {
                    let velocity = |i: usize| w.entities[i].kinematics(w.motion_time).1;
                    let (ia, ib) = ((w.entities[a].id, velocity(a)), (w.entities[b].id, velocity(b)));
                    let ea = self.event(ia.0.site, app);
                    out.push((w.sender(ia.0.site), collision(tick, ia, ib.0, ea, 20_000.0)));
                    if std::mem::take(&mut self.duplicate) {
                        out.push((w.sender(ia.0.site), collision(tick, ia, ib.0, ea, 21_000.0)));
                    }
                    if !std::mem::take(&mut self.one_sided) {
                        let eb = self.event(ib.0.site, app);
                        out.push((w.sender(ib.0.site), collision(tick, ib, ia.0, eb, 20_000.0)));
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
                out.push((w.sender(id.site), de_fire(tick, id, event, false, false)));
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
                out.push((w.sender(id.site), de_fire(tick, id, event, true, false)));
                self.shot = Some((i, event, start, t));
            }
        } else if let Some(every) = cfg.de_every {
            if t + 1e-9 >= self.next_de + every {
                self.next_de = t;
                if let Some((a, b)) = pair(w) {
                    let (id, target) = (w.entities[a].id, w.entities[b].id);
                    let event = self.event(id.site, app);
                    let bad = std::mem::take(&mut self.bad_record);
                    out.push((w.sender(id.site), de_fire(tick, id, event, true, bad)));
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
