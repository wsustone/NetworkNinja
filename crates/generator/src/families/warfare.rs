//! Warfare (family 2): every `fire_every` seconds of running time a random
//! entity fires on one from another site; the Detonation follows 2 s later.
//!
//! Faults (on the next engagement): its Detonation never comes
//! (`no-detonation`), names another munition type (`detonation-mismatch`),
//! or its Fire's PDU Status calls the munition an expendable
//! (`wrong-fire-type`, v7), or it fires a mine (`mine-fired`: munition
//! category Fixed), or its Detonation claims an entity impact 2 km from the
//! target (`impact-miss`); or a Detonation for an Event ID never fired
//! (`orphan-detonation`), now.
//!
//! A Detonation lands where its target is when it detonates.

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Config, Event, EventKind};
use nn_decode::*;
use nn_state::geo;

pub(crate) struct Warfare {
    fire_count: u16,
    next_fire: f64,
    /// Detonations due, with when.
    detonations: Vec<(f64, Detonation)>,
    drop_next: bool,
    mismatch_next: bool,
    wrong_type_next: bool,
    mine_next: bool,
    miss_next: bool,
}

impl Warfare {
    pub fn new(cfg: &Config) -> Self {
        Warfare {
            fire_count: 0,
            next_fire: cfg.fire_every.unwrap_or(f64::INFINITY),
            detonations: Vec::new(),
            drop_next: false,
            mismatch_next: false,
            wrong_type_next: false,
            mine_next: false,
            miss_next: false,
        }
    }
}

impl Family for Warfare {
    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        match ev.kind {
            EventKind::NoDetonation => self.drop_next = true,
            EventKind::DetonationMismatch => self.mismatch_next = true,
            EventKind::WrongFireType => self.wrong_type_next = true,
            EventKind::MineFired => self.mine_next = true,
            EventKind::ImpactMiss => self.miss_next = true,
            EventKind::OrphanDetonation => {
                let Some(e) = w.entities.iter().find(|e| e.sending) else {
                    return Some(false);
                };
                let (at, _, _) = e.kinematics(w.motion_time);
                let id = e.id;
                let d = Detonation {
                    firing_entity: id,
                    target_entity: EntityId::default(),
                    munition_id: EntityId::default(),
                    event_id: EventId {
                        site: id.site,
                        application: id.application,
                        event_number: 60_000,
                    },
                    velocity: Vec3f::default(),
                    location: at,
                    descriptor: munition(),
                    location_in_entity: Vec3f::default(),
                    result: 5, // ground impact
                    variable_parameters: Vec::new(),
                };
                let pdu = Pdu {
                    header: tick.header(pdu_type::DETONATION),
                    body: PduBody::Detonation(d),
                };
                out.push((w.sender(id.site), pdu));
            }
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let t = tick.t;
        if !w.frozen && t >= self.next_fire {
            self.next_fire += w.cfg.fire_every.unwrap_or(f64::INFINITY);
            let live: Vec<usize> = (0..w.entities.len()).filter(|&i| w.entities[i].sending).collect();
            if live.len() >= 2 {
                let a = live[(w.rng.next_u64() as usize) % live.len()];
                let others: Vec<usize> = live
                    .iter()
                    .copied()
                    .filter(|&i| w.entities[i].id.site != w.entities[a].id.site)
                    .collect();
                let pool = if others.is_empty() {
                    live.iter().copied().filter(|&i| i != a).collect()
                } else {
                    others
                };
                let b = pool[(w.rng.next_u64() as usize) % pool.len()];
                self.fire_count = self.fire_count.wrapping_add(1);
                let (from, _, _) = w.entities[a].kinematics(w.motion_time);
                let (to, _, _) = w.entities[b].kinematics(w.motion_time);
                let firer = w.entities[a].id;
                let target = w.entities[b].id;
                let event_id = EventId {
                    site: firer.site,
                    application: firer.application,
                    event_number: self.fire_count,
                };
                let munition_id = EntityId::new(firer.site, firer.application, 1000 + self.fire_count);
                let mut descriptor = munition();
                if std::mem::take(&mut self.mine_next) {
                    descriptor.munition_type.category = 3; // Fixed: a mine
                }
                let range = geo::distance(&from, &to) as f32;
                let mut header = tick.header(pdu_type::FIRE);
                if std::mem::take(&mut self.wrong_type_next) {
                    header.pdu_status |= 1 << 4; // FTI: expendable
                }
                let fire = Pdu {
                    header,
                    body: PduBody::Fire(Fire {
                        firing_entity: firer,
                        target_entity: target,
                        munition_id,
                        event_id,
                        fire_mission_index: 0,
                        location: from,
                        descriptor,
                        velocity: Vec3f {
                            x: 0.0,
                            y: 0.0,
                            z: 300.0,
                        },
                        range,
                    }),
                };
                out.push((w.sender(firer.site), fire));
                let mut det_descriptor = descriptor;
                if std::mem::take(&mut self.mismatch_next) {
                    det_descriptor.munition_type.category += 1;
                }
                if !std::mem::take(&mut self.drop_next) {
                    self.detonations.push((
                        t + 2.0,
                        Detonation {
                            firing_entity: firer,
                            target_entity: target,
                            munition_id,
                            event_id,
                            velocity: Vec3f {
                                x: 0.0,
                                y: 0.0,
                                z: -250.0,
                            },
                            // Where the target is when it detonates: below.
                            location: to,
                            descriptor: det_descriptor,
                            location_in_entity: Vec3f::default(),
                            result: 1, // entity impact
                            variable_parameters: Vec::new(),
                        },
                    ));
                }
            }
        }

        let miss = &mut self.miss_next;
        self.detonations.retain_mut(|(at, d)| {
            if *at <= t + 1e-9 {
                if let Some(e) = w.entities.iter().find(|e| e.id == d.target_entity) {
                    d.location = e.kinematics(w.motion_time).0;
                }
                if std::mem::take(miss) {
                    d.location.x += 2000.0;
                }
                let pdu = Pdu {
                    header: tick.header(pdu_type::DETONATION),
                    body: PduBody::Detonation(d.clone()),
                };
                out.push((w.sender(d.firing_entity.site), pdu));
                false
            } else {
                true
            }
        });
    }
}

/// The munition every engagement fires: a US land-attack round.
fn munition() -> BurstDescriptor {
    BurstDescriptor {
        munition_type: EntityType {
            kind: 2,
            domain: 1,
            country: 225,
            category: 2,
            subcategory: 1,
            specific: 0,
            extra: 0,
        },
        warhead: 1000,
        fuse: 1000,
        quantity: 1,
        rate: 0,
    }
}
