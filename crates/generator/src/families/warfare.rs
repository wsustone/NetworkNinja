//! Warfare (family 2): every `fire_every` seconds of running time a random
//! entity fires on one from another site; the Detonation follows 2 s later.

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::Config;
use nn_decode::*;
use nn_state::geo;

pub(crate) struct Warfare {
    fire_count: u16,
    next_fire: f64,
    /// Detonations due, with when.
    detonations: Vec<(f64, Detonation)>,
}

impl Warfare {
    pub fn new(cfg: &Config) -> Self {
        Warfare {
            fire_count: 0,
            next_fire: cfg.fire_every.unwrap_or(f64::INFINITY),
            detonations: Vec::new(),
        }
    }
}

impl Family for Warfare {
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
                let descriptor = BurstDescriptor {
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
                };
                let range = geo::distance(&from, &to) as f32;
                let fire = Pdu {
                    header: tick.header(pdu_type::FIRE),
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
                        location: to,
                        descriptor,
                        location_in_entity: Vec3f::default(),
                        result: 1, // entity impact
                        variable_parameters: Vec::new(),
                    },
                ));
            }
        }

        self.detonations.retain(|(at, d)| {
            if *at <= t + 1e-9 {
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
