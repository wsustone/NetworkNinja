//! Simulation Management (family 5): the exercise's Start/Resume at the
//! start of the run, Remove Entity, and Stop/Freeze / Start/Resume controls.
//! Sent by the first site's simulator on behalf of the exercise.

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind, Target};
use nn_decode::*;

pub(crate) struct SimManagement;

/// A site's simulation application address (every entity of it).
fn sim_address(w: &World, site: u16) -> EntityId {
    EntityId::new(site, w.cfg.application, 0xffff)
}

const EVERYONE: EntityId = EntityId::new(0xffff, 0xffff, 0xffff);

impl SimManagement {
    fn start_resume(w: &World, tick: &Tick, request_id: u32) -> Pdu {
        Pdu {
            header: tick.header(pdu_type::START_RESUME),
            body: PduBody::StartResume(StartResume {
                originating: sim_address(w, w.manager_site()),
                receiving: EVERYONE,
                real_world_time: tick.clock,
                simulation_time: ClockTime::default(),
                request_id,
            }),
        }
    }
}

impl Family for SimManagement {
    fn begin(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        if tick.step == 0 {
            out.push((w.sender(w.manager_site()), Self::start_resume(w, tick, 1)));
        }
    }

    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        match (ev.kind, ev.target) {
            (EventKind::Remove | EventKind::NoFinalReport | EventKind::Zombie, Target::Entity(id)) => {
                Some(match w.find(&id) {
                    Some(i) => {
                        // The entity's last report says Deactivated (5.6.5.3.4);
                        // the faults skip it, or keep reporting after it.
                        let e = &mut w.entities[i];
                        match ev.kind {
                            EventKind::NoFinalReport => e.sending = false,
                            EventKind::Zombie => {
                                e.final_due = true;
                                e.zombie = true;
                            }
                            _ => e.final_due = true,
                        }
                        let pdu = Pdu {
                            header: tick.header(pdu_type::REMOVE_ENTITY),
                            body: PduBody::RemoveEntity(RemoveEntity {
                                originating: sim_address(w, id.site),
                                receiving: id,
                                request_id: 100 + i as u32,
                            }),
                        };
                        out.push((w.sender(id.site), pdu));
                        true
                    }
                    None => false,
                })
            }
            (EventKind::Freeze, _) => {
                w.frozen = true;
                let pdu = Pdu {
                    header: tick.header(pdu_type::STOP_FREEZE),
                    body: PduBody::StopFreeze(StopFreeze {
                        originating: sim_address(w, w.manager_site()),
                        receiving: EVERYONE,
                        real_world_time: tick.clock,
                        reason: 2, // recess
                        frozen_behavior: 1,
                        request_id: 2,
                    }),
                };
                out.push((w.sender(w.manager_site()), pdu));
                Some(true)
            }
            (EventKind::Resume, _) => {
                w.frozen = false;
                out.push((w.sender(w.manager_site()), Self::start_resume(w, tick, 3)));
                Some(true)
            }
            _ => None,
        }
    }
}
