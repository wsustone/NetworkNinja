//! Entity Information/Interaction (family 1): Entity State, sent when the
//! dead-reckoning error passes the threshold and otherwise on the
//! heartbeat. Owns the entity faults: a dropped heartbeat, a teleport, and
//! a rogue simulator cloning an Entity ID.

use super::{Family, Out};
use crate::world::{SimEntity, Tick, World};
use crate::{Event, EventKind, Sender, Target};
use nn_decode::*;

#[derive(Default)]
pub(crate) struct EntityInfo {
    /// The entity a rogue simulator is cloning, and when it last sent.
    clone_of: Option<(usize, f64)>,
}

fn entity_state(
    tick: &Tick,
    frozen: bool,
    e: &SimEntity,
    (pos, vel, orientation): (WorldCoord, Vec3f, EulerAngles),
    marking: Marking,
    dr_algorithm: u8,
) -> Pdu {
    // Body-axis algorithms (6-9) report velocity in the body frame: the
    // vehicles drive nose first, so it is all along body x.
    let velocity = match (frozen, dr_algorithm) {
        (true, _) => Vec3f::default(),
        (false, 6..=9) => Vec3f {
            x: e.speed as f32,
            ..Default::default()
        },
        (false, _) => vel,
    };
    Pdu {
        header: tick.header(pdu_type::ENTITY_STATE),
        body: PduBody::EntityState(EntityState {
            entity_id: e.id,
            force_id: e.force,
            entity_type: e.entity_type,
            alternative_entity_type: e.entity_type,
            linear_velocity: velocity,
            location: pos,
            orientation,
            appearance: if frozen { appearance::FROZEN } else { 0 },
            dead_reckoning: DeadReckoning {
                algorithm: dr_algorithm,
                ..Default::default()
            },
            marking,
            capabilities: 0,
            variable_parameters: Vec::new(),
        }),
    }
}

/// The Entity State Update carrying `es`'s changing fields (5.3.5).
fn update_of(tick: &Tick, es: Pdu) -> Pdu {
    let PduBody::EntityState(e) = es.body else { return es };
    Pdu {
        header: tick.header(pdu_type::ENTITY_STATE_UPDATE),
        body: PduBody::EntityStateUpdate(EntityStateUpdate {
            entity_id: e.entity_id,
            linear_velocity: e.linear_velocity,
            location: e.location,
            orientation: e.orientation,
            appearance: e.appearance,
            variable_parameters: e.variable_parameters,
        }),
    }
}

impl Family for EntityInfo {
    fn on_event(&mut self, w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        let Target::Entity(id) = ev.target else {
            return None;
        };
        let i = match ev.kind {
            EventKind::DropHeartbeat
            | EventKind::Teleport
            | EventKind::CloneId
            | EventKind::StaticMoving
            | EventKind::TypeChange
            | EventKind::OrphanUpdate => w.find(&id),
            _ => return None,
        };
        let Some(i) = i else { return Some(false) };
        let e = &mut w.entities[i];
        match ev.kind {
            EventKind::DropHeartbeat => e.sending = false,
            EventKind::Teleport => e.centre_e += 20_000.0,
            EventKind::StaticMoving => e.static_moving = true,
            EventKind::TypeChange => e.entity_type.category = if e.entity_type.category == 1 { 2 } else { 1 },
            EventKind::OrphanUpdate => e.orphan_updates = true,
            _ => self.clone_of = Some((i, f64::NEG_INFINITY)),
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let (cfg, t, frozen, motion) = (w.cfg, tick.t, w.frozen, w.motion_time);
        let silent = frozen && cfg.silent_when_frozen;
        let senders = &w.senders;
        for e in w.entities.iter_mut() {
            if !e.sending || silent {
                continue;
            }
            let kin @ (pos, vel, _) = e.kinematics(motion);
            if e.final_due {
                // The last report: appearance Deactivated.
                let mut pdu = entity_state(tick, frozen, e, kin, e.marking, cfg.dr_algorithm);
                if let PduBody::EntityState(es) = &mut pdu.body {
                    es.appearance |= appearance::DEACTIVATED;
                }
                out.push((senders.get(e.id.site), pdu));
                e.final_due = false;
                e.sending = e.zombie;
                e.last_sent = t;
                continue;
            }
            let heartbeat = if e.parked {
                cfg.stationary_heartbeat
            } else {
                cfg.heartbeat
            };
            let heartbeat_due = t - e.last_sent >= heartbeat;
            let dr_due = !e.parked && !frozen && e.last_sent >= 0.0 && e.dr_error(t, &pos) > cfg.dr_threshold;
            if heartbeat_due || dr_due {
                let algorithm = if e.parked || e.static_moving {
                    1
                } else {
                    cfg.dr_algorithm
                };
                let full = !cfg.entity_state_update || e.reports % 6 == 0;
                let mut pdu = entity_state(tick, frozen, e, kin, e.marking, algorithm);
                if !full {
                    pdu = update_of(tick, pdu);
                }
                e.reports += 1;
                e.last_sent = t;
                e.last_pos = pos;
                // A Static report is dead-reckoned as standing still.
                e.last_vel = if frozen || e.static_moving {
                    Vec3f::default()
                } else {
                    vel
                };
                if e.orphan_updates {
                    let mut ghost = update_of(tick, entity_state(tick, frozen, e, kin, e.marking, algorithm));
                    if let PduBody::EntityStateUpdate(u) = &mut ghost.body {
                        u.entity_id.entity += 1000;
                    }
                    out.push((senders.get(e.id.site), ghost));
                }
                out.push((senders.get(e.id.site), pdu));
            }
        }

        if let Some((i, last)) = self.clone_of {
            if t - last >= cfg.heartbeat && !silent {
                let e = &w.entities[i];
                let mut kin = e.kinematics(motion);
                kin.0.z += 500.0; // a different simulator's idea of the same entity
                let pdu = entity_state(tick, frozen, e, kin, Marking::ascii("CLONE"), cfg.dr_algorithm);
                let rogue = Sender {
                    site: e.id.site,
                    generation: 0,
                    rogue: true,
                    relay: false,
                };
                out.push((rogue, pdu));
                self.clone_of = Some((i, t));
            }
        }
    }
}
