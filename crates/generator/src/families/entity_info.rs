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
    pos: WorldCoord,
    vel: Vec3f,
    heading: f32,
    marking: Marking,
) -> Pdu {
    Pdu {
        header: tick.header(pdu_type::ENTITY_STATE),
        body: PduBody::EntityState(EntityState {
            entity_id: e.id,
            force_id: e.force,
            entity_type: e.entity_type,
            alternative_entity_type: e.entity_type,
            linear_velocity: if frozen { Vec3f::default() } else { vel },
            location: pos,
            orientation: EulerAngles {
                psi: heading,
                theta: 0.0,
                phi: 0.0,
            },
            appearance: if frozen { appearance::FROZEN } else { 0 },
            dead_reckoning: DeadReckoning {
                algorithm: 2,
                ..Default::default()
            },
            marking,
            capabilities: 0,
            variable_parameters: Vec::new(),
        }),
    }
}

impl Family for EntityInfo {
    fn on_event(&mut self, w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        let Target::Entity(id) = ev.target else {
            return None;
        };
        let i = match ev.kind {
            EventKind::DropHeartbeat | EventKind::Teleport | EventKind::CloneId => w.find(&id),
            _ => return None,
        };
        let Some(i) = i else { return Some(false) };
        match ev.kind {
            EventKind::DropHeartbeat => w.entities[i].sending = false,
            EventKind::Teleport => w.entities[i].centre_e += 20_000.0,
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
            let (pos, vel, heading) = e.kinematics(motion);
            let heartbeat_due = t - e.last_sent >= cfg.heartbeat;
            let dr_due = !frozen && e.last_sent >= 0.0 && e.dr_error(t, &pos) > cfg.dr_threshold;
            if heartbeat_due || dr_due {
                let pdu = entity_state(tick, frozen, e, pos, vel, heading, e.marking);
                e.last_sent = t;
                e.last_pos = pos;
                e.last_vel = if frozen { Vec3f::default() } else { vel };
                out.push((senders.get(e.id.site), pdu));
            }
        }

        if let Some((i, last)) = self.clone_of {
            if t - last >= cfg.heartbeat && !silent {
                let e = &w.entities[i];
                let (mut pos, vel, heading) = e.kinematics(motion);
                pos.z += 500.0; // a different simulator's idea of the same entity
                let pdu = entity_state(tick, frozen, e, pos, vel, heading, Marking::ascii("CLONE"));
                let rogue = Sender {
                    site: e.id.site,
                    generation: 0,
                    rogue: true,
                };
                out.push((rogue, pdu));
                self.clone_of = Some((i, t));
            }
        }
    }
}
