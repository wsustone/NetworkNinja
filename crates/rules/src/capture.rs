//! Which PDUs to persist (ADR 0009): the pack's `[[capture]]` tiers keep
//! every report from fast movers and a thinned stream from slow and static
//! ones, so a full-rate exercise doesn't flood the disk.
//!
//! The decider only chooses; the server's writer thread stores what it
//! chose, inside a byte budget.

use crate::pack::{pick_capture, CaptureRule};
use nn_decode::{EntityId, Pdu, PduBody};
use nn_state::metrics::entity_of;
use nn_state::EntityKey;
use std::collections::HashMap;
use std::net::SocketAddr;

/// One PDU chosen for storage, with its exact wire bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Captured {
    pub at: f64,
    pub sender: SocketAddr,
    pub exercise: u8,
    pub pdu_type: u8,
    pub entity: Option<EntityId>,
    /// Why it was kept: `all`, `every 5s`, `event` or `alert`, prefixed with
    /// the matching type for Entity State (`1.2 all`).
    pub tier: String,
    pub raw: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct Capture {
    rules: Vec<CaptureRule>,
    last_kept: HashMap<(EntityKey, SocketAddr), f64>,
    last_prune: f64,
    pub kept: u64,
    pub skipped: u64,
    out: Vec<Captured>,
}

/// Forget an entity/sender's last kept time after this long, seconds.
const FORGET_AFTER: f64 = 600.0;

impl Capture {
    pub fn new(rules: Vec<CaptureRule>) -> Self {
        Capture {
            rules,
            ..Default::default()
        }
    }

    /// Decide on one decoded PDU. `alerted`: its entity has an open alert.
    pub fn offer(&mut self, now: f64, sender: SocketAddr, raw: &[u8], pdu: &Pdu, alerted: bool) {
        if now - self.last_prune > 60.0 {
            self.last_prune = now;
            self.last_kept.retain(|_, t| now - *t <= FORGET_AFTER);
        }
        let tier = match &pdu.body {
            PduBody::Other(_) => None,
            PduBody::EntityState(es) => {
                let key = EntityKey {
                    exercise: pdu.header.exercise_id,
                    id: es.entity_id,
                };
                let v = es.linear_velocity;
                let speed = ((v.x * v.x + v.y * v.y + v.z * v.z) as f64).sqrt();
                let rule = pick_capture(&self.rules, &es.entity_type, speed);
                let last = self.last_kept.get(&(key, sender)).copied();
                let tier = match rule.map(|r| (r.type_label(), r.every)) {
                    _ if alerted => Some("alert".to_string()),
                    Some((t, Some(e))) if e <= 0.0 => Some(format!("{t} all")),
                    // First report from this sender, or the interval is up.
                    Some((t, Some(e))) if last.is_none_or(|l| now - l >= e || now < l) => {
                        Some(format!("{t} every {e}s"))
                    }
                    _ => None,
                };
                if tier.is_some() {
                    self.last_kept.insert((key, sender), now);
                }
                tier
            }
            _ => Some("event".to_string()),
        };
        let Some(tier) = tier else {
            self.skipped += 1;
            return;
        };
        self.kept += 1;
        self.out.push(Captured {
            at: now,
            sender,
            exercise: pdu.header.exercise_id,
            pdu_type: pdu.header.pdu_type,
            entity: entity_of(pdu),
            tier,
            raw: raw.to_vec(),
        });
    }

    /// Everything kept since the last drain.
    pub fn drain(&mut self) -> Vec<Captured> {
        std::mem::take(&mut self.out)
    }
}
