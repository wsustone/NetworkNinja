//! Simulation Management handshakes (family 5, IEEE 1278.1 5.6.5): with
//! `siman_every`, the first site's simulator acts as simulation manager and
//! sends a request to the second site every so often, rotating through
//! Create Entity, Action Request, Data Query and Set Data. The second site
//! answers each one (Acknowledge, Action Response, Data) a moment later, the
//! way a conforming simulation does.
//!
//! Faults, on the answering site: it stops answering (`no-response`), its
//! next Acknowledge carries the wrong flag (`wrong-ack`), or it sends an
//! Action Response to a request nobody made (`orphan-response`).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind, Target};
use nn_decode::structure::minimal_body;
use nn_decode::*;
use std::collections::{BTreeMap, BTreeSet};

/// Seconds between a request and its answer.
const ANSWER_DELAY: f64 = 0.2;

/// Request types in rotation, with what answers them.
const ROTATION: [(u8, u8); 4] = [(11, 15), (16, 17), (18, 20), (19, 20)];

#[derive(Default)]
pub(crate) struct Handshakes {
    next: f64,
    round: usize,
    /// Next Request ID per request type ("incremented by one for each
    /// subsequent issue of this type", 5.6.5.7.3 c).
    request_ids: BTreeMap<u8, u32>,
    /// Answers due: (when, request type, request ID, requester, target).
    due: Vec<(f64, u8, u32, EntityId, EntityId)>,
    silent: BTreeSet<u16>,
    wrong_ack: BTreeSet<u16>,
}

/// A PDU of `pdu_type` with the SIMAN header IDs and `fields` (absolute
/// offset, value, width) written over its minimal body.
fn simple(tick: &Tick, pdu_type: u8, orig: EntityId, recv: EntityId, fields: &[(usize, u32, usize)]) -> Pdu {
    let mut body = minimal_body(pdu_type).expect("a standard PDU type");
    for (i, v) in [
        orig.site,
        orig.application,
        orig.entity,
        recv.site,
        recv.application,
        recv.entity,
    ]
    .into_iter()
    .enumerate()
    {
        body[2 * i..2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }
    for &(at, v, width) in fields {
        let at = at - HEADER_LEN;
        body[at..at + width].copy_from_slice(&v.to_be_bytes()[4 - width..]);
    }
    Pdu {
        header: tick.header(pdu_type),
        body: PduBody::Other(body),
    }
}

/// The answer to request `pdu_type` number `request_id`: an Acknowledge
/// (flag by request type, "able to comply"), an Action Response, or Data.
fn answer(tick: &Tick, pdu_type: u8, request_id: u32, from: EntityId, to: EntityId, wrong_flag: bool) -> Pdu {
    match pdu_type {
        11 => {
            let flag = if wrong_flag { 2 } else { 1 };
            simple(tick, 15, from, to, &[(24, flag, 2), (26, 1, 2), (28, request_id, 4)])
        }
        16 => simple(tick, 17, from, to, &[(24, request_id, 4)]),
        _ => simple(tick, 20, from, to, &[(24, request_id, 4)]),
    }
}

impl Family for Handshakes {
    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        let Target::Site(site) = ev.target else { return None };
        match ev.kind {
            EventKind::NoResponse => {
                self.silent.insert(site);
            }
            EventKind::WrongAck => {
                self.wrong_ack.insert(site);
            }
            EventKind::OrphanResponse => {
                let from = EntityId::new(site, w.cfg.application, 1);
                let to = EntityId::new(w.manager_site(), w.cfg.application, 0xffff);
                out.push((w.sender(site), simple(tick, 17, from, to, &[(24, 900_000, 4)])));
            }
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.siman_every else { return };
        let app = w.cfg.application;
        // Answers that are due, unless their site has gone quiet.
        let (now, later): (Vec<_>, Vec<_>) = self.due.drain(..).partition(|d| d.0 <= tick.t + 1e-9);
        self.due = later;
        for (_, pdu_type, request_id, requester, target) in now {
            if self.silent.contains(&target.site) {
                continue;
            }
            // Only an Acknowledge carries a flag to get wrong.
            let wrong = pdu_type == 11 && self.wrong_ack.remove(&target.site);
            let pdu = answer(tick, pdu_type, request_id, target, requester, wrong);
            out.push((w.sender(target.site), pdu));
        }
        if w.cfg.sites < 2 || tick.t + 1e-9 < self.next {
            return;
        }
        self.next = tick.t + every;
        let manager = EntityId::new(w.manager_site(), app, 0xffff);
        let site = w.cfg.site_base + 1;
        let (pdu_type, _) = ROTATION[self.round % ROTATION.len()];
        self.round += 1;
        let id = self.request_ids.entry(pdu_type).or_insert(1);
        let request_id = *id;
        *id += 1;
        // Create Entity goes to the simulation; the rest to its entity 1.
        let target = if pdu_type == 11 {
            EntityId::new(site, app, 0xffff)
        } else {
            EntityId::new(site, app, 1)
        };
        let req = simple(tick, pdu_type, manager, target, &[(24, request_id, 4)]);
        out.push((w.sender(manager.site), req));
        self.due
            .push((tick.t + ANSWER_DELAY, pdu_type, request_id, manager, target));
    }
}
