//! Logistics (family 8; IEEE 1278.1 5.5, 7.4): every `logistics_every`
//! seconds an entity on the first site starts a conversation with one on
//! another site, alternating resupply and repair:
//!
//! - resupply: Service Request, repeated after RESUP_REC_T1 (5 s); the
//!   supplier's Resupply Offer; 40 s of loading (under RESUP_REC_T2, 55 s),
//!   then Resupply Received for part of the offer.
//! - repair: Service Requests every 5 s while the repair runs, the
//!   repairer's Repair Complete, the receiver's Repair Response.
//!
//! Each fault scripts the next conversation instead: `logistics-no-offer`,
//! `logistics-no-receipt`, `received-more`, `no-repair-response`,
//! `repair-cancel-result` (a supplier's cancel answered as a finished
//! repair), `supplies-on-repair`, `unsolicited-offer`, `orphan-received`,
//! `unrequested-repair`, `orphan-repair-response`, `unknown-supplier` (a
//! request to an entity that doesn't exist, withdrawn with a cancel).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::structure::minimal_body;
use nn_decode::*;
use std::collections::VecDeque;

const RESUPPLY: u8 = 1;
const REPAIR: u8 = 2;
/// The supply offered and taken: an entity type of kind Supply (9).
const FUEL: [u8; 8] = [9, 0, 0, 0, 3, 0, 0, 0];
const ALL_REPAIRS: u16 = 1;
const NO_REPAIRS: u16 = 0;
const REPAIR_ENDED: u8 = 1;

#[derive(Debug, Clone, Copy)]
enum Msg {
    Request { service: u8, supplies: u8 },
    Offer(f32),
    Received(f32),
    Cancel,
    Complete(u16),
    Response(u8),
}

/// (seconds in, sent by the receiver, what).
type Step = (f64, bool, Msg);

struct Conversation {
    receiver: usize,
    supplier: usize,
    /// The Servicing Entity ID's entity number, if not the supplier's own.
    supplier_number: Option<u16>,
    start: f64,
    steps: Vec<Step>,
    next: usize,
}

#[derive(Default)]
pub(crate) struct Logistics {
    next: f64,
    conversations: Vec<Conversation>,
    pending: VecDeque<EventKind>,
    started: u32,
}

fn script(fault: Option<EventKind>, repair_turn: bool) -> Vec<Step> {
    use Msg::*;
    let ask = Request {
        service: RESUPPLY,
        supplies: 1,
    };
    let fix = |supplies| Request {
        service: REPAIR,
        supplies,
    };
    let resupply = |taken| {
        vec![
            (0.0, true, ask),
            (5.0, true, ask),
            (6.0, false, Offer(80.0)),
            (46.0, true, Received(taken)),
        ]
    };
    let repair = |supplies, done, answer: Option<u8>| {
        let mut s = vec![
            (0.0, true, fix(supplies)),
            (5.0, true, fix(supplies)),
            (10.0, true, fix(supplies)),
        ];
        s.push((12.0, false, Complete(done)));
        if let Some(r) = answer {
            s.push((13.0, true, Response(r)));
        }
        s
    };
    match fault {
        Some(EventKind::LogisticsNoOffer) => vec![(0.0, true, ask), (5.0, true, ask), (10.0, true, ask)],
        Some(EventKind::LogisticsNoReceipt) => vec![(0.0, true, ask), (6.0, false, Offer(80.0))],
        Some(EventKind::ReceivedMore) => resupply(200.0),
        Some(EventKind::NoRepairResponse) => repair(0, ALL_REPAIRS, None),
        Some(EventKind::RepairCancelResult) => repair(0, NO_REPAIRS, Some(REPAIR_ENDED)),
        Some(EventKind::SuppliesOnRepair) => repair(1, ALL_REPAIRS, Some(REPAIR_ENDED)),
        Some(EventKind::UnsolicitedOffer) => vec![(0.0, false, Offer(80.0)), (40.0, true, Received(40.0))],
        Some(EventKind::OrphanReceived) => vec![(0.0, true, Received(40.0))],
        Some(EventKind::UnrequestedRepair) => {
            vec![(0.0, false, Complete(ALL_REPAIRS)), (1.0, true, Response(REPAIR_ENDED))]
        }
        Some(EventKind::OrphanRepairResponse) => vec![(0.0, true, Response(REPAIR_ENDED))],
        Some(EventKind::UnknownSupplier) => vec![(0.0, true, ask), (3.0, true, Cancel)],
        _ if repair_turn => repair(0, ALL_REPAIRS, Some(REPAIR_ENDED)),
        _ => resupply(40.0),
    }
}

fn pdu(w: &World, tick: &Tick, c: &Conversation, msg: Msg) -> Pdu {
    let pdu_type = match msg {
        Msg::Request { .. } => 5,
        Msg::Offer(_) => 6,
        Msg::Received(_) => 7,
        Msg::Cancel => 8,
        Msg::Complete(_) => 9,
        Msg::Response(_) => 10,
    };
    let mut b = minimal_body(pdu_type).expect("logistics layouts");
    let at = |abs: usize| abs - HEADER_LEN;
    let r = w.entities[c.receiver].id;
    let mut s = w.entities[c.supplier].id;
    if let Some(n) = c.supplier_number {
        s.entity = n;
    }
    // Every logistics PDU starts receiving (requesting) entity, then
    // supplying (servicing, repairing) entity.
    for (abs, id) in [(12, r), (18, s)] {
        for (i, v) in [id.site, id.application, id.entity].into_iter().enumerate() {
            b[at(abs) + 2 * i..at(abs) + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
        }
    }
    let records = |b: &mut Vec<u8>, q: &[f32]| {
        for &v in q {
            b.extend(FUEL);
            b.extend(v.to_be_bytes());
        }
    };
    match msg {
        Msg::Request { service, supplies } => {
            b[at(24)] = service;
            b[at(25)] = supplies;
            records(&mut b, &vec![100.0; supplies as usize]);
        }
        Msg::Offer(q) | Msg::Received(q) => {
            b[at(24)] = 1;
            records(&mut b, &[q]);
        }
        Msg::Complete(repair) => b[at(24)..at(26)].copy_from_slice(&repair.to_be_bytes()),
        Msg::Response(result) => b[at(24)] = result,
        Msg::Cancel => {}
    }
    Pdu {
        header: tick.header(pdu_type),
        body: PduBody::Other(b),
    }
}

impl Family for Logistics {
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        match ev.kind {
            EventKind::LogisticsNoOffer
            | EventKind::LogisticsNoReceipt
            | EventKind::ReceivedMore
            | EventKind::NoRepairResponse
            | EventKind::RepairCancelResult
            | EventKind::SuppliesOnRepair
            | EventKind::UnsolicitedOffer
            | EventKind::OrphanReceived
            | EventKind::UnrequestedRepair
            | EventKind::OrphanRepairResponse
            | EventKind::UnknownSupplier => {
                self.pending.push_back(ev.kind);
                Some(true)
            }
            _ => None,
        }
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.logistics_every else { return };
        let t = tick.t;
        if w.frozen {
            // Frozen: nothing is sent, and the scripts wait.
            for c in &mut self.conversations {
                c.start += crate::TICK;
            }
            return;
        }
        let alive = |i: usize| {
            let e = &w.entities[i];
            e.sending && !e.final_due && !e.destroyed
        };
        // Due steps; a conversation ends when its script does or either
        // entity goes.
        self.conversations.retain_mut(|c| {
            if !alive(c.receiver) || !alive(c.supplier) {
                return false;
            }
            while let Some(&(dt, by_receiver, msg)) = c.steps.get(c.next) {
                if t + 1e-9 < c.start + dt {
                    break;
                }
                let from = if by_receiver { c.receiver } else { c.supplier };
                out.push((w.sender(w.entities[from].id.site), pdu(w, tick, c, msg)));
                c.next += 1;
            }
            c.next < c.steps.len()
        });
        if t + 1e-9 < self.next + every {
            return;
        }
        self.next = t;
        let first = w.cfg.site_base;
        let pick = |on_first: bool, k: u32| {
            let pool: Vec<usize> = (0..w.entities.len())
                .filter(|&i| (w.entities[i].id.site == first) == on_first && alive(i))
                .collect();
            (!pool.is_empty()).then(|| pool[k as usize % pool.len()])
        };
        // Round robin over pairs, so overlapping conversations don't share one.
        let k = self.started;
        let (Some(receiver), Some(supplier)) = (pick(true, k), pick(false, k / 2)) else {
            return;
        };
        if self
            .conversations
            .iter()
            .any(|c| c.receiver == receiver && c.supplier == supplier)
        {
            return;
        }
        let fault = self.pending.pop_front();
        self.started += 1;
        let c = Conversation {
            receiver,
            supplier,
            supplier_number: (fault == Some(EventKind::UnknownSupplier)).then_some(999),
            start: t,
            steps: script(fault, k % 2 == 1),
            next: 0,
        };
        self.conversations.push(c);
        // Steps due at once go out this tick.
        let last = self.conversations.last_mut().expect("just pushed");
        while let Some(&(dt, by_receiver, msg)) = last.steps.get(last.next) {
            if dt > 1e-9 {
                break;
            }
            let from = if by_receiver { last.receiver } else { last.supplier };
            out.push((w.sender(w.entities[from].id.site), pdu(w, tick, last, msg)));
            last.next += 1;
        }
    }
}
