//! Transfer Ownership (family 9; IEEE 1278.1 5.9.4, Figure 25): every
//! `transfer_every` seconds an entity's owner pushes it to another site's
//! simulator. The divesting simulation sends a TO PDU (Push Transfer -
//! Entity, Unacknowledged); the acquiring one answers with an
//! Acknowledge-R (Transfer Ownership, Able to Comply), then reports the
//! entity from its own sender (Transferred Entity Indicator set when the
//! entity's site isn't its own) and sends an ownership Event Report. The
//! old owner stops. The entity keeps its ID, type and marking.
//!
//! Faults script the next transfer: `transfer-lingering` (the old owner
//! keeps reporting), `transfer-reliability` (Acknowledged service asked),
//! `transfer-indicator` (indicator left clear), `transfer-attributes` (the
//! new owner changes the marking), `transfer-no-report` (no Event Report),
//! `transfer-concurrent` (a second TO for it, to another simulation),
//! `transfer-inactive` (an entity just deactivated; answered Unable to
//! Comply), `transfer-stalled` (no answer, and nobody cancels).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::structure::minimal_body;
use nn_decode::*;
use std::collections::VecDeque;

const TRANSFER_OWNERSHIP: u8 = 35;
const ACKNOWLEDGE_R: u8 = 55;
const EVENT_REPORT: u8 = 21;
const PUSH_ENTITY: u8 = 1;
const UNACKNOWLEDGED: u8 = 1;
const ACKNOWLEDGED: u8 = 0;
const ACK_TRANSFER: u16 = 5;
const ABLE: u16 = 1;
const UNABLE: u16 = 2;
const OWNERSHIP_REPORT: u32 = 17;

#[derive(Clone, Copy)]
struct Transfer {
    entity: usize,
    from: u16,
    to: u16,
    request_id: u32,
    start: f64,
    step: u8,
    fault: Option<EventKind>,
}

#[derive(Default)]
pub(crate) struct Transfers {
    next: f64,
    current: Option<Transfer>,
    pending: VecDeque<EventKind>,
    requests: u32,
}

fn put_id(b: &mut [u8], abs: usize, id: EntityId) {
    let at = abs - HEADER_LEN;
    for (i, v) in [id.site, id.application, id.entity].into_iter().enumerate() {
        b[at + 2 * i..at + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }
}

fn simulation(w: &World, site: u16) -> EntityId {
    EntityId::new(site, w.cfg.application, 0)
}

fn transfer_pdu(w: &World, tick: &Tick, x: &Transfer, to: u16, reliability: u8) -> Pdu {
    let mut b = minimal_body(TRANSFER_OWNERSHIP).expect("TO layout");
    put_id(&mut b, 12, simulation(w, x.from));
    put_id(&mut b, 18, simulation(w, to));
    let at = |abs: usize| abs - HEADER_LEN;
    b[at(24)..at(28)].copy_from_slice(&x.request_id.to_be_bytes());
    b[at(28)] = reliability;
    b[at(29)] = PUSH_ENTITY;
    put_id(&mut b, 30, w.entities[x.entity].id);
    Pdu {
        header: tick.header(TRANSFER_OWNERSHIP),
        body: PduBody::Other(b),
    }
}

fn acknowledge(w: &World, tick: &Tick, x: &Transfer, response: u16) -> Pdu {
    let mut b = minimal_body(ACKNOWLEDGE_R).expect("Acknowledge-R layout");
    put_id(&mut b, 12, simulation(w, x.to));
    put_id(&mut b, 18, simulation(w, x.from));
    let at = |abs: usize| abs - HEADER_LEN;
    b[at(24)..at(26)].copy_from_slice(&ACK_TRANSFER.to_be_bytes());
    b[at(26)..at(28)].copy_from_slice(&response.to_be_bytes());
    b[at(28)..at(32)].copy_from_slice(&x.request_id.to_be_bytes());
    Pdu {
        header: tick.header(ACKNOWLEDGE_R),
        body: PduBody::Other(b),
    }
}

fn event_report(w: &World, tick: &Tick, x: &Transfer) -> Pdu {
    let mut b = minimal_body(EVENT_REPORT).expect("Event Report layout");
    put_id(&mut b, 12, simulation(w, x.to));
    put_id(&mut b, 18, EntityId::new(0xffff, 0xffff, 0xffff));
    let at = |abs: usize| abs - HEADER_LEN;
    b[at(24)..at(28)].copy_from_slice(&OWNERSHIP_REPORT.to_be_bytes());
    Pdu {
        header: tick.header(EVENT_REPORT),
        body: PduBody::Other(b),
    }
}

impl Family for Transfers {
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        match ev.kind {
            EventKind::TransferLingering
            | EventKind::TransferReliability
            | EventKind::TransferIndicator
            | EventKind::TransferAttributes
            | EventKind::TransferNoReport
            | EventKind::TransferConcurrent
            | EventKind::TransferInactive
            | EventKind::TransferStalled => {
                self.pending.push_back(ev.kind);
                Some(true)
            }
            _ => None,
        }
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.transfer_every else { return };
        if w.frozen {
            if let Some(x) = &mut self.current {
                x.start += crate::TICK;
            }
            return;
        }
        let t = tick.t;
        if let Some(x) = &mut self.current {
            let dt = t - x.start;
            let fault = x.fault;
            match (x.step, fault) {
                (9, _) if dt >= 1.0 => {
                    // Its deactivated report is out: now the request.
                    out.push((w.sender(x.from), transfer_pdu(w, tick, x, x.to, UNACKNOWLEDGED)));
                    x.start = t;
                    x.step = 0;
                }
                (9, _) => {}
                (0, Some(EventKind::TransferConcurrent)) if dt >= 0.3 => {
                    // A second request for the same entity, to a third
                    // simulation, while the first is open.
                    let third = (w.cfg.site_base..w.cfg.site_base + w.cfg.sites)
                        .find(|&s| s != x.from && s != x.to)
                        .unwrap_or(x.to + 100);
                    let mut again = Transfer {
                        request_id: x.request_id + 1000,
                        ..*x
                    };
                    again.to = third;
                    out.push((w.sender(x.from), transfer_pdu(w, tick, &again, third, UNACKNOWLEDGED)));
                    x.step = 1;
                }
                (0, Some(EventKind::TransferConcurrent)) => {}
                (0 | 1, Some(EventKind::TransferStalled)) => {
                    // Nobody answers, nobody cancels.
                    self.current = None;
                }
                (0 | 1, Some(EventKind::TransferInactive)) if dt >= 0.5 => {
                    out.push((w.sender(x.to), acknowledge(w, tick, x, UNABLE)));
                    self.current = None;
                }
                (0 | 1, _) if dt >= 0.5 => {
                    out.push((w.sender(x.to), acknowledge(w, tick, x, ABLE)));
                    x.step = 2;
                }
                (2, _) if dt >= 1.0 => {
                    // The new owner reports it now; the old one stops.
                    let e = &mut w.entities[x.entity];
                    e.owner = Some(x.to);
                    e.last_sent = f64::NEG_INFINITY;
                    e.linger_from = (fault == Some(EventKind::TransferLingering)).then_some(x.from);
                    e.wrong_indicator = fault == Some(EventKind::TransferIndicator);
                    if fault == Some(EventKind::TransferAttributes) {
                        e.marking = Marking::ascii("XFER");
                    }
                    x.step = 3;
                }
                (3, _) if dt >= 1.5 => {
                    if fault != Some(EventKind::TransferNoReport) {
                        out.push((w.sender(x.to), event_report(w, tick, x)));
                    }
                    self.current = None;
                }
                _ => {}
            }
            return;
        }
        if t + 1e-9 < self.next + every {
            return;
        }
        self.next = t;
        let sites: Vec<u16> = (w.cfg.site_base..w.cfg.site_base + w.cfg.sites).collect();
        if sites.len() < 2 {
            return;
        }
        let fault = self.pending.pop_front();
        // An active, moving entity, in turn; not the IFF carrier (the first
        // site's first moving entity), whose IFF stays with its site.
        let carrier =
            (0..w.entities.len()).find(|&i| w.entities[i].id.site == w.cfg.site_base && !w.entities[i].parked);
        let pool: Vec<usize> = (0..w.entities.len())
            .filter(|&i| {
                let e = &w.entities[i];
                // Not one another scheduled event acts on, which would blur
                // what the transfer's own faults show.
                let spared = !w.cfg.events.iter().any(|ev| ev.target == crate::Target::Entity(e.id));
                e.sending
                    && !e.final_due
                    && !e.destroyed
                    && !e.parked
                    && Some(i) != carrier
                    && e.linger_from.is_none()
                    && spared
            })
            .collect();
        if pool.is_empty() {
            return;
        }
        self.requests += 1;
        let entity = pool[self.requests as usize % pool.len()];
        let from = w.entities[entity].owner.unwrap_or(w.entities[entity].id.site);
        let i = sites.iter().position(|&s| s == from).unwrap_or(0);
        let to = sites[(i + 1) % sites.len()];
        let mut x = Transfer {
            entity,
            from,
            to,
            request_id: self.requests,
            start: t,
            step: 0,
            fault,
        };
        if fault == Some(EventKind::TransferInactive) {
            // Deactivated first; the request follows its last report.
            w.entities[entity].final_due = true;
            x.step = 9;
            self.current = Some(x);
            return;
        }
        let reliability = if fault == Some(EventKind::TransferReliability) {
            ACKNOWLEDGED
        } else {
            UNACKNOWLEDGED
        };
        out.push((w.sender(from), transfer_pdu(w, tick, &x, to, reliability)));
        self.current = Some(x);
    }
}
