//! Every PDU type (ADR 0010 tiers S and E): with `all_types`, a round of
//! minimal valid PDUs of each type the other families don't send, from the
//! first site's simulator; and the PDU defects, which bend one such PDU.
//!
//! A minimal PDU has every count zero and every optional field absent (see
//! `nn_decode::structure::minimal_body`), with its first identifier filled
//! in, so alerts name the sending simulator, and a SISO-defined value in
//! each enumerated field (`nn_decode::fields`). Deep decoding of these
//! types, with real content, comes family by family (ADR 0010 step 5).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind, Target};
use nn_decode::fields::enum_fields_of;
use nn_decode::structure::{layout, layouts, minimal_body, IdField};
use nn_decode::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct Coverage {
    /// Simulation time each type is next due. Types with a heartbeat
    /// (`nn_decode::heartbeat`) go out at least that often; the rest once a
    /// round.
    next: BTreeMap<u8, f64>,
    /// Types `stop-heartbeat` has silenced.
    stopped: BTreeSet<u8>,
}

/// Types with real behaviour in another family, never sent minimal. (An
/// Entity State Update needs an Entity State before it: entity_info sends
/// them, with `entity_state_update`.)
const ELSEWHERE: [u8; 7] = [
    pdu_type::ENTITY_STATE_UPDATE,
    pdu_type::ENTITY_STATE,
    pdu_type::FIRE,
    pdu_type::DETONATION,
    pdu_type::REMOVE_ENTITY,
    pdu_type::START_RESUME,
    pdu_type::STOP_FREEZE,
];

/// A minimal PDU of `pdu_type` naming `site`'s simulator as its first
/// identifier.
fn minimal(w: &World, tick: &Tick, site: u16, pdu_type: u8) -> Option<Pdu> {
    let l = layout(pdu_type)?;
    let mut body = minimal_body(pdu_type)?;
    let app = w.cfg.application;
    let id: Vec<u8> = match l.id {
        IdField::Entity(_) => [site, app, 0].iter().flat_map(|v| v.to_be_bytes()).collect(),
        IdField::Simulation(_) => [site, app].iter().flat_map(|v| v.to_be_bytes()).collect(),
        IdField::Live(_) => vec![site as u8, app as u8, 0, 0],
    };
    let at = match l.id {
        IdField::Entity(at) | IdField::Simulation(at) | IdField::Live(at) => at - HEADER_LEN,
    };
    body[at..at + id.len()].copy_from_slice(&id);
    // Every enumerated field holds a value SISO-REF-010 defines.
    for f in enum_fields_of(pdu_type) {
        f.write(&mut body, HEADER_LEN, f.valid);
    }
    Some(Pdu {
        header: tick.header(pdu_type),
        body: PduBody::Other(body),
    })
}

impl Family for Coverage {
    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        let Target::Pdu { site, pdu_type } = ev.target else {
            return None;
        };
        if !EventKind::DEFECTS.contains(&ev.kind) {
            return None;
        }
        if ev.kind == EventKind::StopHeartbeat {
            self.stopped.insert(pdu_type);
            return Some(true);
        }
        let Some(mut pdu) = minimal(w, tick, site, pdu_type) else {
            return Some(false);
        };
        let sender = w.sender(site);
        let PduBody::Other(body) = &mut pdu.body else {
            unreachable!()
        };
        match ev.kind {
            EventKind::ShortPdu => body.truncate(body.len() - 4),
            EventKind::CountOverrun => {
                let Some(&(at, width)) = layout(pdu_type).and_then(|l| l.counts.first()) else {
                    return Some(false);
                };
                body[at - HEADER_LEN + width as usize - 1] = 1;
            }
            EventKind::PaddedPdu => body.extend([0; 8]),
            EventKind::WrongFamily => pdu.header.protocol_family = default_family(pdu_type) % 13 + 1,
            EventKind::TruncatedPdu => {
                out.push_cut(sender, pdu, 4);
                return Some(true);
            }
            EventKind::BadEnum => {
                let Some(f) = enum_fields_of(pdu_type).next() else {
                    return Some(false);
                };
                f.write(body, HEADER_LEN, u32::MAX >> (32 - 8 * f.width as u32));
            }
            _ => unreachable!(),
        }
        out.push((sender, pdu));
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.all_types else { return };
        let site = w.manager_site();
        for l in layouts() {
            if ELSEWHERE.contains(&l.pdu_type) || self.stopped.contains(&l.pdu_type) {
                continue;
            }
            let due = self.next.entry(l.pdu_type).or_insert(0.0);
            if tick.t + 1e-9 < *due {
                continue;
            }
            let interval = match nn_decode::heartbeat::of(l.pdu_type) {
                Some(h) if !h.own_rule => every.min(h.seconds),
                _ => every,
            };
            *due = tick.t + interval;
            if let Some(pdu) = minimal(w, tick, site, l.pdu_type) {
                out.push((w.sender(site), pdu));
            }
        }
    }
}
