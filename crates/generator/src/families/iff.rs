//! IFF (family 7; IEEE 1278.1 5.7.6, 7.6.5, Annex B): with `iff_every`, the
//! first site's first moving entity carries a Mark XIIA transponder (System
//! Type 9), regeneration mode. It sends a heartbeat IFF PDU every 10 s
//! (HBT_PDU_IFF) with Layers 1-4, and every `iff_every` seconds its Mode 3/A
//! code changes: a change PDU (Layers 1, 3, 4) with the Change Indicator set,
//! and the next heartbeat sets it too. Its first PDU is the initial report;
//! when its entity goes it sends a final PDU with System On/Off Off.
//!
//! Faults bend the next PDU, except `iff-destroyed-on`, which destroys the
//! entity and keeps the transponder on: `iff-missing-layer` (no Layer 3),
//! `iff-layer-bits` (Information Layers claim Layer 5), `iff-layer-order`
//! (Layer 4 before 3), `iff-empty-layer2` (no Fundamental Parameter record),
//! `iff-unflagged-change` (a change with the flag clear),
//! `iff-heartbeat-unflagged` (a change whose next heartbeat clears it),
//! `iff-mode-mismatch` (On with System Mode Off).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::*;

const IFF: u8 = 28;
const HEARTBEAT: f64 = 10.0;
const MARK_XIIA_TRANSPONDER: u16 = 9;
const GENERIC_MARK_XIIA: u16 = 11;
const NORMAL: u8 = 3;
const OFF: u8 = 1;
/// Mode 3/A codes (octal), in turn.
const CODES: [u16; 4] = [0o1200, 0o4321, 0o2000, 0o0777];

#[derive(Default, Clone, Copy)]
struct Faults {
    missing_layer: bool,
    layer_bits: bool,
    layer_order: bool,
    empty_layer2: bool,
    mode_mismatch: bool,
}

struct Transponder {
    carrier: usize,
    last_heartbeat: f64,
    last_change: f64,
    code: usize,
    /// The next heartbeat repeats the Change Indicator.
    flag_next: bool,
    /// Fault: the next heartbeat clears it anyway.
    clear_next: bool,
    /// Fault: stays on after its entity is destroyed.
    stay_on: bool,
    /// The next PDU reports a change (System Mode back from the fault).
    flag_once: bool,
}

#[derive(Default)]
pub(crate) struct Iff {
    tx: Option<Transponder>,
    pending: Faults,
    /// Faults that act on the transponder itself, waiting for one.
    unflagged_change: bool,
    heartbeat_unflagged: bool,
    destroyed_on: bool,
}

/// What one PDU carries.
struct Report {
    on: bool,
    change: bool,
    heartbeat: bool,
    layers: Vec<u8>,
}

fn layer(n: u8, site: u16, app: u16, empty: bool) -> Vec<u8> {
    let len: usize = match n {
        2 => 52, // header, beam data, secondary data, one parameter record
        3 => 28, // Mode 5 transponder format, no IFF data records
        _ => 36, // Mode S transponder format, no IFF data records
    };
    let mut b = vec![0u8; len];
    b[0] = n;
    b[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    if n == 2 {
        if !empty {
            b[26..28].copy_from_slice(&1u16.to_be_bytes());
        }
        let record = &mut b[28..52];
        record[0..4].copy_from_slice(&250f32.to_be_bytes()); // ERP, W
        record[4..8].copy_from_slice(&1.09e9f32.to_be_bytes()); // reply frequency, Hz
        record[20] = 1; // Applicable Modes: All Modes
    } else {
        b[4..6].copy_from_slice(&site.to_be_bytes());
        b[6..8].copy_from_slice(&app.to_be_bytes());
    }
    b
}

fn iff(w: &World, tick: &Tick, t: &Transponder, r: &Report, f: &Faults) -> Pdu {
    let e = &w.entities[t.carrier];
    let at = |abs: usize| abs - HEADER_LEN;
    let mut b = vec![0u8; 60 - HEADER_LEN];
    for (i, v) in [e.id.site, e.id.application, e.id.entity].into_iter().enumerate() {
        b[at(12) + 2 * i..at(14) + 2 * i].copy_from_slice(&v.to_be_bytes());
    }
    b[at(36)..at(38)].copy_from_slice(&MARK_XIIA_TRANSPONDER.to_be_bytes());
    b[at(38)..at(40)].copy_from_slice(&GENERIC_MARK_XIIA.to_be_bytes());
    b[at(40)] = if r.on && !f.mode_mismatch { NORMAL } else { OFF };
    b[at(41)] = r.change as u8 | (r.heartbeat as u8) << 3;
    b[at(42)] = 1; // System Designator
                   // System Status: On/Off, and no TCAS (Parameter 6 Not Capable); off,
                   // every parameter Not Capable (5.7.6.3 k 2).
    b[at(44)] = if r.on { 0b0100_0001 } else { 0b0111_1110 };
    // Parameter 3: the Mode 3/A code, its status On (bit 13).
    let code = if r.on { CODES[t.code % CODES.len()] | 1 << 13 } else { 0 };
    b[at(52)..at(54)].copy_from_slice(&code.to_be_bytes());
    let mut layers = r.layers.clone();
    if f.missing_layer {
        layers.retain(|&l| l != 3);
    }
    let mut info = 0b10u8;
    for &l in &layers {
        info |= 1 << l;
    }
    if f.layer_bits {
        info |= 1 << 5;
    }
    if f.layer_order {
        layers.sort_unstable_by(|a, b| b.cmp(a));
    }
    b[at(46)] = info;
    for l in layers {
        b.extend(layer(l, e.id.site, e.id.application, f.empty_layer2));
    }
    Pdu {
        header: tick.header(IFF),
        body: PduBody::Other(b),
    }
}

impl Family for Iff {
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        let p = &mut self.pending;
        match ev.kind {
            EventKind::IffMissingLayer => p.missing_layer = true,
            EventKind::IffLayerBits => p.layer_bits = true,
            EventKind::IffLayerOrder => p.layer_order = true,
            EventKind::IffEmptyLayer2 => p.empty_layer2 = true,
            EventKind::IffModeMismatch => p.mode_mismatch = true,
            EventKind::IffUnflaggedChange => self.unflagged_change = true,
            EventKind::IffHeartbeatUnflagged => self.heartbeat_unflagged = true,
            EventKind::IffDestroyedOn => self.destroyed_on = true,
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.iff_every else { return };
        let t = tick.t;
        if w.frozen {
            return;
        }
        let alive = |w: &World, i: usize| {
            let e = &w.entities[i];
            e.sending && !e.final_due && !e.destroyed
        };
        let Some(tx) = &mut self.tx else {
            // The first site's first moving entity turns its transponder on.
            let site = w.cfg.site_base;
            let Some(carrier) =
                (0..w.entities.len()).find(|&i| w.entities[i].id.site == site && !w.entities[i].parked && alive(w, i))
            else {
                return;
            };
            let tx = Transponder {
                carrier,
                last_heartbeat: t,
                last_change: t,
                code: 0,
                flag_next: true,
                clear_next: false,
                stay_on: false,
                flag_once: false,
            };
            let r = Report {
                on: true,
                change: true,
                heartbeat: false,
                layers: vec![2, 3, 4],
            };
            let f = std::mem::take(&mut self.pending);
            out.push((w.sender(site), iff(w, tick, &tx, &r, &f)));
            self.tx = Some(tx);
            return;
        };
        let site = w.entities[tx.carrier].id.site;
        if self.destroyed_on {
            self.destroyed_on = false;
            w.entities[tx.carrier].destroyed = true;
            tx.stay_on = true;
        }
        if !alive(w, tx.carrier) && !tx.stay_on {
            // Its entity went: one final report, Off (5.7.6.3 k, l 2).
            if w.entities[tx.carrier].sending || w.entities[tx.carrier].destroyed {
                let r = Report {
                    on: false,
                    change: true,
                    heartbeat: false,
                    layers: Vec::new(),
                };
                out.push((w.sender(site), iff(w, tick, tx, &r, &Faults::default())));
            }
            self.tx = None;
            return;
        }
        if self.unflagged_change || self.heartbeat_unflagged {
            tx.last_change = f64::NEG_INFINITY;
        }
        let r = if t - tx.last_change >= every - 1e-9 {
            tx.code += 1;
            tx.last_change = t;
            let flagged = !std::mem::take(&mut self.unflagged_change);
            tx.flag_next = flagged;
            tx.clear_next = std::mem::take(&mut self.heartbeat_unflagged);
            Report {
                on: true,
                change: flagged,
                heartbeat: false,
                layers: vec![3, 4],
            }
        } else if t - tx.last_heartbeat >= HEARTBEAT - 1e-9 {
            tx.last_heartbeat = t;
            let flag = tx.flag_next && !tx.clear_next;
            tx.flag_next = false;
            tx.clear_next = false;
            Report {
                on: true,
                change: flag,
                heartbeat: true,
                layers: vec![2, 3, 4],
            }
        } else {
            return;
        };
        let f = std::mem::take(&mut self.pending);
        // A mode switch is a change, both ways: flag it and the PDU after.
        let flag = std::mem::replace(&mut tx.flag_once, f.mode_mismatch);
        let r = Report {
            change: r.change || f.mode_mismatch || flag,
            ..r
        };
        out.push((w.sender(site), iff(w, tick, tx, &r, &f)));
    }
}
