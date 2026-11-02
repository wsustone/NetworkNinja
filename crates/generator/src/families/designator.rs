//! Designators (family 6; IEEE 1278.1 5.7.4): every `designator_every`
//! seconds a live entity lases an entity on another site for 30 s, sending a
//! Designator PDU every 5 s (HBT_PDU_DESIGNATOR) with the spot 1.5 m above
//! the target, then a final one with Power 0. If either entity goes away
//! first (a removal, another fault), the designator switches off properly.
//!
//! Faults (on the next designation): the spot is on no entity but keeps an
//! offset (`spot-offset`); it designates an entity that doesn't exist
//! (`unknown-designated`); its target is deactivated a few seconds in and it
//! stays on (`target-gone`); its designating entity is deactivated and its
//! designator just stops, with no Power 0 report (`designator-gone`).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::fields::enum_fields_of;
use nn_decode::structure::minimal_body;
use nn_decode::*;

const DESIGNATOR: u8 = 24;
const ON_FOR: f64 = 30.0;
const HEARTBEAT: f64 = 5.0;
const POWER: f32 = 10.0; // W
const WAVELENGTH: f32 = 1.064; // µm, Nd:YAG
const DR_FPW: u8 = 2;

#[derive(Default, Clone, Copy)]
struct Faults {
    spot_offset: bool,
    unknown: bool,
    target_gone: bool,
    self_gone: bool,
}

struct Lasing {
    by: usize,
    target: usize,
    start: f64,
    last: f64,
    reports: u32,
    faults: Faults,
}

#[derive(Default)]
pub(crate) struct Designator {
    next: f64,
    lasing: Option<Lasing>,
    pending: Faults,
}

/// One Designator PDU from `by` on `target` (or on no entity).
fn designator(w: &World, tick: &Tick, l: &Lasing, power: f32) -> Pdu {
    let mut b = minimal_body(DESIGNATOR).expect("Designator layout");
    let at = |abs: usize| abs - HEADER_LEN;
    // Code name, designator code: values SISO-REF-010 defines.
    for f in enum_fields_of(DESIGNATOR) {
        f.write(&mut b, HEADER_LEN, f.valid);
    }
    let by = w.entities[l.by].id;
    let t = &w.entities[l.target];
    let designated = match (l.faults.spot_offset, l.faults.unknown) {
        (true, _) => EntityId::new(0, 0, 0),
        (_, true) => EntityId { entity: 999, ..t.id },
        _ => t.id,
    };
    let put_id = |b: &mut Vec<u8>, abs: usize, id: EntityId| {
        for (i, v) in [id.site, id.application, id.entity].into_iter().enumerate() {
            b[at(abs) + 2 * i..at(abs) + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
        }
    };
    put_id(&mut b, 12, by);
    put_id(&mut b, 20, designated);
    b[at(28)..at(32)].copy_from_slice(&power.to_be_bytes());
    b[at(32)..at(36)].copy_from_slice(&WAVELENGTH.to_be_bytes());
    // The spot relative to the designated entity: above it, or (for a spot on
    // no entity) zero, which the `spot-offset` fault breaks.
    let offset: [f32; 3] = if designated == t.id || l.faults.spot_offset {
        [if l.faults.spot_offset { 1.0 } else { 0.0 }, 0.0, -1.5]
    } else {
        [0.0; 3]
    };
    for (i, v) in offset.iter().enumerate() {
        b[at(36) + 4 * i..at(40) + 4 * i].copy_from_slice(&v.to_be_bytes());
    }
    let (pos, _, _) = t.kinematics(w.motion_time);
    for (i, v) in [pos.x, pos.y, pos.z].iter().enumerate() {
        b[at(48) + 8 * i..at(56) + 8 * i].copy_from_slice(&v.to_be_bytes());
    }
    b[at(72)] = DR_FPW;
    Pdu {
        header: tick.header(DESIGNATOR),
        body: PduBody::Other(b),
    }
}

impl Family for Designator {
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        let p = &mut self.pending;
        match ev.kind {
            EventKind::SpotOffset => p.spot_offset = true,
            EventKind::UnknownDesignated => p.unknown = true,
            EventKind::TargetGone => p.target_gone = true,
            EventKind::DesignatorGone => p.self_gone = true,
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let t = tick.t;
        if w.frozen {
            return;
        }
        if let Some(l) = &mut self.lasing {
            let site = w.entities[l.by].id.site;
            let alive = |i: usize| w.entities[i].sending && !w.entities[i].final_due && !w.entities[i].destroyed;
            let (me_ok, target_ok) = (alive(l.by), alive(l.target));
            if l.faults.self_gone && !me_ok {
                // Gone with the designator on: no final report.
                self.lasing = None;
            } else if !me_ok || (!target_ok && !l.faults.target_gone) || t - l.start >= ON_FOR {
                out.push((w.sender(site), designator(w, tick, l, 0.0)));
                self.lasing = None;
            } else if t - l.last >= HEARTBEAT - 1e-9 {
                out.push((w.sender(site), designator(w, tick, l, POWER)));
                l.reports += 1;
                l.last = t;
                // Two reports in, the faults take their entity away.
                if l.reports == 2 {
                    if l.faults.target_gone {
                        w.entities[l.target].final_due = true;
                    }
                    if l.faults.self_gone {
                        w.entities[l.by].final_due = true;
                    }
                }
            }
            return;
        }
        let Some(every) = w.cfg.designator_every else { return };
        if t + 1e-9 < self.next + every {
            return;
        }
        self.next = t;
        let live: Vec<usize> = (0..w.entities.len())
            .filter(|&i| {
                let e = &w.entities[i];
                e.sending && !e.parked && !e.destroyed && !e.final_due
            })
            .collect();
        if live.len() < 2 {
            return;
        }
        let by = live[(w.rng.next_u64() as usize) % live.len()];
        let site = w.entities[by].id.site;
        let others: Vec<usize> = live
            .iter()
            .copied()
            .filter(|&i| w.entities[i].id.site != site)
            .collect();
        let pool: Vec<usize> = if others.is_empty() { live.clone() } else { others };
        let pool: Vec<usize> = pool.into_iter().filter(|&i| i != by).collect();
        let Some(&target) = pool.get((w.rng.next_u64() as usize) % pool.len().max(1)) else {
            return;
        };
        let l = Lasing {
            by,
            target,
            start: t,
            last: t,
            reports: 1,
            faults: std::mem::take(&mut self.pending),
        };
        out.push((w.sender(site), designator(w, tick, &l, POWER)));
        self.lasing = Some(l);
    }
}
