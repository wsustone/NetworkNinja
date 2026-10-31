//! Distributed emission regeneration (family 6; IEEE 1278.1 5.7.3): every
//! `emission_every` seconds a live entity switches on its fire-control radar
//! (an AN/APG-63, SISO Emitter Name 1800) for 30 s, tracking an entity on
//! another site. Complete-Entity issuance: one system, one pulsed tracking
//! beam, an EE PDU every 5 s (HBT_PDU_EE), then one EE PDU with the beam
//! Deactivated.
//!
//! Faults (on the next emitter): its EE PDUs stop with the beam still on
//! (`emitter-dropout`); its Emitter Name changes after the first report
//! (`emitter-rename`); its beam is numbered NO_BEAM (`reserved-beam`); it
//! selects High Density Track/Jam and still lists its target
//! (`dense-targets`); it gives a PRF with no pulse width (`half-pulsed`);
//! its target is 0:A:E (`no-site-target`); it reports the beam Deactivated
//! twice (`repeat-deactivated`); its entity is destroyed a second in and
//! keeps emitting (`destroyed-emitting`).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::structure::minimal_body;
use nn_decode::*;

const EE: u8 = 23;
const ON_FOR: f64 = 30.0;
const HEARTBEAT: f64 = 5.0;
/// AN/APG-63 (UID 75), Fire Control (UID 76), Tracking (UID 78).
const NAME: u16 = 1800;
const RENAMED: u16 = 1805;
const FUNCTION: u8 = 4;
const BEAM_FUNCTION: u8 = 4;

#[derive(Default, Clone, Copy)]
struct Faults {
    dropout: bool,
    rename: bool,
    reserved_beam: bool,
    dense: bool,
    half_pulsed: bool,
    no_site: bool,
    repeat_off: bool,
    destroyed: bool,
}

struct Emitter {
    entity: usize,
    target: EntityId,
    start: f64,
    last: f64,
    reports: u32,
    faults: Faults,
    /// The final report went out at this time (`repeat-deactivated` sends a
    /// second one a heartbeat later).
    ended: Option<f64>,
}

#[derive(Default)]
pub(crate) struct Emission {
    next: f64,
    events: u16,
    emitter: Option<Emitter>,
    pending: Faults,
}

/// One EE PDU: one system with one beam, on or Deactivated.
fn ee(tick: &Tick, entity: EntityId, event: u16, e: &Emitter, on: bool) -> Pdu {
    let mut b = minimal_body(EE).expect("EE layout");
    let at = |abs: usize| abs - HEADER_LEN;
    for (i, v) in [
        entity.site,
        entity.application,
        entity.entity,
        entity.site,
        entity.application,
        event,
    ]
    .into_iter()
    .enumerate()
    {
        b[at(12) + 2 * i..at(14) + 2 * i].copy_from_slice(&v.to_be_bytes());
    }
    b[at(25)] = 1;
    let f = e.faults;
    let name = if f.rename && e.reports > 0 { RENAMED } else { NAME };
    // Emitter system: lengths, Emitter System record, location on the entity.
    let mut s = vec![0u8; 20];
    s[1] = 1;
    s[4..6].copy_from_slice(&name.to_be_bytes());
    s[6] = FUNCTION;
    s[7] = 1;
    s[16..20].copy_from_slice(&(-2.0f32).to_be_bytes()); // 2 m above the origin
                                                         // Beam: number, parameter index, fundamental parameters, beam data,
                                                         // function, targets, high density, status, jamming technique.
    let mut beam = vec![0u8; 52];
    beam[1] = if f.reserved_beam { 0 } else { 1 };
    beam[2..4].copy_from_slice(&1u16.to_be_bytes());
    let pw = if f.half_pulsed { 0.0 } else { 1.0 };
    for (i, v) in [9.6e9f32, 1.0e8, 80.0, 1000.0, pw, 0.0, 1.0, 0.0, 0.5]
        .into_iter()
        .enumerate()
    {
        beam[4 + 4 * i..8 + 4 * i].copy_from_slice(&v.to_be_bytes());
    }
    beam[44] = BEAM_FUNCTION;
    beam[45] = 1;
    beam[46] = f.dense as u8;
    beam[47] = (!on) as u8;
    let t = if f.no_site {
        EntityId { site: 0, ..e.target }
    } else {
        e.target
    };
    for v in [t.site, t.application, t.entity] {
        beam.extend(v.to_be_bytes());
    }
    beam.extend([0, 0]); // NO_EMITTER, NO_BEAM: not jamming
    beam[0] = (beam.len() / 4) as u8;
    s.extend(beam);
    s[0] = (s.len() / 4) as u8;
    b.extend(s);
    Pdu {
        header: tick.header(EE),
        body: PduBody::Other(b),
    }
}

impl Family for Emission {
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        let p = &mut self.pending;
        match ev.kind {
            EventKind::EmitterDropout => p.dropout = true,
            EventKind::EmitterRename => p.rename = true,
            EventKind::ReservedBeam => p.reserved_beam = true,
            EventKind::DenseTargets => p.dense = true,
            EventKind::HalfPulsed => p.half_pulsed = true,
            EventKind::NoSiteTarget => p.no_site = true,
            EventKind::RepeatDeactivated => p.repeat_off = true,
            EventKind::DestroyedEmitting => p.destroyed = true,
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let t = tick.t;
        if w.frozen {
            return;
        }
        if let Some(e) = &mut self.emitter {
            let id = w.entities[e.entity].id;
            if !w.entities[e.entity].sending {
                self.emitter = None;
            } else if let Some(ended) = e.ended {
                if e.faults.repeat_off && t - ended >= HEARTBEAT {
                    out.push((w.sender(id.site), ee(tick, id, self.events, e, false)));
                    self.emitter = None;
                } else if !e.faults.repeat_off {
                    self.emitter = None;
                }
            } else if t - e.start >= ON_FOR {
                // A dropout never says goodbye.
                if !e.faults.dropout {
                    out.push((w.sender(id.site), ee(tick, id, self.events, e, false)));
                }
                e.ended = Some(t);
            } else if t - e.last >= HEARTBEAT - 1e-9 {
                if e.faults.destroyed && e.reports == 1 {
                    w.entities[e.entity].destroyed = true;
                    // An appearance change is reported at once (5.3.2.3).
                    w.entities[e.entity].last_sent = f64::NEG_INFINITY;
                }
                if !(e.faults.dropout && e.reports >= 2) {
                    out.push((w.sender(id.site), ee(tick, id, self.events, e, true)));
                    e.reports += 1;
                }
                e.last = t;
            }
            return;
        }
        let Some(every) = w.cfg.emission_every else { return };
        if t + 1e-9 < self.next + every {
            return;
        }
        self.next = t;
        let live: Vec<usize> = (0..w.entities.len())
            .filter(|&i| w.entities[i].sending && !w.entities[i].parked && !w.entities[i].destroyed)
            .collect();
        if live.len() < 2 {
            return;
        }
        let a = live[(w.rng.next_u64() as usize) % live.len()];
        let site = w.entities[a].id.site;
        let others: Vec<usize> = live
            .iter()
            .copied()
            .filter(|&i| w.entities[i].id.site != site)
            .collect();
        let pool = if others.is_empty() { live.clone() } else { others };
        let pool: Vec<usize> = pool.into_iter().filter(|&i| i != a).collect();
        let Some(&b) = pool.get((w.rng.next_u64() as usize) % pool.len().max(1)) else {
            return;
        };
        self.events = self.events.wrapping_add(1);
        let mut e = Emitter {
            entity: a,
            target: w.entities[b].id,
            start: t,
            last: t,
            reports: 0,
            faults: std::mem::take(&mut self.pending),
            ended: None,
        };
        let id = w.entities[a].id;
        out.push((w.sender(id.site), ee(tick, id, self.events, &e, true)));
        e.reports = 1;
        // `destroyed-emitting`: destroyed on the next heartbeat.
        if e.faults.destroyed {
            e.last = t - HEARTBEAT + 1.0;
        }
        self.emitter = Some(e);
    }
}
