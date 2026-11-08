//! Entity management (family 10; IEEE 1278.1 5.9.2, 5.9.5): with
//! `aggregate_every`, a platoon aggregate on the first site sends an
//! Aggregate State every 30 s (HBT_PDU_AGGREGATE_STATE) listing a
//! subaggregate (which sends its own), its live member entities and a
//! silent entity system; and every `aggregate_every` seconds one of its
//! members asks an entity on another site to become a part (IsPartOf, On
//! Station xyz, the part's own type).
//!
//! Faults: `aggregate-stale-member` (a member is removed and stays listed),
//! `aggregate-unknown-member` (lists an entity that doesn't exist),
//! `aggregate-stale-subaggregate` (lists a subaggregate that never reports),
//! `aggregate-appearances` (more appearance records than entities),
//! `part-of-unknown` (the part doesn't exist), `part-of-range-bearing`
//! (range and bearing with a third component), `part-of-type` (the wrong
//! Part Type).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind};
use nn_decode::fields::enum_fields_of;
use nn_decode::structure::minimal_body;
use nn_decode::*;

const AGGREGATE_STATE: u8 = 33;
const IS_PART_OF: u8 = 36;
const HEARTBEAT: f64 = 30.0;
const PLATOON: u16 = 1001;
const SECTION: u16 = 1002;
const NEVER_REPORTS: u16 = 1003;
const ON_STATION_XYZ: u16 = 16;
const ON_STATION_RANGE_BEARING: u16 = 15;

#[derive(Default)]
pub(crate) struct Aggregates {
    last_state: Option<f64>,
    last_part: f64,
    /// Members as last listed: kept listed, gone or not, after the
    /// stale-member fault.
    members: Vec<usize>,
    sticky: bool,
    unknown_member: bool,
    stale_sub: bool,
    appearances: bool,
    part_fault: Option<EventKind>,
}

fn put_id(b: &mut [u8], abs: usize, id: EntityId) {
    let at = abs - HEADER_LEN;
    for (i, v) in [id.site, id.application, id.entity].into_iter().enumerate() {
        b[at + 2 * i..at + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
    }
}

/// An Aggregate State: `subs` and `ents` listed, then one Silent Entity
/// System of `silent` entities with `appearances` records.
fn aggregate_state(
    tick: &Tick,
    id: EntityId,
    subs: &[EntityId],
    ents: &[EntityId],
    silent: u16,
    appearances: u16,
) -> Pdu {
    let mut b = minimal_body(AGGREGATE_STATE).expect("Aggregate State layout");
    for f in enum_fields_of(AGGREGATE_STATE) {
        f.write(&mut b, HEADER_LEN, f.valid);
    }
    put_id(&mut b, 12, id);
    let at = |abs: usize| abs - HEADER_LEN;
    b[at(124)..at(126)].copy_from_slice(&(subs.len() as u16).to_be_bytes());
    b[at(126)..at(128)].copy_from_slice(&(ents.len() as u16).to_be_bytes());
    b[at(130)..at(132)].copy_from_slice(&1u16.to_be_bytes());
    // The ID lists replace the variable datum count, which comes last.
    b.truncate(at(132));
    for id in subs.iter().chain(ents) {
        for v in [id.site, id.application, id.entity] {
            b.extend(v.to_be_bytes());
        }
    }
    while !(b.len() + HEADER_LEN).is_multiple_of(4) {
        b.push(0);
    }
    b.extend(silent.to_be_bytes());
    b.extend(appearances.to_be_bytes());
    b.extend([3, 1, 0, 225, 1, 1, 0, 0]); // dismounted infantry
    for _ in 0..appearances {
        b.extend(0u32.to_be_bytes());
    }
    b.extend(0u32.to_be_bytes()); // no variable datums
    Pdu {
        header: tick.header(AGGREGATE_STATE),
        body: PduBody::Other(b),
    }
}

impl Family for Aggregates {
    fn on_event(&mut self, w: &mut World, _tick: &Tick, ev: &Event, _out: &mut Out) -> Option<bool> {
        match ev.kind {
            EventKind::AggregateStaleMember => {
                // Its first member goes; the aggregate keeps listing it.
                self.sticky = true;
                if let Some(&i) = self.members.first() {
                    w.entities[i].final_due = true;
                }
            }
            EventKind::AggregateUnknownMember => self.unknown_member = true,
            EventKind::AggregateStaleSubaggregate => self.stale_sub = true,
            EventKind::AggregateAppearances => self.appearances = true,
            EventKind::PartOfUnknown | EventKind::PartOfRangeBearing | EventKind::PartOfType => {
                self.part_fault = Some(ev.kind)
            }
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.aggregate_every else { return };
        let t = tick.t;
        if w.frozen {
            return;
        }
        let site = w.cfg.site_base;
        let app = w.cfg.application;
        let alive = |i: usize| {
            let e = &w.entities[i];
            e.sending && !e.final_due && !e.destroyed
        };
        if self.last_state.is_none_or(|l| t - l >= HEARTBEAT - 1e-9) {
            self.last_state = Some(t);
            if !self.sticky || self.members.is_empty() {
                // Two live moving members of the first site, in order.
                self.members = (0..w.entities.len())
                    .filter(|&i| w.entities[i].id.site == site && !w.entities[i].parked && alive(i))
                    .take(2)
                    .collect();
            }
            let mut ents: Vec<EntityId> = self.members.iter().map(|&i| w.entities[i].id).collect();
            if std::mem::take(&mut self.unknown_member) {
                ents.push(EntityId::new(site, app, 999));
            }
            let mut subs = vec![EntityId::new(site, app, SECTION)];
            if self.stale_sub {
                subs.push(EntityId::new(site, app, NEVER_REPORTS));
            }
            let apps = if std::mem::take(&mut self.appearances) { 3 } else { 0 };
            let sender = w.sender(site);
            out.push((
                sender,
                aggregate_state(tick, EntityId::new(site, app, PLATOON), &subs, &ents, 2, apps),
            ));
            out.push((
                sender,
                aggregate_state(tick, EntityId::new(site, app, SECTION), &[], &[], 3, 1),
            ));
        }
        if t - self.last_part < every - 1e-9 || t < every - 1e-9 {
            return;
        }
        self.last_part = t;
        let Some(&host) = self.members.iter().find(|&&i| alive(i)) else {
            return;
        };
        let Some(part) = (0..w.entities.len()).find(|&i| w.entities[i].id.site != site && alive(i)) else {
            return;
        };
        let fault = self.part_fault.take();
        let mut b = minimal_body(IS_PART_OF).expect("IsPartOf layout");
        for f in enum_fields_of(IS_PART_OF) {
            f.write(&mut b, HEADER_LEN, f.valid);
        }
        let at = |abs: usize| abs - HEADER_LEN;
        put_id(&mut b, 12, w.entities[host].id);
        let mut part_id = w.entities[part].id;
        if fault == Some(EventKind::PartOfUnknown) {
            part_id.entity = 999;
        }
        put_id(&mut b, 18, part_id);
        let range_bearing = fault == Some(EventKind::PartOfRangeBearing);
        // On Station xyz (16): x, y, z of the part, in metres. Range and
        // bearing (15) leaves the third component 0, which the fault breaks.
        for (i, v) in [1.0f32, 0.0, 2.0].iter().enumerate() {
            b[at(28) + 4 * i..at(32) + 4 * i].copy_from_slice(&v.to_be_bytes());
        }
        let station = if range_bearing {
            ON_STATION_RANGE_BEARING
        } else {
            ON_STATION_XYZ
        };
        b[at(40)..at(42)].copy_from_slice(&station.to_be_bytes());
        let mut ty = w.entities[part].entity_type;
        if fault == Some(EventKind::PartOfType) {
            ty.category = ty.category.wrapping_add(1);
        }
        let t8 = [
            ty.kind,
            ty.domain,
            (ty.country >> 8) as u8,
            ty.country as u8,
            ty.category,
            ty.subcategory,
            ty.specific,
            ty.extra,
        ];
        b[at(44)..at(52)].copy_from_slice(&t8);
        out.push((
            w.sender(site),
            Pdu {
                header: tick.header(IS_PART_OF),
                body: PduBody::Other(b),
            },
        ));
    }
}
