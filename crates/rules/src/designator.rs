//! Designator (ADR 0010 Wave 2; IEEE 1278.1 5.7.4), on raw PDU bytes:
//! designators keyed by (exercise, designating entity). The heartbeat, and
//! Power 0 as the final report, are the `heartbeat` rule's; this one checks
//! what the standard asks of the spot. Findings, all point events of the
//! `designator` rule:
//!
//! - `spot-offset`: Designated Entity ID D-SPOT_NO_ENTITY (0:0:0) with a
//!   non-zero spot offset from it (5.7.4.3, field 2).
//! - `unknown-target`: a designated entity the exercise doesn't know, once
//!   the monitor has watched a while (5.7.4).
//! - `stale-target`: the designated entity ceased to exist (removed or
//!   Deactivated), but the designator stays on without its final Power 0
//!   report (5.7.4.3 d).
//! - `designator-gone`: the designating entity was removed or deactivated
//!   with its designator still on and no final Power 0 report (5.7.4.3 b).

use crate::interactions::Finding;
use nn_decode::EntityId;
use nn_state::{EntityKey, EntityTable};
use std::collections::HashMap;
use std::net::SocketAddr;

pub const DESIGNATOR: u8 = 24;
const NO_ENTITY: EntityId = EntityId::new(0, 0, 0);

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn f32_at(b: &[u8], at: usize) -> Option<f32> {
    Some(f32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

#[derive(Debug, Clone)]
struct Spot {
    power: f32,
    designated: EntityId,
    source: SocketAddr,
    last_seen: f64,
    /// When the monitor first saw the designated / designating entity gone
    /// while the designator was on.
    target_gone: Option<f64>,
    self_gone: Option<f64>,
    reported_target: bool,
    reported_self: bool,
}

#[derive(Debug, Default)]
pub struct Designators {
    spots: HashMap<(u8, EntityId), Spot>,
    started: Option<f64>,
}

fn gone(table: &EntityTable, key: &EntityKey) -> bool {
    table.get(key).is_some_and(|r| r.removed || r.deactivated())
}

impl Designators {
    /// A Designator PDU's bytes. `grace` is how long to watch before
    /// judging designated entities unknown.
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        table: &EntityTable,
        grace: f64,
    ) -> Vec<Finding> {
        let (Some(&exercise), Some(&DESIGNATOR), Some(designating), Some(designated), Some(power)) =
            (pdu.get(1), pdu.get(2), id_at(pdu, 12), id_at(pdu, 20), f32_at(pdu, 28))
        else {
            return Vec::new();
        };
        let started = *self.started.get_or_insert(now);
        let key = EntityKey {
            exercise,
            id: designating,
        };
        let mut out = Vec::new();
        let base = |facts: &mut crate::engine::Facts| {
            facts.insert(0, ("designating entity", designating.to_string()));
            facts.insert(1, ("designated entity", designated.to_string()));
            facts.insert(2, ("power", format!("{power} W")));
        };
        let spot = [f32_at(pdu, 36), f32_at(pdu, 40), f32_at(pdu, 44)].map(|v| v.unwrap_or(0.0));
        if designated == NO_ENTITY && spot.iter().any(|&v| v != 0.0) {
            let mut facts = vec![(
                "spot offset",
                format!("{}, {}, {} m (expected 0, 0, 0)", spot[0], spot[1], spot[2]),
            )];
            base(&mut facts);
            out.push(Finding {
                kind: "spot-offset",
                key,
                sender: source,
                message: format!(
                    "{designating} designator: the spot is on no entity (D-SPOT_NO_ENTITY), so its offset from the designated entity must be 0, 0, 0{}",
                    cite("5.7.4.3")
                ),
                facts,
            });
        }
        let target = EntityKey {
            exercise,
            id: designated,
        };
        if designated != NO_ENTITY && power > 0.0 && now - started >= grace && table.get(&target).is_none() {
            let mut facts = vec![("in the entity table", "no".to_string())];
            base(&mut facts);
            out.push(Finding {
                kind: "unknown-target",
                key,
                sender: source,
                message: format!(
                    "{designating} designator: designates {designated}, which isn't an entity in the exercise; use D-SPOT_NO_ENTITY (0:0:0) for a spot on no entity{}",
                    cite("5.7.4")
                ),
                facts,
            });
        }
        let s = self.spots.entry((exercise, designating)).or_insert(Spot {
            power,
            designated,
            source,
            last_seen: now,
            target_gone: None,
            self_gone: None,
            reported_target: false,
            reported_self: false,
        });
        if s.designated != designated {
            s.target_gone = None;
            s.reported_target = false;
        }
        s.power = power;
        s.designated = designated;
        s.source = source;
        s.last_seen = now;
        if power <= 0.0 {
            // The final report: nothing more is owed.
            s.target_gone = None;
            s.self_gone = None;
        }
        out
    }

    /// Designators left on after their designated or designating entity
    /// ceased to exist; forget old ones. `window` is how long a final
    /// Power 0 report may take.
    pub fn expire(
        &mut self,
        now: f64,
        window: f64,
        table: &EntityTable,
        frozen: impl Fn(u8, EntityId) -> bool,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        self.spots.retain(|&(exercise, designating), s| {
            if frozen(exercise, designating) || s.power <= 0.0 {
                return now - s.last_seen < 600.0;
            }
            let me = EntityKey { exercise, id: designating };
            let target = EntityKey { exercise, id: s.designated };
            let mut push = |kind, message: String, since: f64, gone_entity: EntityId| {
                out.push(Finding {
                    kind,
                    key: me,
                    sender: s.source,
                    message,
                    facts: vec![
                        ("designating entity", designating.to_string()),
                        ("designated entity", s.designated.to_string()),
                        ("power", format!("{} W", s.power)),
                        ("ceased to exist", format!("{gone_entity}, {:.0} s ago", now - since)),
                        ("final Power 0 report", "not sent".into()),
                    ],
                });
            };
            if s.designated != NO_ENTITY && gone(table, &target) {
                let since = *s.target_gone.get_or_insert(now);
                if now - since > window && !s.reported_target {
                    s.reported_target = true;
                    push(
                        "stale-target",
                        format!(
                            "{designating} designator: still on {} {:.0} s after it ceased to exist; end it with a final Designator PDU with Power 0{}",
                            s.designated,
                            now - since,
                            cite("5.7.4.3 d)")
                        ),
                        since,
                        s.designated,
                    );
                }
            }
            if gone(table, &me) {
                let since = *s.self_gone.get_or_insert(now);
                if now - since > window && !s.reported_self {
                    s.reported_self = true;
                    push(
                        "designator-gone",
                        format!(
                            "{designating} was removed or deactivated with its designator on: it owes a final Designator PDU with Power 0{}",
                            cite("5.7.4.3 b)")
                        ),
                        since,
                        designating,
                    );
                }
            }
            now - s.last_seen < 600.0
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_decode::{
        appearance, DeadReckoning, DisTimestamp, EntityState, EntityType, EulerAngles, Marking, Pdu, PduBody,
        PduHeader, Vec3f, WorldCoord,
    };

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const ME: EntityId = EntityId::new(1, 1, 1);
    const T: EntityId = EntityId::new(2, 1, 1);

    fn designator(designated: EntityId, power: f32, spot: [f32; 3]) -> Vec<u8> {
        let mut b = vec![0u8; 88];
        b[0] = 7;
        b[1] = 1;
        b[2] = DESIGNATOR;
        for (at, id) in [(12, ME), (20, designated)] {
            for (i, v) in [id.site, id.application, id.entity].iter().enumerate() {
                b[at + 2 * i..at + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
            }
        }
        b[28..32].copy_from_slice(&power.to_be_bytes());
        for (i, v) in spot.iter().enumerate() {
            b[36 + 4 * i..40 + 4 * i].copy_from_slice(&v.to_be_bytes());
        }
        b
    }

    /// A table with ME and T; `gone` ones report Deactivated.
    fn table(gone: &[EntityId]) -> EntityTable {
        let mut t = EntityTable::default();
        for id in [ME, T] {
            t.apply(
                0.0,
                src(),
                &Pdu {
                    header: PduHeader::new(7, 1, 1, DisTimestamp(0)),
                    body: PduBody::EntityState(EntityState {
                        entity_id: id,
                        force_id: 1,
                        entity_type: EntityType::default(),
                        alternative_entity_type: EntityType::default(),
                        linear_velocity: Vec3f::default(),
                        location: WorldCoord::default(),
                        orientation: EulerAngles::default(),
                        appearance: if gone.contains(&id) { appearance::DEACTIVATED } else { 0 },
                        dead_reckoning: DeadReckoning::default(),
                        marking: Marking::ascii("T"),
                        capabilities: 0,
                        variable_parameters: Vec::new(),
                    }),
                },
            );
        }
        t
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn a_designation_told_right_is_silent() {
        let t = table(&[]);
        let mut d = Designators::default();
        let mut found = Vec::new();
        for i in 0..5 {
            let now = 5.0 * i as f64;
            found.extend(d.observe(now, src(), &designator(T, 10.0, [0.0, 0.0, 1.5]), &t, 0.0));
            found.extend(d.expire(now + 1.0, 12.0, &t, |_, _| false));
        }
        // A spot on the ground: no entity, no offset.
        found.extend(d.observe(30.0, src(), &designator(NO_ENTITY, 10.0, [0.0; 3]), &t, 0.0));
        // Switched off with Power 0, then its target goes: nothing owed.
        found.extend(d.observe(35.0, src(), &designator(T, 0.0, [0.0; 3]), &t, 0.0));
        found.extend(d.expire(100.0, 12.0, &table(&[T, ME]), |_, _| false));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn spot_and_target_rules_are_named() {
        let t = table(&[]);
        let mut d = Designators::default();
        assert_eq!(
            kinds(&d.observe(0.0, src(), &designator(NO_ENTITY, 10.0, [1.0, 0.0, 0.0]), &t, 0.0)),
            ["spot-offset"]
        );
        let ghost = EntityId::new(9, 9, 9);
        assert_eq!(
            kinds(&d.observe(0.0, src(), &designator(ghost, 10.0, [0.0; 3]), &t, 0.0)),
            ["unknown-target"]
        );
        // Not before the monitor has watched a while.
        let mut d = Designators::default();
        assert!(d
            .observe(0.0, src(), &designator(ghost, 10.0, [0.0; 3]), &t, 144.0)
            .is_empty());
    }

    #[test]
    fn a_designator_left_on_after_an_entity_goes_is_named_once() {
        let mut d = Designators::default();
        d.observe(0.0, src(), &designator(T, 10.0, [0.0; 3]), &table(&[]), 0.0);
        let target_gone = table(&[T]);
        assert!(d.expire(1.0, 12.0, &target_gone, |_, _| false).is_empty());
        assert_eq!(
            kinds(&d.expire(14.0, 12.0, &target_gone, |_, _| false)),
            ["stale-target"]
        );
        assert!(d.expire(20.0, 12.0, &target_gone, |_, _| false).is_empty(), "once");
        let mut d = Designators::default();
        d.observe(0.0, src(), &designator(T, 10.0, [0.0; 3]), &table(&[]), 0.0);
        let self_gone = table(&[ME]);
        d.expire(1.0, 12.0, &self_gone, |_, _| false);
        assert_eq!(
            kinds(&d.expire(14.0, 12.0, &self_gone, |_, _| false)),
            ["designator-gone"]
        );
    }
}
