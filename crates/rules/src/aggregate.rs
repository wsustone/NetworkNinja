//! Entity management: Aggregate State (IEEE 1278.1 5.9.2.2, 7.8.2) and
//! IsPartOf (5.9.5, 7.8.5), on raw PDU bytes. Point events of the
//! `entity-management` rule:
//!
//! - `stale-member`: an Aggregate State lists an entity that no longer
//!   sends Entity States (removed, deactivated or silent past its timeout);
//!   it reverts to a silent entity and leaves the list (5.9.2.2.3 b).
//! - `unknown-member`: it lists an entity the exercise doesn't know, once
//!   the monitor has watched long enough.
//! - `stale-subaggregate`: it lists a subaggregate with no Aggregate State
//!   of its own for heartbeat × multiplier (5.9.2.2.3 a).
//! - `appearance-count`: a Silent Entity System with more appearance
//!   records than entities (5.9.2.2.3 c).
//! - `unknown-host` / `unknown-part`: an IsPartOf naming an entity the
//!   exercise doesn't know (after the same grace).
//! - `range-bearing`: Station Name On Station Range and Bearing (15) with a
//!   non-zero third location component (5.9.5.3 a).
//! - `part-type`: Part Type differs from the part entity's own Entity Type
//!   (5.9.5.2 e).
//!
//! Only specific IDs are judged: an entity or aggregate number of 0 or
//! 65535 names none (the minimal PDUs of `--all-types`).

use crate::interactions::Finding;
use nn_decode::EntityId;
use nn_state::{EntityKey, EntityTable};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

const AGGREGATE_STATE: u8 = 33;
const IS_PART_OF: u8 = 36;
const RANGE_AND_BEARING: u16 = 15;

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

fn specific(id: EntityId) -> bool {
    id.entity != 0 && id.entity != 0xffff
}

/// The rule's limits, in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Watch this long before calling an ID unknown.
    pub grace: f64,
    /// An aggregate's own Aggregate State is due within this.
    pub aggregate_timeout: f64,
}

#[derive(Debug, Default)]
pub struct Aggregates {
    /// When each aggregate last sent its own Aggregate State.
    heard: HashMap<(u8, EntityId), f64>,
    /// (aggregate, listed ID, finding) already reported while still listed.
    reported: HashSet<(u8, EntityId, EntityId, &'static str)>,
    started: Option<f64>,
}

impl Aggregates {
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        table: &EntityTable,
        limits: &Limits,
        timeout_of: impl Fn(&nn_state::EntityRecord) -> f64,
    ) -> Vec<Finding> {
        let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
            return Vec::new();
        };
        if pdu_type != AGGREGATE_STATE && pdu_type != IS_PART_OF {
            return Vec::new();
        }
        let started = *self.started.get_or_insert(now);
        let watched = now - started >= limits.grace;
        let mut out = Vec::new();
        if pdu_type == AGGREGATE_STATE {
            self.aggregate(now, source, pdu, (table, &timeout_of), limits, watched, &mut out);
        } else {
            self.part_of(source, exercise, pdu, table, watched, &mut out);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn aggregate(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        (table, timeout_of): (&EntityTable, &dyn Fn(&nn_state::EntityRecord) -> f64),
        limits: &Limits,
        watched: bool,
        out: &mut Vec<Finding>,
    ) {
        let exercise = pdu[1];
        let (Some(agg), Some(aggs), Some(ents), Some(silent_aggs), Some(silent_ents)) = (
            id_at(pdu, 12),
            u16_at(pdu, 124),
            u16_at(pdu, 126),
            u16_at(pdu, 128),
            u16_at(pdu, 130),
        ) else {
            return;
        };
        if !specific(agg) {
            return;
        }
        self.heard.insert((exercise, agg), now);
        let key = EntityKey { exercise, id: agg };
        let mut listed = HashSet::new();
        let mut push = |kind: &'static str, message: String, facts: crate::engine::Facts| {
            let mut f = vec![("aggregate", agg.to_string())];
            f.extend(facts);
            out.push(Finding {
                kind,
                key,
                sender: source,
                message: format!("aggregate {agg}: {message}"),
                facts: f,
            });
        };
        // Subaggregates, then entities: 6 bytes each from 132.
        for i in 0..aggs as usize + ents as usize {
            let Some(id) = id_at(pdu, 132 + 6 * i) else { break };
            listed.insert(id);
            if !specific(id) {
                continue;
            }
            let is_sub = i < aggs as usize;
            let finding = if is_sub {
                let silent = match self.heard.get(&(exercise, id)) {
                    Some(&at) => now - at > limits.aggregate_timeout,
                    None => watched,
                };
                silent.then(|| {
                    (
                        "stale-subaggregate",
                        format!(
                            "lists subaggregate {id}, which sends no Aggregate State of its own; it reverts to silent and leaves the list{}",
                            cite("5.9.2.2.3 a)")
                        ),
                        vec![("subaggregate", id.to_string())],
                    )
                })
            } else {
                let ek = EntityKey { exercise, id };
                match table.get(&ek) {
                    Some(r) if r.removed || r.deactivated() || now - r.last_seen > timeout_of(r) => Some((
                        "stale-member",
                        format!(
                            "lists entity {id}, which no longer sends Entity States; it reverts to silent and leaves the list{}",
                            cite("5.9.2.2.3 b)")
                        ),
                        vec![
                            ("member", id.to_string()),
                            ("entity", if r.removed || r.deactivated() { "removed or deactivated".into() } else { format!("silent {:.0} s", now - r.last_seen) }),
                        ],
                    )),
                    Some(_) => None,
                    None if watched => Some((
                        "unknown-member",
                        format!("lists entity {id}, which isn't an entity in the exercise{}", cite("5.9.2.2.3 b)")),
                        vec![("member", id.to_string()), ("in the entity table", "no".into())],
                    )),
                    None => None,
                }
            };
            if let Some((kind, message, facts)) = finding {
                if self.reported.insert((exercise, agg, id, kind)) {
                    push(kind, message, facts);
                }
            }
        }
        // Reported IDs that left the list may be reported again later.
        self.reported
            .retain(|(ex, a, id, _)| *ex != exercise || *a != agg || listed.contains(id));
        // Silent Entity Systems: after the ID lists (padded to 32 bits) and
        // the 12-byte Silent Aggregate Systems.
        let mut at = (132 + 6 * (aggs as usize + ents as usize)).div_ceil(4) * 4 + 12 * silent_aggs as usize;
        for _ in 0..silent_ents {
            let (Some(n), Some(apps)) = (u16_at(pdu, at), u16_at(pdu, at + 2)) else {
                break;
            };
            if apps > n {
                push(
                    "appearance-count",
                    format!(
                        "a Silent Entity System has {apps} appearance records for {n} entities; at most one per entity{}",
                        cite("5.9.2.2.3 c)")
                    ),
                    vec![
                        ("number of entities", n.to_string()),
                        ("appearance records", apps.to_string()),
                    ],
                );
                break;
            }
            at += 12 + 4 * apps as usize;
        }
    }

    fn part_of(
        &mut self,
        source: SocketAddr,
        exercise: u8,
        pdu: &[u8],
        table: &EntityTable,
        watched: bool,
        out: &mut Vec<Finding>,
    ) {
        let (Some(host), Some(part), Some(c), Some(station)) =
            (id_at(pdu, 12), id_at(pdu, 18), f32_at(pdu, 36), u16_at(pdu, 40))
        else {
            return;
        };
        if !specific(host) || !specific(part) {
            return;
        }
        let key = EntityKey { exercise, id: host };
        let mut push = |kind: &'static str, message: String, facts: crate::engine::Facts| {
            let mut f = vec![("host entity", host.to_string()), ("part entity", part.to_string())];
            f.extend(facts);
            out.push(Finding {
                kind,
                key,
                sender: source,
                message: format!("IsPartOf {host} ← {part}: {message}"),
                facts: f,
            });
        };
        for (kind, id, role) in [("unknown-host", host, "host"), ("unknown-part", part, "part")] {
            if watched && table.get(&EntityKey { exercise, id }).is_none() {
                push(
                    kind,
                    format!(
                        "the {role} entity {id} isn't an entity in the exercise{}",
                        cite("5.9.5")
                    ),
                    vec![("in the entity table", "no".into())],
                );
            }
        }
        if station == RANGE_AND_BEARING && c != 0.0 {
            push(
                "range-bearing",
                format!(
                    "On Station Range and Bearing gives range and bearing; the third location component must be 0, not {c}{}",
                    cite("5.9.5.3 a)")
                ),
                vec![("station name", "On Station Range and Bearing (15)".into()), ("component C", c.to_string())],
            );
        }
        if let (Some(r), Some(t)) = (table.get(&EntityKey { exercise, id: part }), pdu.get(44..52)) {
            let declared = format!(
                "{}.{}.{}.{}.{}.{}.{}",
                t[0],
                t[1],
                u16::from_be_bytes([t[2], t[3]]),
                t[4],
                t[5],
                t[6],
                t[7]
            );
            if declared != r.entity_type.to_string() {
                push(
                    "part-type",
                    format!(
                        "Part Type is {declared}, but {part} reports itself as {}{}",
                        r.entity_type,
                        cite("5.9.5.2 e)")
                    ),
                    vec![
                        ("part type", declared),
                        ("entity type reported", r.entity_type.to_string()),
                    ],
                );
            }
        }
    }

    /// Forget aggregates not heard from in an hour.
    pub fn expire(&mut self, now: f64) {
        self.heard.retain(|_, at| now - *at < 3600.0);
    }
}
