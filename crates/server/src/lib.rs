//! Console pipeline for milestone 1: decode datagrams, describe each PDU,
//! and keep running totals.
//!
//! Later milestones replace the console output with entity state, rules and
//! the dashboard; [`Tally`] stays as the cross-check against generator truth.

pub mod auth;
pub mod config;
pub mod evidence;
pub mod names;
pub mod pdustore;
pub mod report;
pub mod store;
pub mod summary;
pub mod tls;
pub mod web;

use nn_capture::Datagram;
use nn_decode::*;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

/// Running totals over everything seen.
#[derive(Debug, Default, Clone)]
pub struct Tally {
    pub datagrams: u64,
    pub bytes: u64,
    pub pdus_by_type: BTreeMap<&'static str, u64>,
    pub errors_by_kind: BTreeMap<&'static str, u64>,
    pub by_version: BTreeMap<u8, u64>,
    pub by_exercise: BTreeMap<u8, u64>,
    pub entities: BTreeSet<EntityId>,
    pub senders: BTreeSet<SocketAddr>,
}

impl Tally {
    pub fn pdus(&self) -> u64 {
        self.pdus_by_type.values().sum()
    }
    pub fn errors(&self) -> u64 {
        self.errors_by_kind.values().sum()
    }

    /// Decode one datagram, update the totals, and return the results.
    pub fn ingest(&mut self, d: &Datagram) -> Vec<Result<Pdu, DecodeError>> {
        self.datagrams += 1;
        self.bytes += d.payload.len() as u64;
        self.senders.insert(d.source);
        let results = decode_datagram(&d.payload);
        for r in &results {
            match r {
                Ok(p) => {
                    *self.pdus_by_type.entry(p.type_name()).or_insert(0) += 1;
                    *self.by_version.entry(p.header.protocol_version).or_insert(0) += 1;
                    *self.by_exercise.entry(p.header.exercise_id).or_insert(0) += 1;
                    if let PduBody::EntityState(e) = &p.body {
                        self.entities.insert(e.entity_id);
                    }
                }
                Err(e) => {
                    let kind = match e {
                        DecodeError::Truncated { .. } => "truncated",
                        DecodeError::BadLength { .. } => "bad-length",
                        DecodeError::LengthMismatch { .. } => "length-mismatch",
                    };
                    *self.errors_by_kind.entry(kind).or_insert(0) += 1;
                }
            }
        }
        results
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "datagrams {}  bytes {}  PDUs {}  decode errors {}  entities {}  senders {}\n",
            self.datagrams,
            self.bytes,
            self.pdus(),
            self.errors(),
            self.entities.len(),
            self.senders.len()
        );
        let join = |m: Vec<String>| if m.is_empty() { "-".to_string() } else { m.join("  ") };
        s += &format!(
            "  by type:     {}\n",
            join(self.pdus_by_type.iter().map(|(k, v)| format!("{k} {v}")).collect())
        );
        s += &format!(
            "  by version:  {}\n",
            join(self.by_version.iter().map(|(k, v)| format!("v{k} {v}")).collect())
        );
        s += &format!(
            "  by exercise: {}\n",
            join(self.by_exercise.iter().map(|(k, v)| format!("ex{k} {v}")).collect())
        );
        if self.errors() > 0 {
            s += &format!(
                "  errors:      {}\n",
                join(self.errors_by_kind.iter().map(|(k, v)| format!("{k} {v}")).collect())
            );
        }
        s
    }
}

/// One-line description of a PDU for the console.
pub fn describe(p: &Pdu) -> String {
    let h = &p.header;
    let head = format!("v{} ex{} {:<12}", h.protocol_version, h.exercise_id, p.type_name());
    let body = match &p.body {
        PduBody::EntityState(e) => {
            let mut flags = Vec::new();
            if e.is_frozen() {
                flags.push("FROZEN");
            }
            if e.is_deactivated() {
                flags.push("DEACTIVATED");
            }
            format!(
                "{:<11} {:<11} type {} force {} DR {}{}{}",
                e.entity_id.to_string(),
                e.marking.text(),
                e.entity_type,
                e.force_id,
                e.dead_reckoning.algorithm,
                if flags.is_empty() { "" } else { " " },
                flags.join(",")
            )
        }
        PduBody::Fire(f) => format!(
            "{} → {}  event {}  range {:.0} m",
            f.firing_entity, f.target_entity, f.event_id.event_number, f.range
        ),
        PduBody::Detonation(d) => format!(
            "{} → {}  event {}  result {}",
            d.firing_entity, d.target_entity, d.event_id.event_number, d.result
        ),
        PduBody::StartResume(s) => format!("from {} to {}  request {}", s.originating, s.receiving, s.request_id),
        PduBody::StopFreeze(s) => format!(
            "from {} to {}  reason {}  request {}",
            s.originating, s.receiving, s.reason, s.request_id
        ),
        PduBody::RemoveEntity(r) => format!("{} removes {}  request {}", r.originating, r.receiving, r.request_id),
        PduBody::EntityStateUpdate(e) => format!(
            "{:<11} appearance 0x{:08x}  {} parameters",
            e.entity_id.to_string(),
            e.appearance,
            e.variable_parameters.len()
        ),
        PduBody::Other(raw) => format!(
            "type {} family {}  {} bytes",
            h.pdu_type,
            h.protocol_family,
            raw.len() + HEADER_LEN
        ),
    };
    format!("{head} {body}")
}
