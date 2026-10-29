//! The monitor: decode → rules → state → metrics, for one stream of datagrams.

use crate::engine::{AlertEvent, Engine, RuleConfig};
use nn_capture::Datagram;
use nn_decode::{decode_datagram, Pdu};
use nn_state::{secs, EntityTable, Metrics};

/// Entities silent this long are dropped from the table, seconds.
pub const ENTITY_EXPIRY: f64 = 600.0;

#[derive(Debug, Default)]
pub struct Monitor {
    pub table: EntityTable,
    pub metrics: Metrics,
    pub engine: Engine,
    pub datagrams: u64,
    pub pdus: u64,
    pub decode_errors: u64,
    /// Latest time seen, seconds since the epoch.
    pub now: f64,
    last_prune: f64,
}

impl Monitor {
    /// Base-pack enum checks and defaults with an explicit threshold config.
    pub fn new(config: RuleConfig) -> Self {
        Monitor {
            engine: Engine::new(config),
            ..Default::default()
        }
    }

    /// Everything from merged rule packs: thresholds, toggles and checks.
    pub fn with_packs(packs: &crate::pack::Merged) -> Self {
        Monitor {
            engine: Engine::with_packs(packs),
            ..Default::default()
        }
    }

    /// Decode a datagram and run it through the rules and state.
    /// Returns the decoded PDUs (for display) and any alert changes.
    pub fn ingest(&mut self, d: &Datagram) -> (Vec<Pdu>, Vec<AlertEvent>) {
        let now = secs(d.received_at);
        self.now = self.now.max(now);
        self.datagrams += 1;
        self.metrics.record_datagram(now, d.payload.len());
        let mut pdus = Vec::new();
        let mut events = Vec::new();
        for result in decode_datagram(&d.payload) {
            match result {
                Ok(pdu) => {
                    self.pdus += 1;
                    events.extend(self.engine.check_enums(now, &pdu));
                    events.extend(self.engine.before_apply(now, d.source, &pdu, &self.table));
                    self.table.apply(now, d.source, &pdu);
                    events.extend(self.engine.after_apply(now, &pdu, &self.table));
                    self.metrics.record_pdu(now, &pdu);
                    pdus.push(pdu);
                }
                Err(_) => {
                    self.decode_errors += 1;
                    self.metrics.record_error(now);
                }
            }
        }
        events.extend(self.tick(now));
        (pdus, events)
    }

    /// Advance time with no traffic (call regularly when live).
    pub fn tick(&mut self, now: f64) -> Vec<AlertEvent> {
        self.now = self.now.max(now);
        if now - self.last_prune > 60.0 {
            self.last_prune = now;
            self.table.prune(now, ENTITY_EXPIRY);
        }
        self.engine.tick(now, &self.table)
    }

    /// Entities currently reporting (not removed, heard within the timeout).
    pub fn active_entities(&self) -> usize {
        let timeout = self.engine.config.timeout();
        self.table
            .entities
            .values()
            .filter(|r| !r.removed && self.now - r.last_seen <= timeout)
            .count()
    }
}
