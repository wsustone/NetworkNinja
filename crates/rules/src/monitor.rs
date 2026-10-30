//! The monitor: decode → rules → state → metrics, for one stream of datagrams.

use crate::capture::Capture;
use crate::engine::{AlertEvent, Engine, RuleConfig};
use nn_capture::Datagram;
use nn_decode::{decode_datagram_spans, EntityType, Pdu, PduBody};
use nn_state::metrics::entity_of;
use nn_state::{extrapolate, geo, secs, EntityKey, EntityTable, Metric, Metrics, Tags};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

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
    /// Last second the 1 Hz gauges were sampled, and last 10 s slot for the
    /// per-entity ones (ADR 0008).
    last_gauge: i64,
    last_entity_gauge: i64,
    /// PDU capture tiers (ADR 0009); `None` keeps nothing.
    pub capture: Option<Capture>,
    /// Relayed copies dropped before the rules (see `duplicate_window`).
    pub duplicates: u64,
    /// Hash of each recent PDU's bytes → when and from whom it first came.
    recent_pdus: HashMap<u64, (f64, SocketAddr)>,
    last_dedup_prune: f64,
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
        // Live datagrams carry a steady stamp that a host clock step can't move.
        let now = d.monotonic.unwrap_or_else(|| secs(d.received_at));
        self.now = self.now.max(now);
        self.datagrams += 1;
        self.metrics.record_datagram(now, d.source, d.payload.len());
        let mut pdus = Vec::new();
        let mut events = Vec::new();
        for (span, result) in decode_datagram_spans(&d.payload) {
            match result {
                Ok(pdu) => {
                    self.pdus += 1;
                    if self.is_relayed_copy(now, d.source, &d.payload[span.clone()]) {
                        self.duplicates += 1;
                        let tags = Tags {
                            exercise: Some(pdu.header.exercise_id),
                            pdu_type: Some(pdu.type_name()),
                            sender: Some(d.source),
                            ..Default::default()
                        };
                        self.metrics.record(now, Metric::PduDuplicates, tags, 1.0);
                        pdus.push(pdu);
                        continue;
                    }
                    events.extend(self.engine.check_enums(now, &pdu));
                    events.extend(self.engine.before_apply(now, d.source, &pdu, &self.table));
                    self.record_dr_error(now, d.source, &pdu);
                    self.table.apply(now, d.source, &pdu);
                    events.extend(self.engine.after_apply(now, &pdu, &self.table));
                    let etype = self.entity_type_of(&pdu);
                    self.metrics.record_pdu(now, d.source, &pdu, etype);
                    if self.capture.is_some() {
                        let alerted = entity_of(&pdu).is_some_and(|id| {
                            self.engine
                                .active()
                                .any(|a| a.key.id == id && a.key.exercise == pdu.header.exercise_id)
                        });
                        if let Some(c) = self.capture.as_mut() {
                            c.offer(now, d.source, &d.payload[span], &pdu, alerted);
                        }
                    }
                    pdus.push(pdu);
                }
                Err(_) => {
                    self.decode_errors += 1;
                    self.metrics.record_error(now, d.source);
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
        let events = self.engine.tick(now, &self.table);
        self.sample_gauges(now);
        events
    }

    /// Has another sender delivered these exact bytes within the duplicate
    /// window? Then this is a relay's copy: it skips the rules, the entity
    /// table and capture, so it can't pose as a second simulator.
    fn is_relayed_copy(&mut self, now: f64, source: SocketAddr, raw: &[u8]) -> bool {
        use std::hash::{Hash, Hasher};
        let window = self.engine.config.duplicate_window;
        if window <= 0.0 {
            return false;
        }
        if now - self.last_dedup_prune > window {
            self.last_dedup_prune = now;
            self.recent_pdus.retain(|_, (t, _)| now - *t <= window);
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        raw.hash(&mut h);
        match self.recent_pdus.get(&h.finish()) {
            Some((t, from)) if *from != source && now - t <= window && now >= *t => true,
            _ => {
                self.recent_pdus.insert(h.finish(), (now, source));
                false
            }
        }
    }

    /// The PDU's primary entity type: carried by Entity State, looked up in
    /// the table for everything else.
    fn entity_type_of(&self, pdu: &Pdu) -> Option<EntityType> {
        if let PduBody::EntityState(es) = &pdu.body {
            return Some(es.entity_type);
        }
        let id = entity_of(pdu)?;
        self.table
            .get(&EntityKey {
                exercise: pdu.header.exercise_id,
                id,
            })
            .map(|r| r.entity_type)
    }

    /// `entity.dr_error`: how far this report lands from where the sender's
    /// previous report dead-reckons to. Skipped while the exercise is frozen
    /// and for the first report or a stale baseline, like the jump rule.
    fn record_dr_error(&mut self, now: f64, source: SocketAddr, pdu: &Pdu) {
        let PduBody::EntityState(es) = &pdu.body else { return };
        let key = EntityKey {
            exercise: pdu.header.exercise_id,
            id: es.entity_id,
        };
        if self.table.state_for(&key).frozen {
            return;
        }
        let Some(track) = self.table.get(&key).and_then(|r| r.sources.get(&source)) else {
            return;
        };
        let dt = now - track.last_seen;
        if dt <= 0.0 || dt > self.engine.config.timeout() {
            return;
        }
        let err = geo::distance(&extrapolate(&track.last, dt), &es.location);
        let tags = Tags {
            exercise: Some(key.exercise),
            entity: Some(key.id),
            ..Default::default()
        };
        self.metrics.record(now, Metric::DrError, tags, err);
    }

    /// Once a second: `entity.active` by exercise/site/kind/force and
    /// `alerts.open` by exercise/pack/rule/severity. Once per ten-second
    /// slot: each active entity's heartbeat mean and jitter per sender.
    fn sample_gauges(&mut self, now: f64) {
        let second = now.floor() as i64;
        if second <= self.last_gauge {
            return;
        }
        self.last_gauge = second;
        let timeout = self.engine.config.timeout();
        let active = |r: &&nn_state::EntityRecord| !r.removed && now - r.last_seen <= timeout;
        let mut counts: HashMap<Tags, f64> = HashMap::new();
        for r in self.table.entities.values().filter(active) {
            let tags = Tags {
                exercise: Some(r.key.exercise),
                site: Some(r.key.id.site),
                kind: Some(r.entity_type.kind),
                force: Some(r.force_id),
                ..Default::default()
            };
            *counts.entry(tags).or_default() += 1.0;
        }
        for (tags, n) in counts {
            self.metrics.record(now, Metric::EntityActive, tags, n);
        }
        let mut open: HashMap<Tags, f64> = HashMap::new();
        for a in self.engine.active() {
            let tags = Tags {
                exercise: Some(a.key.exercise),
                pack: Some(Arc::from(a.pack.as_str())),
                rule: Some(Arc::from(a.rule_id.as_str())),
                severity: Some(match a.severity {
                    crate::Severity::Critical => "critical",
                    crate::Severity::Warning => "warning",
                }),
                ..Default::default()
            };
            *open.entry(tags).or_default() += 1.0;
        }
        for (tags, n) in open {
            self.metrics.record(now, Metric::AlertsOpen, tags, n);
        }

        let slot = nn_state::metrics::slot_of(second);
        if slot <= self.last_entity_gauge {
            return;
        }
        self.last_entity_gauge = slot;
        let mut samples = Vec::new();
        for r in self.table.entities.values().filter(active) {
            for (addr, src) in &r.sources {
                if src.intervals.count == 0 || now - src.last_seen > timeout {
                    continue;
                }
                let tags = Tags {
                    exercise: Some(r.key.exercise),
                    entity: Some(r.key.id),
                    sender: Some(*addr),
                    ..Default::default()
                };
                samples.push((Metric::HeartbeatMean, tags.clone(), src.intervals.mean));
                samples.push((Metric::HeartbeatJitter, tags, src.intervals.variance().sqrt()));
            }
        }
        for (m, tags, v) in samples {
            self.metrics.record(now, m, tags, v);
        }
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
