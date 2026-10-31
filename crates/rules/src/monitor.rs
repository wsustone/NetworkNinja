//! The monitor: decode → rules → state → metrics, for one stream of datagrams.

use crate::capture::Capture;
use crate::engine::{AlertEvent, Engine, RuleConfig};
use nn_capture::Datagram;
use nn_decode::{decode_datagram_spans, structure, EntityType, Pdu, PduBody};
use nn_state::metrics::entity_of;
use nn_state::{extrapolate, geo, secs, EntityKey, EntityTable, Metric, Metrics, Tags};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

/// Entities silent this long are dropped from the table, seconds.
pub const ENTITY_EXPIRY: f64 = 600.0;

/// What [`Monitor::copy_of`] made of a PDU's bytes.
#[derive(Debug, Clone, PartialEq)]
enum Copy {
    No,
    /// Another sender's copy: a relay.
    Relay,
    /// The same sender's again: one send delivered twice. `first` is the
    /// listener the first copy came through.
    Echo {
        first: Option<Arc<str>>,
        gap: f64,
    },
}

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
    /// Hash of each recent PDU's bytes → when, from whom and through which
    /// listener it first came.
    recent_pdus: HashMap<u64, (f64, SocketAddr, Option<Arc<str>>)>,
    /// Second deliveries of one send dropped (`duplicate-delivery`).
    pub echoes: u64,
    /// When each (sender, kind) duplicate-delivery finding last fired.
    echo_reported: HashMap<(SocketAddr, &'static str), f64>,
    /// The listener each sender was last heard through.
    via: HashMap<SocketAddr, Arc<str>>,
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
        if let Some(l) = &d.listener {
            if self.via.get(&d.source) != Some(l) {
                self.via.insert(d.source, Arc::clone(l));
            }
        }
        self.metrics.record_datagram(now, d.source, d.payload.len());
        let mut pdus = Vec::new();
        let mut events = Vec::new();
        let decoded = decode_datagram_spans(&d.payload);
        // Each PDU's neighbours in the bundle, for Coupled PDU Extension.
        let spans: Vec<_> = decoded.iter().map(|(span, _)| span.clone()).collect();
        for (i, (span, result)) in decoded.into_iter().enumerate() {
            if result.is_ok() {
                self.pdus += 1;
            }
            // A relay's copy, or a second delivery of one send, skips every
            // check, malformed or not: a gateway can't pose as a second
            // simulator, and nothing is counted twice.
            let copy = self.copy_of(now, d, &d.payload[span.clone()]);
            if copy != Copy::No {
                self.duplicates += 1;
                let pdu_type = d.payload.get(span.start + 2).copied();
                let exercise = d.payload.get(span.start + 1).copied();
                let tags = Tags {
                    exercise,
                    pdu_type: pdu_type.map(nn_decode::pdu_type_name),
                    sender: Some(d.source),
                    ..Default::default()
                };
                self.metrics.record(now, Metric::PduDuplicates, tags, 1.0);
                if let Copy::Echo { first, gap } = &copy {
                    self.echoes += 1;
                    events.extend(self.report_echo(now, d, first.clone(), *gap, &d.payload[span.clone()]));
                }
                if let Ok(pdu) = result {
                    pdus.push(pdu);
                }
                continue;
            }
            // Tier S (ADR 0010): structure is checked on the raw bytes, so a
            // PDU the decoder rejects is still reported against its sender.
            let structure = structure::check(&d.payload[span.start..]);
            events.extend(self.engine.check_structure(now, d.source, &structure));
            let near = |j: Option<usize>| j.and_then(|j| spans.get(j)).map(|s| &d.payload[s.clone()]);
            events.extend(self.engine.check_attribute(
                now,
                d.source,
                &d.payload[span.clone()],
                near(i.checked_sub(1)),
                near(Some(i + 1)),
            ));
            match result {
                Ok(pdu) => {
                    let pdu = self.merge_update(pdu);
                    events.extend(self.engine.check_siman(now, d.source, &d.payload[span.clone()]));
                    events.extend(self.engine.check_radio(now, d.source, &d.payload[span.clone()]));
                    self.engine.observe_heartbeat(now, d.source, &d.payload[span.clone()]);
                    events.extend(self.engine.check_lifecycle(now, d.source, &pdu, &self.table));
                    events.extend(self.engine.check_warfare(now, d.source, &pdu, &self.table));
                    events.extend(
                        self.engine
                            .check_interactions(now, d.source, &d.payload[span.clone()], &self.table),
                    );
                    events.extend(self.engine.check_enums(now, d.source, &pdu));
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

    /// Is this PDU a copy of one already seen? From another sender within
    /// `duplicate_window`: a relay's. From the same sender within
    /// `echo_window`: the same send delivered twice.
    fn copy_of(&mut self, now: f64, d: &Datagram, raw: &[u8]) -> Copy {
        use std::hash::{Hash, Hasher};
        let (relay, echo) = (self.engine.config.duplicate_window, self.engine.config.echo_window);
        let keep = relay.max(echo);
        if keep <= 0.0 {
            return Copy::No;
        }
        if now - self.last_dedup_prune > keep {
            self.last_dedup_prune = now;
            self.recent_pdus.retain(|_, (t, _, _)| now - *t <= keep);
        }
        let mut h = std::collections::hash_map::DefaultHasher::new();
        raw.hash(&mut h);
        let key = h.finish();
        match self.recent_pdus.get(&key) {
            Some((t, from, _)) if *from != d.source && now - t <= relay && now >= *t => Copy::Relay,
            Some((t, from, l)) if *from == d.source && now - t <= echo && now >= *t => Copy::Echo {
                first: l.clone(),
                gap: now - t,
            },
            _ => {
                self.recent_pdus.insert(key, (now, d.source, d.listener.clone()));
                Copy::No
            }
        }
    }

    /// A duplicate-delivery finding, at most once per sender and kind every
    /// `enum_repeat` seconds (the engine's per-entity limit isn't enough: a
    /// sender's whole stream is doubled, entity by entity).
    fn report_echo(
        &mut self,
        now: f64,
        d: &Datagram,
        first: Option<Arc<str>>,
        gap: f64,
        raw: &[u8],
    ) -> Vec<AlertEvent> {
        let overlap = match (&first, &d.listener) {
            (Some(a), Some(b)) if a != b => Some((a.clone(), b.clone())),
            _ => None,
        };
        let kind = if overlap.is_some() {
            "listener-overlap"
        } else {
            "network-duplicate"
        };
        let repeat = self.engine.repeat_seconds();
        if self
            .echo_reported
            .get(&(d.source, kind))
            .is_some_and(|t| now - t < repeat)
        {
            return Vec::new();
        }
        self.echo_reported.insert((d.source, kind), now);
        let message = match overlap {
            Some((a, b)) => format!(
                "{}'s datagrams reach two listeners, '{a}' and '{b}': each is counted once; change the listeners so they don't overlap (docs/capture.md)",
                d.source
            ),
            None => format!(
                "{}'s datagrams arrive twice{} within {:.0} ms: a network loop, a sender transmitting on two paths, or a gateway echoing them back; each is counted once",
                d.source,
                d.listener.as_ref().map_or(String::new(), |l| format!(" on listener '{l}'")),
                gap * 1000.0
            ),
        };
        let exercise = raw.get(1).copied().unwrap_or(0);
        let id = raw
            .get(2)
            .and_then(|&t| nn_decode::structure::first_id(t, raw.get(nn_decode::HEADER_LEN..)?))
            .unwrap_or_default();
        let mut out = Vec::new();
        self.engine.point_event(
            now,
            crate::engine::Rule::DuplicateDelivery,
            kind,
            EntityKey { exercise, id },
            Some(d.source),
            message,
            &mut out,
        );
        out
    }

    /// An Entity State Update, merged with its entity's last Entity State
    /// into a full Entity State (type, marking and dead-reckoning settings
    /// from that report), so the table and every rule treat it as one: a
    /// simulation may heartbeat with updates (5.3.5.3 c). The header keeps
    /// type 67, so metrics and the console still call it an update. An
    /// update for an entity never seen in full passes through unchanged.
    fn merge_update(&self, pdu: Pdu) -> Pdu {
        let PduBody::EntityStateUpdate(u) = &pdu.body else {
            return pdu;
        };
        let key = EntityKey {
            exercise: pdu.header.exercise_id,
            id: u.entity_id,
        };
        let Some(rec) = self.table.get(&key) else {
            return pdu;
        };
        let k = rec.kinematics();
        let es = nn_decode::EntityState {
            entity_id: u.entity_id,
            force_id: rec.force_id,
            entity_type: rec.entity_type,
            alternative_entity_type: rec.entity_type,
            linear_velocity: u.linear_velocity,
            location: u.location,
            orientation: u.orientation,
            appearance: u.appearance,
            dead_reckoning: nn_decode::DeadReckoning {
                algorithm: k.algorithm,
                linear_acceleration: k.acceleration,
                ..Default::default()
            },
            marking: nn_decode::Marking::ascii(&rec.marking),
            capabilities: 0,
            variable_parameters: u.variable_parameters.clone(),
        };
        Pdu {
            header: pdu.header,
            body: PduBody::EntityState(es),
        }
    }

    /// The listener a sender was last heard through (live capture only).
    pub fn via(&self, sender: &SocketAddr) -> Option<&str> {
        self.via.get(sender).map(|s| &**s)
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
        if dt <= 0.0 || dt > self.engine.config.timeout_for(&track.last) {
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
        let cfg = &self.engine.config;
        let active = |r: &&nn_state::EntityRecord| !r.removed && now - r.last_seen <= cfg.timeout_of(r);
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
                if src.intervals.count == 0 || now - src.last_seen > cfg.timeout_for(&src.last) {
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
        let cfg = &self.engine.config;
        self.table
            .entities
            .values()
            .filter(|r| !r.removed && self.now - r.last_seen <= cfg.timeout_of(r))
            .count()
    }
}
