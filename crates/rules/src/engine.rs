//! The rule engine: three rules over the entity table.

use nn_decode::{EntityType, Pdu, PduBody};
use nn_state::{extrapolate, geo, EntityKey, EntityTable};
use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    EntityTimeout,
    IdConflict,
    PositionJump,
}

impl Rule {
    pub fn name(self) -> &'static str {
        match self {
            Rule::EntityTimeout => "entity-timeout",
            Rule::IdConflict => "id-conflict",
            Rule::PositionJump => "position-jump",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertState {
    Firing,
    Resolved,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alert {
    pub rule: Rule,
    pub key: EntityKey,
    pub severity: Severity,
    /// When the alert started firing.
    pub since: f64,
    pub message: String,
}

/// A change in an alert's state, at time `at`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertEvent {
    pub at: f64,
    pub state: AlertState,
    pub alert: Alert,
    /// Why it fired or resolved, for the alert log.
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct RuleConfig {
    /// Expected Entity State heartbeat, seconds (IEEE 1278.1 default 5 s).
    pub heartbeat: f64,
    /// Timeout = heartbeat × this (IEEE 1278.1 default 2.4).
    pub timeout_multiplier: f64,
    /// A second sender must still be reporting this long after the first
    /// sender's arrival before it counts as a conflict (allows restarts).
    pub conflict_grace: f64,
    /// Smallest position-jump tolerance, metres.
    pub jump_min_tolerance: f64,
    /// Assumed sender dead-reckoning threshold, metres, and the multiple of
    /// it that is tolerated.
    pub assumed_dr_threshold: f64,
    pub jump_dr_multiplier: f64,
    /// Receive-time uncertainty, seconds; tolerance grows by speed × this.
    pub jump_timing_slack: f64,
    /// How often time-based checks run, seconds.
    pub tick_interval: f64,
}

impl Default for RuleConfig {
    fn default() -> Self {
        RuleConfig {
            heartbeat: 5.0,
            timeout_multiplier: 2.4,
            conflict_grace: 2.0,
            jump_min_tolerance: 50.0,
            assumed_dr_threshold: 1.0,
            jump_dr_multiplier: 3.0,
            jump_timing_slack: 0.5,
            tick_interval: 0.25,
        }
    }
}

impl RuleConfig {
    pub fn timeout(&self) -> f64 {
        self.heartbeat * self.timeout_multiplier
    }
}

/// Physical speed cap by entity kind and domain, m/s.
pub fn max_speed(t: &EntityType) -> f64 {
    match (t.kind, t.domain) {
        (1, 1) => 120.0,         // platform, land
        (1, 2) => 1_200.0,       // platform, air
        (1, 3) | (1, 4) => 40.0, // surface, subsurface
        (1, 5) => 12_000.0,      // space
        (2, _) => 3_000.0,       // munition
        (3, _) => 15.0,          // life form
        _ => 3_000.0,
    }
}

fn speed(v: &nn_decode::Vec3f) -> f64 {
    ((v.x * v.x + v.y * v.y + v.z * v.z) as f64).sqrt()
}

#[derive(Debug, Default)]
pub struct Engine {
    pub config: RuleConfig,
    active: BTreeMap<(Rule, EntityKey), Alert>,
    last_tick: f64,
}

impl Engine {
    pub fn new(config: RuleConfig) -> Self {
        Engine {
            config,
            active: BTreeMap::new(),
            last_tick: f64::NEG_INFINITY,
        }
    }

    pub fn active(&self) -> impl Iterator<Item = &Alert> {
        self.active.values()
    }

    pub fn is_active(&self, rule: Rule, key: &EntityKey) -> bool {
        self.active.contains_key(&(rule, *key))
    }

    fn fire(
        &mut self,
        at: f64,
        rule: Rule,
        key: EntityKey,
        severity: Severity,
        message: String,
        out: &mut Vec<AlertEvent>,
    ) {
        if self.active.contains_key(&(rule, key)) {
            return;
        }
        let alert = Alert {
            rule,
            key,
            severity,
            since: at,
            message: message.clone(),
        };
        self.active.insert((rule, key), alert.clone());
        out.push(AlertEvent {
            at,
            state: AlertState::Firing,
            alert,
            reason: message,
        });
    }

    fn resolve(&mut self, at: f64, rule: Rule, key: EntityKey, reason: String, out: &mut Vec<AlertEvent>) {
        if let Some(alert) = self.active.remove(&(rule, key)) {
            out.push(AlertEvent {
                at,
                state: AlertState::Resolved,
                alert,
                reason,
            });
        }
    }

    /// Checks that need the state *before* this PDU is applied.
    pub fn before_apply(&mut self, now: f64, source: SocketAddr, pdu: &Pdu, table: &EntityTable) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        let PduBody::EntityState(es) = &pdu.body else {
            return out;
        };
        let key = EntityKey {
            exercise: pdu.header.exercise_id,
            id: es.entity_id,
        };
        let Some(rec) = table.get(&key) else { return out };
        let last_change = match table.exercises.get(&key.exercise) {
            Some(ex) if ex.frozen => return out,
            Some(ex) => ex.last_change,
            None => 0.0,
        };
        let timeout = self.config.timeout();

        // Position jump: compare with this sender's own previous report.
        // A freeze or resume since that report invalidates the baseline.
        let exercise_changed_since = |t: f64| last_change > t;
        if let Some(track) = rec.sources.get(&source) {
            let dt = now - track.last_seen;
            if dt >= 0.0 && dt <= timeout && !rec.removed && !exercise_changed_since(track.last_seen) {
                let predicted = extrapolate(&track.last, dt);
                let error = geo::distance(&predicted, &es.location);
                let displacement = geo::distance(&track.last.location, &es.location);
                let v = speed(&track.last.velocity).max(speed(&es.linear_velocity));
                let tolerance = self
                    .config
                    .jump_min_tolerance
                    .max(self.config.jump_dr_multiplier * self.config.assumed_dr_threshold)
                    + v * self.config.jump_timing_slack;
                let cap = max_speed(&es.entity_type);
                let too_fast = dt > 0.0 && displacement > tolerance && displacement / dt > cap;
                if error > tolerance || too_fast {
                    let msg = format!(
                        "{} jumped {:.0} m from its dead-reckoned position after {:.1} s (tolerance {:.0} m)",
                        key.id, error, dt, tolerance
                    );
                    self.fire(now, Rule::PositionJump, key, Severity::Warning, msg, &mut out);
                } else {
                    self.resolve(
                        now,
                        Rule::PositionJump,
                        key,
                        "back on its dead-reckoned path".into(),
                        &mut out,
                    );
                }
            }
        }

        // ID conflict: another sender's reports interleave with this one's.
        let my_first = rec.sources.get(&source).map(|t| t.first_seen).unwrap_or(now);
        for (other, track) in &rec.sources {
            if *other == source || now - track.last_seen > timeout {
                continue;
            }
            // The other sender kept reporting well after this one appeared:
            // two live simulators, not one that restarted on a new port.
            let interleaved = track.last_seen > my_first + self.config.conflict_grace;
            let type_clash = track.entity_type != es.entity_type;
            if interleaved || type_clash {
                let why = if type_clash {
                    format!(
                        "with different entity types ({} vs {})",
                        track.entity_type, es.entity_type
                    )
                } else {
                    "at the same time".to_string()
                };
                let msg = format!("{} is claimed by {} and {} {}", key.id, other, source, why);
                self.fire(now, Rule::IdConflict, key, Severity::Critical, msg, &mut out);
                break;
            }
        }
        out
    }

    /// Checks that need the state *after* this PDU is applied.
    pub fn after_apply(&mut self, now: f64, pdu: &Pdu, table: &EntityTable) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        let exercise = pdu.header.exercise_id;
        match &pdu.body {
            PduBody::EntityState(es) => {
                let key = EntityKey {
                    exercise,
                    id: es.entity_id,
                };
                if table.get(&key).is_some_and(|r| !r.removed) {
                    self.resolve(now, Rule::EntityTimeout, key, "reporting again".into(), &mut out);
                }
            }
            PduBody::RemoveEntity(r) => {
                let key = EntityKey {
                    exercise,
                    id: r.receiving,
                };
                for rule in [Rule::EntityTimeout, Rule::PositionJump, Rule::IdConflict] {
                    self.resolve(now, rule, key, "entity removed".into(), &mut out);
                }
            }
            _ => {}
        }
        out
    }

    /// Time-based checks. Cheap to call often: runs at most every
    /// `tick_interval` seconds.
    pub fn tick(&mut self, now: f64, table: &EntityTable) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        if now - self.last_tick < self.config.tick_interval {
            return out;
        }
        self.last_tick = now;
        let timeout = self.config.timeout();

        let running = nn_state::ExerciseState::default();
        for (key, rec) in &table.entities {
            let ex = table.exercises.get(&key.exercise).unwrap_or(&running);
            if rec.removed || rec.deactivated() {
                continue;
            }
            if ex.frozen {
                continue;
            }
            // Only running time counts towards the timeout, and senders get
            // one heartbeat after a resume to start reporting again.
            let silent = ex.running_between(rec.last_seen, now);
            let resume_grace = ex.freezes > 0 && now - ex.last_change < self.config.heartbeat;
            if silent > timeout && !resume_grace && !self.active.contains_key(&(Rule::EntityTimeout, *key)) {
                let msg = format!(
                    "{} ({}) sent no Entity State for {:.1} s of exercise time (timeout {:.1} s)",
                    key.id, rec.marking, silent, timeout
                );
                self.fire(now, Rule::EntityTimeout, *key, Severity::Warning, msg, &mut out);
            }
        }

        // Resolve alerts whose cause has gone away.
        let keys: Vec<(Rule, EntityKey)> = self.active.keys().copied().collect();
        for (rule, key) in keys {
            let rec = table.get(&key);
            match rule {
                Rule::IdConflict => {
                    let live = rec
                        .map(|r| r.sources.values().filter(|t| now - t.last_seen <= timeout).count())
                        .unwrap_or(0);
                    if live <= 1 {
                        self.resolve(now, rule, key, "only one sender left".into(), &mut out);
                    }
                }
                Rule::EntityTimeout => {
                    if rec.is_none_or(|r| r.removed || r.deactivated()) {
                        self.resolve(now, rule, key, "entity removed or deactivated".into(), &mut out);
                    }
                }
                Rule::PositionJump => {
                    if rec.is_none_or(|r| now - r.last_seen > timeout) {
                        self.resolve(now, rule, key, "entity no longer reporting".into(), &mut out);
                    }
                }
            }
        }
        out
    }
}
