//! The rule engine: three behavioural rules over the entity table, plus
//! per-PDU enumeration checks loaded from rule packs.

use crate::pack::{EnumCheck, Merged};
use nn_decode::structure::Report;
use nn_decode::{EntityId, EntityType, Pdu, PduBody};
use nn_state::{extrapolate, geo, EntityKey, EntityTable};
use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    EntityTimeout,
    IdConflict,
    PositionJump,
    /// A pack `[[enum]]` check failed.
    EnumViolation,
    /// Tier S (ADR 0010): a PDU's length doesn't match its layout and
    /// counts, or the datagram cuts it off.
    PduStructure,
    /// Tier S: a PDU carries bytes its layout doesn't account for, or lacks
    /// its alignment padding.
    PduPadding,
    /// The Protocol Family field doesn't match the PDU type.
    PduFamily,
}

impl Rule {
    pub fn name(self) -> &'static str {
        match self {
            Rule::EntityTimeout => "entity-timeout",
            Rule::IdConflict => "id-conflict",
            Rule::PositionJump => "position-jump",
            Rule::EnumViolation => "enum-violation",
            Rule::PduStructure => "pdu-structure",
            Rule::PduPadding => "pdu-padding",
            Rule::PduFamily => "pdu-family",
        }
    }

    /// Rule section names in pack files.
    pub fn from_name(name: &str) -> Option<Rule> {
        match name {
            "entity-timeout" => Some(Rule::EntityTimeout),
            "id-conflict" => Some(Rule::IdConflict),
            "position-jump" => Some(Rule::PositionJump),
            "pdu-structure" => Some(Rule::PduStructure),
            "pdu-padding" => Some(Rule::PduPadding),
            "pdu-family" => Some(Rule::PduFamily),
            _ => None,
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
    /// Pack id that contributed this rule or check, and its name within
    /// the pack (`entity-timeout`, or the enum field path).
    pub pack: String,
    pub rule_id: String,
    pub key: EntityKey,
    pub severity: Severity,
    /// When the alert started firing.
    pub since: f64,
    pub message: String,
    /// The sender the alert is attributed to (ADR 0008 conformance view):
    /// the PDU's source for enum checks and jumps, the silent sender for a
    /// timeout, the later arrival for an ID conflict.
    pub sender: Option<SocketAddr>,
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
    /// The same PDU bytes from a second sender within this many seconds are
    /// a relay's copy (gateway, second NIC, SPAN), not a second simulator.
    pub duplicate_window: f64,
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
            duplicate_window: 1.0,
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

/// An operator acknowledgement on a firing alert.
#[derive(Debug, Clone, PartialEq)]
pub struct Ack {
    pub at: f64,
    pub by: String,
    pub note: String,
}

/// What a mute suppresses: one rule id everywhere, or everything on one entity.
#[derive(Debug, Clone, PartialEq)]
pub enum MuteScope {
    Rule(String),
    Entity(EntityKey),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mute {
    pub scope: MuteScope,
    pub until: f64,
}

/// The entity a PDU is about, for keying alerts that don't track entity
/// state: for types that aren't deep decoded, the layout's first
/// identifier. `0:0:0` for PDUs with none (e.g. an unknown type).
fn primary_entity(pdu: &Pdu) -> EntityId {
    match &pdu.body {
        PduBody::EntityState(e) => e.entity_id,
        PduBody::Fire(f) => f.firing_entity,
        PduBody::Detonation(d) => d.firing_entity,
        PduBody::StartResume(s) => s.originating,
        PduBody::StopFreeze(s) => s.originating,
        PduBody::RemoveEntity(r) => r.originating,
        PduBody::Other(body) => nn_decode::structure::first_id(pdu.header.pdu_type, body).unwrap_or_default(),
    }
}

#[derive(Debug, Default)]
pub struct Engine {
    pub config: RuleConfig,
    enabled: BTreeMap<Rule, bool>,
    severities: BTreeMap<Rule, Severity>,
    /// Pack id that last configured each rule, for alert citation.
    rule_pack: BTreeMap<Rule, String>,
    enum_checks: Vec<EnumCheck>,
    enum_repeat: f64,
    /// Last time each (field, entity) violation fired.
    enum_last: BTreeMap<(&'static str, EntityKey), f64>,
    /// Last time each structural rule fired for a (PDU type, sender).
    structure_last: BTreeMap<(Rule, Option<u8>, SocketAddr), f64>,
    active: BTreeMap<(Rule, EntityKey), Alert>,
    /// Operator acknowledgements, keyed by (rule_id, entity).
    acks: BTreeMap<(String, EntityKey), Ack>,
    /// Active mutes (entity or rule, each with an expiry).
    mutes: Vec<Mute>,
    last_tick: f64,
}

impl Engine {
    /// Base-pack checks and toggles with an explicit threshold config.
    pub fn new(config: RuleConfig) -> Self {
        let mut e = Engine::with_packs(crate::pack::builtin());
        e.config = config;
        e
    }

    /// Everything from the merged packs: thresholds, toggles, severities
    /// and enum checks.
    pub fn with_packs(p: &Merged) -> Self {
        Engine {
            config: p.config.clone(),
            enabled: p.enabled.clone(),
            severities: p.severities.clone(),
            rule_pack: p.rule_pack.clone(),
            enum_checks: p.enum_checks.clone(),
            enum_repeat: p.enum_repeat_seconds,
            enum_last: BTreeMap::new(),
            structure_last: BTreeMap::new(),
            active: BTreeMap::new(),
            acks: BTreeMap::new(),
            mutes: Vec::new(),
            last_tick: f64::NEG_INFINITY,
        }
    }

    pub fn enabled(&self, rule: Rule) -> bool {
        self.enabled.get(&rule).copied().unwrap_or(true)
    }

    pub fn active(&self) -> impl Iterator<Item = &Alert> {
        self.active.values()
    }

    pub fn is_active(&self, rule: Rule, key: &EntityKey) -> bool {
        self.active.contains_key(&(rule, *key))
    }

    /// Is this rule/entity combination muted right now?
    pub fn muted(&self, rule_id: &str, key: &EntityKey, now: f64) -> bool {
        self.mutes.iter().any(|m| {
            m.until > now
                && match &m.scope {
                    MuteScope::Rule(r) => r == rule_id,
                    MuteScope::Entity(k) => k == key,
                }
        })
    }

    /// Acknowledge a firing alert (matched by its rule_id and entity).
    pub fn ack(&mut self, rule_id: &str, key: EntityKey, by: &str, note: &str, at: f64) -> bool {
        if !self.active.values().any(|a| a.rule_id == rule_id && a.key == key) {
            return false;
        }
        self.acks.insert(
            (rule_id.to_string(), key),
            Ack {
                at,
                by: by.to_string(),
                note: note.to_string(),
            },
        );
        true
    }

    /// The ack on an active alert, if any.
    pub fn ack_of(&self, rule_id: &str, key: &EntityKey) -> Option<&Ack> {
        self.acks.get(&(rule_id.to_string(), *key))
    }

    /// Mute a rule id (behavioural name or enum field path) everywhere.
    pub fn mute_rule(&mut self, rule_id: &str, until: f64) {
        self.mutes.push(Mute {
            scope: MuteScope::Rule(rule_id.to_string()),
            until,
        });
    }

    /// Mute everything on an entity and resolve its open alerts.
    pub fn mute_entity(&mut self, key: EntityKey, until: f64, now: f64) -> Vec<AlertEvent> {
        self.mutes.push(Mute {
            scope: MuteScope::Entity(key),
            until,
        });
        let mut out = Vec::new();
        let keys: Vec<(Rule, EntityKey)> = self.active.keys().filter(|(_, k)| *k == key).copied().collect();
        for (rule, k) in keys {
            self.resolve(now, rule, k, "muted".into(), &mut out);
        }
        out
    }

    /// Remove mutes matching a scope exactly.
    pub fn unmute(&mut self, scope: &MuteScope) -> usize {
        let before = self.mutes.len();
        self.mutes.retain(|m| &m.scope != scope);
        before - self.mutes.len()
    }

    /// Active mutes (for the health/state feed).
    pub fn mutes(&self) -> &[Mute] {
        &self.mutes
    }

    fn fire(
        &mut self,
        at: f64,
        rule: Rule,
        key: EntityKey,
        sender: Option<SocketAddr>,
        message: String,
        out: &mut Vec<AlertEvent>,
    ) {
        if self.active.contains_key(&(rule, key)) || !self.enabled(rule) || self.muted(rule.name(), &key, at) {
            return;
        }
        let alert = Alert {
            rule,
            pack: self.rule_pack.get(&rule).cloned().unwrap_or_else(|| "builtin".into()),
            rule_id: rule.name().to_string(),
            key,
            severity: self.severities.get(&rule).copied().unwrap_or(Severity::Warning),
            since: at,
            message: message.clone(),
            sender,
        };
        self.active.insert((rule, key), alert.clone());
        out.push(AlertEvent {
            at,
            state: AlertState::Firing,
            alert,
            reason: message,
        });
    }

    /// Enum violations are point events, not states: they fire once and do
    /// not stay open, and repeat at most every `enum_repeat` seconds.
    fn fire_once(
        &mut self,
        at: f64,
        key: EntityKey,
        sender: SocketAddr,
        check: &EnumCheck,
        value: u64,
        out: &mut Vec<AlertEvent>,
    ) {
        if self.muted(check.spec.name, &key, at) {
            return;
        }
        let dedup = (check.spec.name, key);
        if self.enum_last.get(&dedup).is_some_and(|t| at - t < self.enum_repeat) {
            return;
        }
        self.enum_last.insert(dedup, at);
        let message = match &check.source {
            Some(source) => format!("{} {} = {} is not defined in {source}", key.id, check.spec.name, value),
            None => format!(
                "{} {} = {} is outside the allowed set ({})",
                key.id,
                check.spec.name,
                value,
                check.allowed_str()
            ),
        };
        out.push(AlertEvent {
            at,
            state: AlertState::Firing,
            alert: Alert {
                rule: Rule::EnumViolation,
                pack: check.pack.clone(),
                rule_id: check.spec.name.to_string(),
                key,
                severity: check.severity,
                since: at,
                message: message.clone(),
                sender: Some(sender),
            },
            reason: message,
        });
    }

    /// The packs' enumeration checks on one decoded PDU.
    pub fn check_enums(&mut self, now: f64, source: SocketAddr, pdu: &Pdu) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        let key = EntityKey {
            exercise: pdu.header.exercise_id,
            id: primary_entity(pdu),
        };
        for i in 0..self.enum_checks.len() {
            if let Some(v) = self.enum_checks[i].violation(pdu) {
                let check = self.enum_checks[i].clone();
                self.fire_once(now, key, source, &check, v, &mut out);
            }
        }
        out
    }

    /// Tier S findings on one PDU (ADR 0010). Like enum violations they are
    /// point events, repeating at most every `enum_repeat` seconds per rule,
    /// PDU type and sender; each cites the layout clause it checks.
    pub fn check_structure(&mut self, now: f64, source: SocketAddr, report: &Report) -> Vec<AlertEvent> {
        let mut out = Vec::new();
        let key = EntityKey {
            exercise: report.exercise.unwrap_or(0),
            id: report.entity.unwrap_or_default(),
        };
        let (name, clause) = report.layout().map_or(("PDU", None), |l| (l.name, Some(l.clause)));
        for f in &report.findings {
            let rule = match f.rule() {
                "pdu-padding" => Rule::PduPadding,
                "pdu-family" => Rule::PduFamily,
                _ => Rule::PduStructure,
            };
            if !self.enabled(rule) || self.muted(rule.name(), &key, now) {
                continue;
            }
            let dedup = (rule, report.pdu_type, source);
            if self
                .structure_last
                .get(&dedup)
                .is_some_and(|t| now - t < self.enum_repeat)
            {
                continue;
            }
            self.structure_last.insert(dedup, now);
            let cite = clause.map_or(String::new(), |c| format!(" (IEEE 1278.1 {c}, draft D16r18)"));
            let message = format!("{name} from {}: {}{cite}", key.id, f.describe());
            out.push(AlertEvent {
                at: now,
                state: AlertState::Firing,
                alert: Alert {
                    rule,
                    pack: self.rule_pack.get(&rule).cloned().unwrap_or_else(|| "builtin".into()),
                    rule_id: rule.name().to_string(),
                    key,
                    severity: self.severities.get(&rule).copied().unwrap_or(Severity::Warning),
                    since: now,
                    message: message.clone(),
                    sender: Some(source),
                },
                reason: message,
            });
        }
        out
    }

    fn resolve(&mut self, at: f64, rule: Rule, key: EntityKey, reason: String, out: &mut Vec<AlertEvent>) {
        if let Some(alert) = self.active.remove(&(rule, key)) {
            self.acks.remove(&(alert.rule_id.clone(), key));
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
        let ex = table.state_for(&key);
        if ex.frozen {
            return out;
        }
        let last_change = ex.last_change;
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
                    self.fire(now, Rule::PositionJump, key, Some(source), msg, &mut out);
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
                // Blame the later arrival: it took an ID already in use.
                let blamed = if track.first_seen > my_first { *other } else { source };
                self.fire(now, Rule::IdConflict, key, Some(blamed), msg, &mut out);
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
                // Wildcards address every matching entity; alerts on a key
                // already pruned from the table are matched directly.
                let keys: Vec<EntityKey> = self
                    .active
                    .keys()
                    .map(|(_, k)| *k)
                    .filter(|k| k.exercise == exercise && nn_state::table::id_matches(&r.receiving, &k.id))
                    .collect();
                for key in keys {
                    for rule in [Rule::EntityTimeout, Rule::PositionJump, Rule::IdConflict] {
                        self.resolve(now, rule, key, "entity removed".into(), &mut out);
                    }
                }
            }
            PduBody::Detonation(d) => {
                let key = EntityKey {
                    exercise,
                    id: d.munition_id,
                };
                for rule in [Rule::EntityTimeout, Rule::PositionJump] {
                    self.resolve(now, rule, key, "munition detonated".into(), &mut out);
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
        self.mutes.retain(|m| m.until > now);
        let timeout = self.config.timeout();

        if self.enabled(Rule::EntityTimeout) {
            for (key, rec) in &table.entities {
                if rec.removed || rec.deactivated() {
                    continue;
                }
                let ex = table.state_for(key);
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
                    let silent_sender = Some(rec.last_source);
                    self.fire(now, Rule::EntityTimeout, *key, silent_sender, msg, &mut out);
                }
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
                // A record expired from the table is not a removal: the alert
                // stays open until the entity returns or is removed.
                Rule::EntityTimeout => {
                    if rec.is_some_and(|r| r.removed || r.deactivated()) {
                        self.resolve(now, rule, key, "entity removed or deactivated".into(), &mut out);
                    }
                }
                Rule::PositionJump => {
                    if rec.is_none_or(|r| now - r.last_seen > timeout) {
                        self.resolve(now, rule, key, "entity no longer reporting".into(), &mut out);
                    }
                }
                // One-shot events; never present in `active`.
                Rule::EnumViolation | Rule::PduStructure | Rule::PduPadding | Rule::PduFamily => {}
            }
        }
        out
    }
}
