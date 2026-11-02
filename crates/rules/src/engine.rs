//! The rule engine: three behavioural rules over the entity table, plus
//! per-PDU enumeration checks loaded from rule packs.

use crate::heartbeats::{HeartbeatConfig, Heartbeats};
use crate::interactions::{Collisions, Damage, DirectedEnergy};
use crate::lifecycle::Lifecycle;
use crate::pack::{EnumCheck, Merged};
use crate::radio::{RadioConfig, Radios};
use crate::siman::Handshakes;
use crate::warfare::Warfare;
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
    /// A Simulation Management request went unanswered, or an answer
    /// doesn't fit a request (ADR 0010 step 5, `crate::siman`).
    SimanHandshake,
    /// Transmitter, Signal and Receiver PDUs contradict each other or stop
    /// (ADR 0010 step 5, `crate::radio`).
    Radio,
    /// The same datagram from the same sender arrived twice: overlapping
    /// listeners, or a network that delivers it twice.
    DuplicateDelivery,
    /// An object stopped sending a PDU type that has a heartbeat
    /// (`crate::heartbeats`).
    Heartbeat,
    /// An entity's life told inconsistently: no final report after Remove
    /// Entity, a zombie, a type change... (`crate::lifecycle`).
    EntityLifecycle,
    /// A Fire and its Detonation don't pair up (`crate::warfare`).
    FireDetonation,
    /// A DE engagement's DE Fire, Fire and Detonation PDUs disagree
    /// (`crate::interactions::DirectedEnergy`).
    DirectedEnergy,
    /// Entity Damage Status and appearance disagree
    /// (`crate::interactions::Damage`).
    EntityDamage,
    /// A collision reported by one party only, or twice
    /// (`crate::interactions::Collisions`).
    Collision,
    /// An Attribute PDU or a Coupled PDU Extension breaks the issuance
    /// rules (`crate::attribute`).
    Attribute,
    /// An emitter system's EE PDUs break the issuance rules
    /// (`crate::emission`).
    Emission,
    /// A designator's spot or its final report (`crate::designator`).
    Designator,
    /// A user monitor's condition held (`crate::monitors`): one alert per
    /// monitor and group; `rule_id` is the monitor id, with `@tags` for a
    /// group.
    UserMonitor,
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
            Rule::SimanHandshake => "siman-handshake",
            Rule::Radio => "radio",
            Rule::DuplicateDelivery => "duplicate-delivery",
            Rule::Heartbeat => "heartbeat",
            Rule::EntityLifecycle => "entity-lifecycle",
            Rule::FireDetonation => "fire-detonation",
            Rule::DirectedEnergy => "directed-energy",
            Rule::EntityDamage => "entity-damage",
            Rule::Collision => "collision",
            Rule::Attribute => "attribute",
            Rule::Emission => "emission",
            Rule::Designator => "designator",
            Rule::UserMonitor => "monitor",
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
            "siman-handshake" => Some(Rule::SimanHandshake),
            "radio" => Some(Rule::Radio),
            "duplicate-delivery" => Some(Rule::DuplicateDelivery),
            "heartbeat" => Some(Rule::Heartbeat),
            "entity-lifecycle" => Some(Rule::EntityLifecycle),
            "fire-detonation" => Some(Rule::FireDetonation),
            "directed-energy" => Some(Rule::DirectedEnergy),
            "entity-damage" => Some(Rule::EntityDamage),
            "collision" => Some(Rule::Collision),
            "attribute" => Some(Rule::Attribute),
            "emission" => Some(Rule::Emission),
            "designator" => Some(Rule::Designator),
            "monitor" => Some(Rule::UserMonitor),
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
    /// The finding within the rule (`timeout`, `one-sided`, `undefined`...):
    /// with the rule, the key into the explanation catalog
    /// (`crate::explain`).
    pub kind: &'static str,
    /// Evidence as data: what was observed and what was expected, named.
    pub facts: Facts,
}

/// Named evidence values of an alert, in display order.
pub type Facts = Vec<(&'static str, String)>;

/// A change in an alert's state, at time `at`.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertEvent {
    pub at: f64,
    pub state: AlertState,
    pub alert: Alert,
    /// Why it fired or resolved, for the alert log.
    pub reason: String,
    /// The PDU that raised it, when one did (most checks; not a timeout,
    /// which is raised by silence). Attached by `Monitor::ingest`.
    pub pdu: Option<std::sync::Arc<[u8]>>,
}

#[derive(Debug, Clone)]
pub struct RuleConfig {
    /// Expected Entity State heartbeat, seconds (IEEE 1278.1 default 5 s).
    pub heartbeat: f64,
    /// Heartbeat of a stationary entity, seconds (HBT_STATIONARY, 60 s): one
    /// whose last report has DR algorithm Static or no speed (4.2.7, Table 4).
    pub stationary_heartbeat: f64,
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
    /// Seconds a Simulation Management request may wait for its answer
    /// (IEEE 1278.1 TI_TIMER2_DFLT, 12 s).
    pub response_timeout: f64,
    /// Radio heartbeats and limits (`[rules.radio]`).
    pub radio: RadioConfig,
    /// The same datagram from the same sender within this many seconds is
    /// a second delivery of one send, not a second send.
    pub echo_window: f64,
    /// Heartbeats of the PDU types without a rule of their own.
    pub heartbeats: HeartbeatConfig,
    /// Seconds a removed entity has to send its final Deactivated report.
    pub final_report_window: f64,
    /// Longest a munition may fly: a Fire's Detonation is due within this.
    pub max_flight: f64,
    /// HBT_PDU_DE_FIRE: a DE Fire is due this often while a shot is on.
    pub de_heartbeat: f64,
    /// Seconds a repaired entity's appearance has to stop showing damage.
    pub repair_window: f64,
    /// Seconds the other party has to report its side of a collision.
    pub collision_window: f64,
    /// COLLISION_THRSH: a collision needs one party faster than this, m/s.
    pub collision_speed: f64,
    /// How far an "entity impact" Detonation may be from its target's
    /// dead-reckoned position, metres, plus the target's speed x 1 s.
    pub impact_tolerance: f64,
    /// HBT_PDU_EE: an active emitter system's EE PDU is due this often.
    pub ee_heartbeat: f64,
    /// EE_HIGH_DENSITY_THRSH: most targets a beam lists one by one.
    pub high_density_threshold: f64,
    /// Seconds a designator has to send its final Power 0 report after its
    /// designating or designated entity ceases to exist.
    pub designator_window: f64,
}

impl Default for RuleConfig {
    fn default() -> Self {
        RuleConfig {
            heartbeat: 5.0,
            stationary_heartbeat: 60.0,
            timeout_multiplier: 2.4,
            conflict_grace: 2.0,
            duplicate_window: 1.0,
            jump_min_tolerance: 50.0,
            assumed_dr_threshold: 1.0,
            jump_dr_multiplier: 3.0,
            jump_timing_slack: 0.5,
            tick_interval: 0.25,
            response_timeout: 12.0,
            radio: RadioConfig::default(),
            echo_window: 0.1,
            heartbeats: HeartbeatConfig::default(),
            final_report_window: 12.0,
            max_flight: 180.0,
            de_heartbeat: 0.5,
            repair_window: 6.0,
            collision_window: 5.0,
            collision_speed: 0.1,
            impact_tolerance: 100.0,
            ee_heartbeat: 5.0,
            high_density_threshold: 10.0,
            designator_window: 12.0,
        }
    }
}

/// Below this speed (m/s) an entity counts as stationary.
const STATIONARY_SPEED: f64 = 0.01;

impl RuleConfig {
    /// The timeout of a moving entity.
    pub fn timeout(&self) -> f64 {
        self.heartbeat * self.timeout_multiplier
    }

    /// The timeout for an entity whose last report was `k`: stationary
    /// entities (DR algorithm Static, or no speed) may heartbeat at
    /// HBT_STATIONARY instead (IEEE 1278.1 4.2.7 c, Table 4).
    pub fn timeout_for(&self, k: &nn_state::Kinematics) -> f64 {
        let stationary = k.algorithm == 1 || speed(&k.velocity) < STATIONARY_SPEED;
        let hb = if stationary {
            self.stationary_heartbeat
        } else {
            self.heartbeat
        };
        hb.max(self.heartbeat) * self.timeout_multiplier
    }

    /// [`RuleConfig::timeout_for`] an entity's latest report.
    pub fn timeout_of(&self, rec: &nn_state::EntityRecord) -> f64 {
        self.timeout_for(rec.kinematics())
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
        PduBody::EntityStateUpdate(e) => e.entity_id,
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
    /// Simulation Management requests awaiting answers.
    handshakes: Handshakes,
    /// Radios and their Transmitter/Receiver state.
    radios: Radios,
    /// Objects of heartbeat PDU types, and when each last reported.
    heartbeats: Heartbeats,
    /// Each entity's life so far.
    lifecycle: Lifecycle,
    /// Fires awaiting their Detonations.
    warfare: Warfare,
    directed_energy: DirectedEnergy,
    damage: Damage,
    collisions: Collisions,
    emissions: crate::emission::Emissions,
    designators: crate::designator::Designators,
    /// Last time each (rule, kind of finding, entity) point event fired.
    point_last: BTreeMap<(Rule, &'static str, EntityKey), f64>,
    active: BTreeMap<(Rule, EntityKey), Alert>,
    /// Open user-monitor alerts, by rule_id (monitor id and group).
    monitor_active: BTreeMap<String, Alert>,
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
            handshakes: Handshakes::default(),
            radios: Radios::default(),
            heartbeats: Heartbeats::default(),
            lifecycle: Lifecycle::default(),
            warfare: Warfare::default(),
            directed_energy: DirectedEnergy::default(),
            damage: Damage::default(),
            collisions: Collisions::default(),
            emissions: crate::emission::Emissions::default(),
            designators: crate::designator::Designators::default(),
            point_last: BTreeMap::new(),
            active: BTreeMap::new(),
            monitor_active: BTreeMap::new(),
            acks: BTreeMap::new(),
            mutes: Vec::new(),
            last_tick: f64::NEG_INFINITY,
        }
    }

    /// Seconds between repeats of a point event (pack `enum_repeat_seconds`).
    pub fn repeat_seconds(&self) -> f64 {
        self.enum_repeat
    }

    pub fn enabled(&self, rule: Rule) -> bool {
        self.enabled.get(&rule).copied().unwrap_or(true)
    }

    pub fn active(&self) -> impl Iterator<Item = &Alert> {
        self.active.values().chain(self.monitor_active.values())
    }

    pub fn is_active(&self, rule: Rule, key: &EntityKey) -> bool {
        self.active.contains_key(&(rule, *key))
    }

    /// Is this rule/entity combination muted right now?
    pub fn muted(&self, rule_id: &str, key: &EntityKey, now: f64) -> bool {
        self.mutes.iter().any(|m| {
            m.until > now
                && match &m.scope {
                    // A monitor's id mutes all its groups (`id@tags`).
                    MuteScope::Rule(r) => {
                        r == rule_id || rule_id.strip_prefix(r.as_str()).is_some_and(|g| g.starts_with('@'))
                    }
                    MuteScope::Entity(k) => k == key,
                }
        })
    }

    /// Acknowledge a firing alert (matched by its rule_id and entity).
    pub fn ack(&mut self, rule_id: &str, key: EntityKey, by: &str, note: &str, at: f64) -> bool {
        if !self.active().any(|a| a.rule_id == rule_id && a.key == key) {
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

    /// A user monitor's group opened or resolved: the alert event, unless
    /// the rule is off or the monitor muted.
    pub fn monitor_change(
        &mut self,
        at: f64,
        def: &crate::monitors::MonitorDef,
        group: &nn_state::metrics::TagPairs,
        change: &crate::monitors::Change,
    ) -> Option<AlertEvent> {
        use crate::monitors::{Change, Kind};
        use nn_state::metrics::Dim;
        let tag = |d: Dim| group.iter().find(|(x, _)| *x == d).map(|(_, v)| v.as_str());
        let filter = |d: Dim| def.filter.iter().find(|(x, _)| *x == d).map(|(_, v)| v.as_str());
        let group_s: Vec<String> = group.iter().map(|(d, v)| format!("{}={v}", d.name())).collect();
        let rule_id = if group.is_empty() {
            def.id.clone()
        } else {
            format!("{}@{}", def.id, group_s.join(","))
        };
        if let Change::Resolve = change {
            let alert = self.monitor_active.remove(&rule_id)?;
            self.acks.retain(|(r, _), _| r != &rule_id);
            return Some(AlertEvent {
                at,
                state: AlertState::Resolved,
                alert,
                reason: format!("{}: back within its condition", def.name),
                pdu: None,
            });
        }
        let Change::Fire { value } = change else { return None };
        // The alert's entity: the group's, else its simulation, else none.
        let n = |s: Option<&str>| s.and_then(|v| v.parse::<u16>().ok()).unwrap_or(0);
        let id = match tag(Dim::Entity).and_then(|e| e.parse::<EntityId>().ok()) {
            Some(e) => e,
            None => EntityId::new(
                n(tag(Dim::Site).or(filter(Dim::Site))),
                n(tag(Dim::App).or(filter(Dim::App))),
                0,
            ),
        };
        let exercise = tag(Dim::Exercise)
            .or(filter(Dim::Exercise))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let key = EntityKey { exercise, id };
        if !self.enabled(Rule::UserMonitor)
            || self.muted(&rule_id, &key, at)
            || self.monitor_active.contains_key(&rule_id)
        {
            return None;
        }
        let who = if group_s.is_empty() {
            String::new()
        } else {
            format!(" ({})", group_s.join(", "))
        };
        let what = match def.kind {
            Kind::Absence => format!("nothing for {} s", def.for_secs),
            Kind::Threshold => format!(
                "{value:.3} {}",
                def.condition.map(|c| c.to_string()).unwrap_or_default()
            ),
            Kind::EventCount => format!(
                "{value:.0} firings, {}",
                def.condition.map(|c| c.to_string()).unwrap_or_default()
            ),
            Kind::Composite => "its expression holds".into(),
        };
        let message = format!("{}{who}: {what} [{}]", def.name, def.describe());
        let mut facts: Facts = vec![
            ("monitor", format!("{} ({})", def.name, def.id)),
            ("type", def.kind.name().into()),
        ];
        if !group_s.is_empty() {
            facts.push(("group", group_s.join(", ")));
        }
        facts.push(("value", format!("{value:.3}")));
        if let Some(c) = def.condition {
            facts.push(("condition", c.to_string()));
        }
        if def.for_secs > 0 {
            facts.push(("held for", format!("{} s", def.for_secs)));
        }
        facts.push(("watching", def.describe()));
        let alert = Alert {
            rule: Rule::UserMonitor,
            pack: "monitors".into(),
            rule_id: rule_id.clone(),
            key,
            severity: def.severity,
            since: at,
            message: message.clone(),
            sender: tag(Dim::Sender).and_then(|s| s.parse().ok()),
            kind: def.kind.name(),
            facts,
        };
        self.monitor_active.insert(rule_id, alert.clone());
        Some(AlertEvent {
            at,
            state: AlertState::Firing,
            alert,
            reason: message,
            pdu: None,
        })
    }

    /// Resolve every open alert of monitors no longer defined.
    pub fn retain_monitors(&mut self, at: f64, ids: &[&str]) -> Vec<AlertEvent> {
        let gone: Vec<String> = self
            .monitor_active
            .keys()
            .filter(|r| {
                !ids.iter()
                    .any(|id| r.as_str() == *id || r.strip_prefix(id).is_some_and(|g| g.starts_with('@')))
            })
            .cloned()
            .collect();
        gone.into_iter()
            .filter_map(|r| self.monitor_active.remove(&r))
            .map(|alert| AlertEvent {
                at,
                state: AlertState::Resolved,
                alert,
                reason: "monitor removed or changed".into(),
                pdu: None,
            })
            .collect()
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

    #[allow(clippy::too_many_arguments)]
    fn fire(
        &mut self,
        at: f64,
        (rule, kind): (Rule, &'static str),
        key: EntityKey,
        sender: Option<SocketAddr>,
        message: String,
        facts: Facts,
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
            kind,
            facts,
        };
        self.active.insert((rule, key), alert.clone());
        out.push(AlertEvent {
            at,
            state: AlertState::Firing,
            alert,
            reason: message,
            pdu: None,
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
        let mut facts: Facts = vec![("field", check.spec.name.to_string()), ("value", value.to_string())];
        match &check.source {
            Some(source) => facts.push(("defined in", source.clone())),
            None => facts.push(("allowed", check.allowed_str())),
        }
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
                kind: if check.source.is_some() {
                    "undefined"
                } else {
                    "not-allowed"
                },
                facts,
            },
            reason: message,
            pdu: None,
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
                    kind: f.kind(),
                    facts: std::iter::once(("PDU type", name.to_string()))
                        .chain(f.facts())
                        .chain(clause.map(|c| ("layout", c.to_string())))
                        .collect(),
                },
                reason: message,
                pdu: None,
            });
        }
        out
    }

    /// One PDU's bytes through the Simulation Management handshake tracker.
    pub fn check_siman(&mut self, now: f64, source: SocketAddr, pdu: &[u8]) -> Vec<AlertEvent> {
        let findings = self.handshakes.observe(now, source, pdu, self.config.response_timeout);
        let mut out = Vec::new();
        for f in findings {
            let key = EntityKey {
                exercise: f.exercise,
                id: f.id,
            };
            let at = (Rule::SimanHandshake, f.kind);
            self.point_event(now, at, key, f.sender, f.message, f.facts, &mut out);
        }
        out
    }

    /// Entity lifecycle checks on one PDU, before it is applied to the table
    /// (a Remove Entity matches entities as the table knows them).
    pub fn check_lifecycle(&mut self, now: f64, source: SocketAddr, pdu: &Pdu, table: &EntityTable) -> Vec<AlertEvent> {
        if !self.enabled(Rule::EntityLifecycle) {
            return Vec::new();
        }
        let exercise = pdu.header.exercise_id;
        let window = self.config.final_report_window;
        let findings = match &pdu.body {
            PduBody::EntityState(es) => self.lifecycle.observe(now, source, exercise, es, window),
            PduBody::RemoveEntity(r) => {
                self.lifecycle.removed(now, &table.matching(exercise, &r.receiving));
                Vec::new()
            }
            // An update the monitor couldn't merge: no full report yet.
            PduBody::EntityStateUpdate(u) => {
                let grace = self.config.stationary_heartbeat * self.config.timeout_multiplier;
                self.lifecycle
                    .orphan_update(now, source, exercise, u.entity_id, grace)
                    .into_iter()
                    .collect()
            }
            _ => Vec::new(),
        };
        let mut out = Vec::new();
        for f in findings {
            self.point_event(
                now,
                (Rule::EntityLifecycle, f.kind),
                f.key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        out
    }

    /// Fire / Detonation pairing on one decoded PDU.
    pub fn check_warfare(&mut self, now: f64, source: SocketAddr, pdu: &Pdu, table: &EntityTable) -> Vec<AlertEvent> {
        if !self.enabled(Rule::FireDetonation) {
            return Vec::new();
        }
        let h = &pdu.header;
        let status = (h.protocol_version, h.pdu_status);
        let findings = match &pdu.body {
            PduBody::Fire(f) => {
                let grace = self.config.stationary_heartbeat * self.config.timeout_multiplier;
                self.warfare.fire(now, source, h.exercise_id, status, f, table, grace)
            }
            PduBody::Detonation(d) => {
                let limits = (
                    self.config.max_flight,
                    self.config.impact_tolerance,
                    // A source reports within this or it's not live.
                    self.config.stationary_heartbeat.max(self.config.heartbeat) * self.config.timeout_multiplier,
                );
                self.warfare
                    .detonation(now, source, h.exercise_id, status, d, table, limits)
            }
            _ => return Vec::new(),
        };
        let mut out = Vec::new();
        for f in findings {
            self.point_event(
                now,
                (Rule::FireDetonation, f.kind),
                f.key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        out
    }

    fn emission_limits(&self) -> crate::emission::Limits {
        crate::emission::Limits {
            heartbeat: self.config.ee_heartbeat,
            multiplier: self.config.heartbeats.timeout_multiplier,
            high_density: self.config.high_density_threshold.clamp(0.0, 255.0) as u8,
            grace: self.config.stationary_heartbeat * self.config.timeout_multiplier,
        }
    }

    /// Attribute PDU issuance and Coupled PDU Extension on one PDU's bytes,
    /// with its neighbours in the datagram.
    pub fn check_attribute(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        prev: Option<&[u8]>,
        next: Option<&[u8]>,
    ) -> Vec<AlertEvent> {
        if !self.enabled(Rule::Attribute) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for f in crate::attribute::check(source, pdu, prev, next) {
            self.point_event(
                now,
                (Rule::Attribute, f.kind),
                f.key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        out
    }

    /// DE engagements, damage status and collisions on one PDU's bytes.
    pub fn check_interactions(
        &mut self,
        now: f64,
        source: SocketAddr,
        raw: &[u8],
        table: &EntityTable,
    ) -> Vec<AlertEvent> {
        let mut found = Vec::new();
        if self.enabled(Rule::DirectedEnergy) {
            found.extend(
                self.directed_energy
                    .observe(now, source, raw)
                    .into_iter()
                    .map(|f| (Rule::DirectedEnergy, f)),
            );
        }
        if self.enabled(Rule::EntityDamage) {
            found.extend(
                self.damage
                    .observe(now, source, raw, table)
                    .into_iter()
                    .map(|f| (Rule::EntityDamage, f)),
            );
        }
        if self.enabled(Rule::Collision) {
            let limits = (self.config.collision_window, self.config.collision_speed);
            found.extend(
                self.collisions
                    .observe(now, source, raw, table, limits)
                    .into_iter()
                    .map(|f| (Rule::Collision, f)),
            );
        }
        if self.enabled(Rule::Designator) {
            let grace = self.config.stationary_heartbeat * self.config.timeout_multiplier;
            found.extend(
                self.designators
                    .observe(now, source, raw, table, grace)
                    .into_iter()
                    .map(|f| (Rule::Designator, f)),
            );
        }
        if self.enabled(Rule::Emission) {
            let limits = self.emission_limits();
            found.extend(
                self.emissions
                    .observe(now, source, raw, table, &limits)
                    .into_iter()
                    .map(|f| (Rule::Emission, f)),
            );
        }
        let mut out = Vec::new();
        for (rule, f) in found {
            self.point_event(now, (rule, f.kind), f.key, Some(f.sender), f.message, f.facts, &mut out);
        }
        out
    }

    /// Note an object of a heartbeat PDU type reporting.
    pub fn observe_heartbeat(&mut self, now: f64, source: SocketAddr, pdu: &[u8]) {
        if self.enabled(Rule::Heartbeat) {
            self.heartbeats.observe(now, source, pdu, &self.config.heartbeats);
        }
    }

    /// One PDU's bytes through the radio tracker.
    pub fn check_radio(&mut self, now: f64, source: SocketAddr, pdu: &[u8]) -> Vec<AlertEvent> {
        let findings = self.radios.observe(now, source, pdu, &self.config.radio);
        let mut out = Vec::new();
        for f in findings {
            let key = EntityKey {
                exercise: f.exercise,
                id: f.id,
            };
            self.point_event(
                now,
                (Rule::Radio, f.kind),
                key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        out
    }

    /// A finding of a stateless rule as a point event, at most one of each
    /// kind per entity every `enum_repeat` seconds.
    #[allow(clippy::too_many_arguments)]
    /// A one-off finding (not an alert that stays open), with its evidence
    /// as named facts; repeats within `enum_repeat` are dropped.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn point_event(
        &mut self,
        at: f64,
        (rule, kind): (Rule, &'static str),
        key: EntityKey,
        sender: Option<SocketAddr>,
        message: String,
        facts: Facts,
        out: &mut Vec<AlertEvent>,
    ) {
        if !self.enabled(rule) || self.muted(rule.name(), &key, at) {
            return;
        }
        if self
            .point_last
            .get(&(rule, kind, key))
            .is_some_and(|t| at - t < self.enum_repeat)
        {
            return;
        }
        self.point_last.insert((rule, kind, key), at);
        out.push(AlertEvent {
            at,
            state: AlertState::Firing,
            alert: Alert {
                rule,
                pack: self.rule_pack.get(&rule).cloned().unwrap_or_else(|| "builtin".into()),
                rule_id: rule.name().to_string(),
                key,
                severity: self.severities.get(&rule).copied().unwrap_or(Severity::Warning),
                since: at,
                message: message.clone(),
                sender,
                kind,
                facts,
            },
            reason: message,
            pdu: None,
        });
    }

    fn resolve(&mut self, at: f64, rule: Rule, key: EntityKey, reason: String, out: &mut Vec<AlertEvent>) {
        if let Some(alert) = self.active.remove(&(rule, key)) {
            self.acks.remove(&(alert.rule_id.clone(), key));
            out.push(AlertEvent {
                at,
                state: AlertState::Resolved,
                alert,
                reason,
                pdu: None,
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
        let timeout = self.config.timeout_of(rec);

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
                    let facts = vec![
                        ("off by", format!("{error:.0} m")),
                        ("tolerance", format!("{tolerance:.0} m")),
                        ("since last report", format!("{dt:.1} s")),
                        ("speed", format!("{v:.1} m/s")),
                    ];
                    self.fire(
                        now,
                        (Rule::PositionJump, "jump"),
                        key,
                        Some(source),
                        msg,
                        facts,
                        &mut out,
                    );
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
                let (blamed, first) = if track.first_seen > my_first {
                    (*other, source)
                } else {
                    (source, *other)
                };
                let mut facts = vec![
                    ("first sender", first.to_string()),
                    ("later sender", blamed.to_string()),
                ];
                let kind = if type_clash {
                    facts.push(("entity types", format!("{} vs {}", track.entity_type, es.entity_type)));
                    "type-clash"
                } else {
                    "two-senders"
                };
                self.fire(now, (Rule::IdConflict, kind), key, Some(blamed), msg, facts, &mut out);
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

        for f in self.handshakes.expire(now, self.config.response_timeout) {
            // The simulation that owes the answer: any entity of it the
            // table has heard from gives its address.
            let owner = f.owes.and_then(|(site, app)| {
                table
                    .entities
                    .iter()
                    .find(|(k, _)| k.exercise == f.exercise && k.id.site == site && k.id.application == app)
                    .map(|(_, r)| r.last_source)
            });
            let key = EntityKey {
                exercise: f.exercise,
                id: f.id,
            };
            let at = (Rule::SimanHandshake, f.kind);
            self.point_event(now, at, key, f.sender.or(owner), f.message, f.facts, &mut out);
        }
        let frozen = |exercise, id| table.state_for(&EntityKey { exercise, id }).frozen;
        let gone = |exercise, id| {
            table
                .get(&EntityKey { exercise, id })
                .is_some_and(|r| r.removed || r.deactivated())
        };
        for f in self.heartbeats.expire(now, &self.config.heartbeats, frozen, gone) {
            let key = EntityKey {
                exercise: f.exercise,
                id: f.id,
            };
            let at = (Rule::Heartbeat, f.kind);
            self.point_event(now, at, key, Some(f.sender), f.message, f.facts, &mut out);
        }
        let mult = self.config.heartbeats.timeout_multiplier;
        let mut found: Vec<(Rule, crate::interactions::Finding)> = Vec::new();
        found.extend(
            self.directed_energy
                .expire(now, self.config.de_heartbeat, mult)
                .into_iter()
                .map(|f| (Rule::DirectedEnergy, f)),
        );
        found.extend(
            self.damage
                .expire(now, self.config.repair_window, table)
                .into_iter()
                .map(|f| (Rule::EntityDamage, f)),
        );
        found.extend(
            self.collisions
                .expire(now, self.config.collision_window, table)
                .into_iter()
                .map(|f| (Rule::Collision, f)),
        );
        let limits = self.emission_limits();
        found.extend(
            self.emissions
                .expire(now, &limits, table, frozen)
                .into_iter()
                .map(|f| (Rule::Emission, f)),
        );
        found.extend(
            self.designators
                .expire(now, self.config.designator_window, table, frozen)
                .into_iter()
                .map(|f| (Rule::Designator, f)),
        );
        for (rule, f) in found {
            self.point_event(now, (rule, f.kind), f.key, Some(f.sender), f.message, f.facts, &mut out);
        }
        for f in self.warfare.expire(now, self.config.max_flight) {
            self.point_event(
                now,
                (Rule::FireDetonation, f.kind),
                f.key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        for f in self.lifecycle.expire(now, self.config.final_report_window) {
            self.point_event(
                now,
                (Rule::EntityLifecycle, f.kind),
                f.key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }
        for f in self.radios.expire(now, &self.config.radio, frozen) {
            let key = EntityKey {
                exercise: f.exercise,
                id: f.id,
            };
            self.point_event(
                now,
                (Rule::Radio, f.kind),
                key,
                Some(f.sender),
                f.message,
                f.facts,
                &mut out,
            );
        }

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
                let timeout = self.config.timeout_of(rec);
                let silent = ex.running_between(rec.last_seen, now);
                let resume_grace = ex.freezes > 0 && now - ex.last_change < self.config.heartbeat;
                if silent > timeout && !resume_grace && !self.active.contains_key(&(Rule::EntityTimeout, *key)) {
                    let msg = format!(
                        "{} ({}) sent no Entity State for {:.1} s of exercise time (timeout {:.1} s)",
                        key.id, rec.marking, silent, timeout
                    );
                    let silent_sender = Some(rec.last_source);
                    let facts = vec![
                        ("silent for", format!("{silent:.1} s")),
                        ("timeout", format!("{timeout:.1} s")),
                        ("marking", rec.marking.clone()),
                        ("last report", format!("{:.0} s ago", now - rec.last_seen)),
                    ];
                    let fired = (Rule::EntityTimeout, "silent");
                    self.fire(now, fired, *key, silent_sender, msg, facts, &mut out);
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
                        .map(|r| {
                            let timeout = self.config.timeout_of(r);
                            r.sources.values().filter(|t| now - t.last_seen <= timeout).count()
                        })
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
                    if rec.is_none_or(|r| now - r.last_seen > self.config.timeout_of(r)) {
                        self.resolve(now, rule, key, "entity no longer reporting".into(), &mut out);
                    }
                }
                // One-shot events; never present in `active`.
                Rule::EnumViolation
                | Rule::PduStructure
                | Rule::PduPadding
                | Rule::PduFamily
                | Rule::SimanHandshake
                | Rule::Radio
                | Rule::DuplicateDelivery
                | Rule::Heartbeat
                | Rule::EntityLifecycle
                | Rule::FireDetonation
                | Rule::DirectedEnergy
                | Rule::EntityDamage
                | Rule::Collision
                | Rule::Attribute
                | Rule::Emission
                | Rule::Designator
                | Rule::UserMonitor => {}
            }
        }
        out
    }
}
