//! Rule packs: rules and enumeration checks as data (ADR 0003).
//!
//! A pack is a TOML file ([`crate::minitoml`] subset) with `[pack]`
//! metadata, `[rules.<name>]` threshold overlays and `[[enum]]` allowed-value
//! checks keyed by field path (`header.protocol_version` applies to every
//! PDU, `entity-state.force_id` only to Entity State). Packs layer —
//! standard → exercise profile → site — with the last pack to touch a rule
//! or field winning. The base DIS pack ships inside the binary
//! ([`Merged::builtin`]); files layered with `--rulepack` sit on top.

use crate::engine::{Rule, RuleConfig, Severity};
use crate::minitoml::{self, Table, Value};
use nn_decode::fields::{enum_fields, repeated_fields, EnumField, RepeatedField};
use nn_decode::{pdu_type, Detonation, EntityState, EntityType, Fire, Pdu, PduBody, StopFreeze};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::Path;

/// Default seconds between repeats of the same enum violation on an entity.
const DEFAULT_ENUM_REPEAT: f64 = 60.0;

const BASE_PACK: &str = include_str!("../../../rulepacks/dis-base.toml");

#[derive(Debug)]
pub struct PackError {
    /// File path, or "<builtin>" for the embedded base pack.
    pub origin: String,
    pub line: usize,
    pub message: String,
}

impl PackError {
    fn at(origin: &str, line: usize, message: impl Into<String>) -> Self {
        PackError {
            origin: origin.to_string(),
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.line > 0 {
            write!(f, "{}:{}: {}", self.origin, self.line, self.message)
        } else {
            write!(f, "{}: {}", self.origin, self.message)
        }
    }
}

impl std::error::Error for PackError {}

/// One enumerated field a pack can constrain.
#[derive(Clone, Copy)]
pub struct FieldSpec {
    /// Field path as written in packs, e.g. "entity-state.force_id".
    pub name: &'static str,
    /// PDU type the field lives in; `None` = header field, every PDU.
    pub scope: Option<u8>,
    /// Extract the field's value, or `None` on a body type mismatch.
    pub get: fn(&Pdu) -> Option<u64>,
    /// The SISO-REF-010 enumeration defining the field's values, if any;
    /// `--siso` turns it into a check (ADR 0010 tier E).
    pub uid: Option<u16>,
    /// A field read from the raw bytes of a PDU type that isn't deep
    /// decoded; `get` is unused for these.
    pub raw: Option<&'static EnumField>,
    /// A field that repeats inside the PDU's records (per beam, per
    /// system): every occurrence is checked.
    pub repeated: Option<&'static RepeatedField>,
}

impl FieldSpec {
    /// The field's value in `pdu`, or `None` if it isn't there. For a
    /// repeated field, its first occurrence.
    pub fn value(&self, pdu: &Pdu) -> Option<u64> {
        self.values(pdu).into_iter().next()
    }

    /// Every value of the field in `pdu`: none if it isn't there, one for an
    /// ordinary field, one per record for a repeated one.
    pub fn values(&self, pdu: &Pdu) -> Vec<u64> {
        match (self.repeated, self.raw, &pdu.body) {
            (Some(r), _, PduBody::Other(body)) => (r.values)(body),
            (Some(_), _, _) => Vec::new(),
            (None, Some(f), PduBody::Other(body)) => f.read_body(body).into_iter().collect(),
            (None, Some(_), _) => Vec::new(),
            (None, None, _) => (self.get)(pdu).into_iter().collect(),
        }
    }
}

/// A decoded field.
const fn spec(name: &'static str, scope: Option<u8>, uid: Option<u16>, get: fn(&Pdu) -> Option<u64>) -> FieldSpec {
    FieldSpec {
        name,
        scope,
        get,
        uid,
        raw: None,
        repeated: None,
    }
}

impl std::fmt::Debug for FieldSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FieldSpec({})", self.name)
    }
}

fn entity_state(p: &Pdu) -> Option<&EntityState> {
    if let PduBody::EntityState(e) = &p.body {
        Some(e)
    } else {
        None
    }
}
fn fire(p: &Pdu) -> Option<&Fire> {
    if let PduBody::Fire(f) = &p.body {
        Some(f)
    } else {
        None
    }
}
fn detonation(p: &Pdu) -> Option<&Detonation> {
    if let PduBody::Detonation(d) = &p.body {
        Some(d)
    } else {
        None
    }
}
fn stop_freeze(p: &Pdu) -> Option<&StopFreeze> {
    if let PduBody::StopFreeze(s) = &p.body {
        Some(s)
    } else {
        None
    }
}
fn es_entity_type(p: &Pdu) -> Option<EntityType> {
    entity_state(p).map(|e| e.entity_type)
}
fn es_alt_type(p: &Pdu) -> Option<EntityType> {
    entity_state(p).map(|e| e.alternative_entity_type)
}
fn fire_munition(p: &Pdu) -> Option<EntityType> {
    fire(p).map(|f| f.descriptor.munition_type)
}
fn det_munition(p: &Pdu) -> Option<EntityType> {
    detonation(p).map(|d| d.descriptor.munition_type)
}

/// Expand an EntityType-shaped record into its seven subfield specs, plus
/// the SISO-only checks that depend on kind and domain: platform domain
/// (UID 8), munition domain (UID 14) and platform category by domain
/// (UIDs 9-13).
macro_rules! etype_fields {
    ($scope:expr, $prefix:literal, $extract:ident) => {
        [
            spec(concat!($prefix, ".kind"), $scope, Some(7), |p| {
                $extract(p).map(|t| t.kind as u64)
            }),
            spec(concat!($prefix, ".domain"), $scope, None, |p| {
                $extract(p).map(|t| t.domain as u64)
            }),
            spec(concat!($prefix, ".country"), $scope, Some(29), |p| {
                $extract(p).map(|t| t.country as u64)
            }),
            spec(concat!($prefix, ".category"), $scope, None, |p| {
                $extract(p).map(|t| t.category as u64)
            }),
            spec(concat!($prefix, ".subcategory"), $scope, None, |p| {
                $extract(p).map(|t| t.subcategory as u64)
            }),
            spec(concat!($prefix, ".specific"), $scope, None, |p| {
                $extract(p).map(|t| t.specific as u64)
            }),
            spec(concat!($prefix, ".extra"), $scope, None, |p| {
                $extract(p).map(|t| t.extra as u64)
            }),
            spec(concat!($prefix, ".platform_domain"), $scope, Some(8), |p| {
                $extract(p).filter(|t| t.kind == 1).map(|t| t.domain as u64)
            }),
            spec(concat!($prefix, ".munition_domain"), $scope, Some(14), |p| {
                $extract(p).filter(|t| t.kind == 2).map(|t| t.domain as u64)
            }),
            spec(concat!($prefix, ".land_category"), $scope, Some(9), |p| {
                $extract(p)
                    .filter(|t| t.kind == 1 && t.domain == 1)
                    .map(|t| t.category as u64)
            }),
            spec(concat!($prefix, ".air_category"), $scope, Some(10), |p| {
                $extract(p)
                    .filter(|t| t.kind == 1 && t.domain == 2)
                    .map(|t| t.category as u64)
            }),
            spec(concat!($prefix, ".surface_category"), $scope, Some(11), |p| {
                $extract(p)
                    .filter(|t| t.kind == 1 && t.domain == 3)
                    .map(|t| t.category as u64)
            }),
            spec(concat!($prefix, ".subsurface_category"), $scope, Some(12), |p| {
                $extract(p)
                    .filter(|t| t.kind == 1 && t.domain == 4)
                    .map(|t| t.category as u64)
            }),
            spec(concat!($prefix, ".space_category"), $scope, Some(13), |p| {
                $extract(p)
                    .filter(|t| t.kind == 1 && t.domain == 5)
                    .map(|t| t.category as u64)
            }),
        ]
    };
}

/// Every field a pack may name in `[[enum]]`.
pub(crate) fn registry() -> Vec<FieldSpec> {
    use pdu_type::*;
    let mut v = vec![
        spec("header.protocol_version", None, Some(3), |p| {
            Some(p.header.protocol_version as u64)
        }),
        spec("header.pdu_type", None, Some(4), |p| Some(p.header.pdu_type as u64)),
        spec("header.protocol_family", None, Some(5), |p| {
            Some(p.header.protocol_family as u64)
        }),
        spec("entity-state.force_id", Some(ENTITY_STATE), Some(6), |p| {
            entity_state(p).map(|e| e.force_id as u64)
        }),
        spec(
            "entity-state.marking.character_set",
            Some(ENTITY_STATE),
            Some(45),
            |p| entity_state(p).map(|e| e.marking.character_set as u64),
        ),
        spec(
            "entity-state.dead_reckoning.algorithm",
            Some(ENTITY_STATE),
            Some(44),
            |p| entity_state(p).map(|e| e.dead_reckoning.algorithm as u64),
        ),
        spec("fire.descriptor.warhead", Some(FIRE), Some(60), |p| {
            fire(p).map(|f| f.descriptor.warhead as u64)
        }),
        spec("fire.descriptor.fuse", Some(FIRE), Some(61), |p| {
            fire(p).map(|f| f.descriptor.fuse as u64)
        }),
        spec("detonation.descriptor.warhead", Some(DETONATION), Some(60), |p| {
            detonation(p).map(|d| d.descriptor.warhead as u64)
        }),
        spec("detonation.descriptor.fuse", Some(DETONATION), Some(61), |p| {
            detonation(p).map(|d| d.descriptor.fuse as u64)
        }),
        spec("detonation.result", Some(DETONATION), Some(62), |p| {
            detonation(p).map(|d| d.result as u64)
        }),
        spec("stop-freeze.reason", Some(STOP_FREEZE), Some(67), |p| {
            stop_freeze(p).map(|s| s.reason as u64)
        }),
        // A SISO bitfield (UID 68), not an enumeration: base-pack range only.
        spec("stop-freeze.frozen_behavior", Some(STOP_FREEZE), None, |p| {
            stop_freeze(p).map(|s| s.frozen_behavior as u64)
        }),
    ];
    v.extend(etype_fields!(
        Some(ENTITY_STATE),
        "entity-state.entity_type",
        es_entity_type
    ));
    v.extend(etype_fields!(
        Some(ENTITY_STATE),
        "entity-state.alternative_entity_type",
        es_alt_type
    ));
    v.extend(etype_fields!(
        Some(FIRE),
        "fire.descriptor.munition_type",
        fire_munition
    ));
    v.extend(etype_fields!(
        Some(DETONATION),
        "detonation.descriptor.munition_type",
        det_munition
    ));
    v.extend(enum_fields().iter().map(|f| FieldSpec {
        name: f.name,
        scope: Some(f.pdu_type),
        get: |_| None,
        uid: Some(f.uid),
        raw: Some(f),
        repeated: None,
    }));
    v.extend(repeated_fields().iter().map(|f| FieldSpec {
        name: f.name,
        scope: Some(f.pdu_type),
        get: |_| None,
        uid: Some(f.uid),
        raw: None,
        repeated: Some(f),
    }));
    v
}

fn field_spec(name: &str) -> Option<FieldSpec> {
    registry().into_iter().find(|f| f.name == name)
}

/// A `[[enum]]` check after layering: the winning pack's version.
#[derive(Debug, Clone)]
pub struct EnumCheck {
    pub spec: FieldSpec,
    pub allowed: Vec<RangeInclusive<u64>>,
    pub severity: Severity,
    /// Id of the pack that contributed this check.
    pub pack: String,
    /// Where the allowed set comes from (e.g. a SISO-REF-010 UID).
    pub source: Option<String>,
}

impl EnumCheck {
    /// `Some(value)` if the field is present in `pdu` and outside `allowed`.
    pub fn violation(&self, pdu: &Pdu) -> Option<u64> {
        if self.spec.scope.is_some_and(|t| t != pdu.header.pdu_type) {
            return None;
        }
        // The first value outside the allowed set: one beam's bad function
        // is a violation even if the others are fine.
        self.spec
            .values(pdu)
            .into_iter()
            .find(|v| !self.allowed.iter().any(|r| r.contains(v)))
    }

    /// Allowed set for messages: `"0-8, 12"`.
    pub fn allowed_str(&self) -> String {
        self.allowed
            .iter()
            .map(|r| {
                if r.start() == r.end() {
                    r.start().to_string()
                } else {
                    format!("{}-{}", r.start(), r.end())
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// `[rules.<name>]` overlay values from one pack.
#[derive(Debug, Default)]
pub struct RuleOverlay {
    pub enabled: Option<bool>,
    pub severity: Option<Severity>,
    /// Threshold overrides by RuleConfig field name.
    pub values: BTreeMap<String, f64>,
}

/// One `[[enum]]` entry from one pack (before layering).
#[derive(Debug)]
pub struct EnumEntry {
    pub spec: FieldSpec,
    pub allowed: Vec<RangeInclusive<u64>>,
    /// `None` = keep the lower layer's severity.
    pub severity: Option<Severity>,
    /// `severity = "off"` — remove this check entirely.
    pub off: bool,
    /// Where the allowed set comes from, for alert messages; `None` for a
    /// pack's own `allowed`.
    pub source: Option<String>,
}

/// One `[[capture]]` entry: how much Entity State traffic to persist for
/// entities of a type (ADR 0009). Packs layer these like `[[enum]]`: a
/// later pack's entry replaces a lower one with the same `type` and
/// `min_speed`.
#[derive(Debug, Clone, PartialEq)]
pub struct CaptureRule {
    /// Entity type prefix, kind first: empty = every type, `[1, 2]` = air
    /// platforms, `[2]` = munitions.
    pub prefix: Vec<u16>,
    /// Applies only while the entity moves at least this fast, m/s.
    pub min_speed: f64,
    /// Seconds between kept reports per entity and sender: `Some(0.0)` keeps
    /// every PDU, `None` (`every = "off"`) keeps none.
    pub every: Option<f64>,
    pub pack: String,
}

impl CaptureRule {
    /// The pack spelling of the type: `*` or `1.2`.
    pub fn type_label(&self) -> String {
        if self.prefix.is_empty() {
            "*".into()
        } else {
            self.prefix.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(".")
        }
    }

    fn matches(&self, t: &EntityType, speed: f64) -> bool {
        let parts = [
            t.kind as u16,
            t.domain as u16,
            t.country,
            t.category as u16,
            t.subcategory as u16,
            t.specific as u16,
            t.extra as u16,
        ];
        speed >= self.min_speed && self.prefix.iter().zip(parts).all(|(a, b)| *a == b)
    }
}

/// See [`Merged::capture_rule`].
pub fn pick_capture<'a>(rules: &'a [CaptureRule], t: &EntityType, speed: f64) -> Option<&'a CaptureRule> {
    rules.iter().filter(|c| c.matches(t, speed)).max_by(|a, b| {
        a.min_speed
            .total_cmp(&b.min_speed)
            .then(a.prefix.len().cmp(&b.prefix.len()))
    })
}

fn parse_type_prefix(s: &str, origin: &str) -> Result<Vec<u16>, PackError> {
    let s = s.trim();
    if s == "*" {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 7 {
        return Err(PackError::at(
            origin,
            0,
            format!("capture type '{s}' has more than 7 parts"),
        ));
    }
    parts
        .iter()
        .map(|p| {
            p.trim().parse::<u16>().map_err(|_| {
                PackError::at(
                    origin,
                    0,
                    format!("capture type '{s}' must be \"*\" or dotted numbers, kind first (e.g. \"1.2\")"),
                )
            })
        })
        .collect()
}

/// One parsed pack file.
#[derive(Debug)]
pub struct RulePack {
    pub id: String,
    pub name: String,
    pub version: u64,
    pub source: Option<String>,
    pub description: Option<String>,
    /// `[defaults]`.
    pub enum_repeat_seconds: Option<f64>,
    pub tick_interval: Option<f64>,
    pub rules: BTreeMap<Rule, RuleOverlay>,
    pub enums: Vec<EnumEntry>,
    pub captures: Vec<CaptureRule>,
}

fn num(v: &Value) -> Option<f64> {
    match v {
        Value::Integer(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    }
}

/// A threshold setter: a key's value onto [`RuleConfig`].
type Setter = Box<dyn Fn(&mut RuleConfig, f64)>;

/// Threshold keys each rule accepts. `[rules.heartbeat]` takes one key per
/// PDU type in `nn_decode::heartbeat` (e.g. `iff = 20.0`) besides
/// `timeout_multiplier`.
fn set_threshold(rule: Rule, key: &str) -> Option<Setter> {
    if rule == Rule::Heartbeat {
        if key == "timeout_multiplier" {
            return Some(Box::new(|c, v| c.heartbeats.timeout_multiplier = v));
        }
        let h = nn_decode::heartbeat::table()
            .iter()
            .find(|h| h.key == key && !h.own_rule)?;
        let t = h.pdu_type;
        return Some(Box::new(move |c, v| {
            c.heartbeats.seconds.insert(t, v);
        }));
    }
    fixed_threshold(rule, key).map(|f| Box::new(f) as Setter)
}

/// Threshold keys of the rules with a fixed set, mapped onto [`RuleConfig`].
fn fixed_threshold(rule: Rule, key: &str) -> Option<fn(&mut RuleConfig, f64)> {
    use Rule::*;
    Some(match (rule, key) {
        (EntityTimeout, "heartbeat") => |c, v| c.heartbeat = v,
        (EntityTimeout, "stationary_heartbeat") => |c, v| c.stationary_heartbeat = v,
        (EntityTimeout, "timeout_multiplier") => |c, v| c.timeout_multiplier = v,
        (IdConflict, "conflict_grace") => |c, v| c.conflict_grace = v,
        (IdConflict, "duplicate_window") => |c, v| c.duplicate_window = v,
        (PositionJump, "jump_min_tolerance") => |c, v| c.jump_min_tolerance = v,
        (PositionJump, "assumed_dr_threshold") => |c, v| c.assumed_dr_threshold = v,
        (PositionJump, "jump_dr_multiplier") => |c, v| c.jump_dr_multiplier = v,
        (PositionJump, "jump_timing_slack") => |c, v| c.jump_timing_slack = v,
        (SimanHandshake, "response_timeout") => |c, v| c.response_timeout = v,
        (Radio, "transmitter_heartbeat") => |c, v| c.radio.transmitter_heartbeat = v,
        (Radio, "stationary_heartbeat") => |c, v| c.radio.stationary_heartbeat = v,
        (Radio, "receiver_heartbeat") => |c, v| c.radio.receiver_heartbeat = v,
        (Radio, "timeout_multiplier") => |c, v| c.radio.timeout_multiplier = v,
        (Radio, "idle_transmit") => |c, v| c.radio.idle_transmit = v,
        (Radio, "signal_slack") => |c, v| c.radio.signal_slack = v,
        (DuplicateDelivery, "echo_window") => |c, v| c.echo_window = v,
        (EntityLifecycle, "final_report_window") => |c, v| c.final_report_window = v,
        (FireDetonation, "max_flight") => |c, v| c.max_flight = v,
        (DirectedEnergy, "de_heartbeat") => |c, v| c.de_heartbeat = v,
        (EntityDamage, "repair_window") => |c, v| c.repair_window = v,
        (Collision, "collision_window") => |c, v| c.collision_window = v,
        (Collision, "collision_speed") => |c, v| c.collision_speed = v,
        (FireDetonation, "impact_tolerance") => |c, v| c.impact_tolerance = v,
        (Emission, "ee_heartbeat") => |c, v| c.ee_heartbeat = v,
        (Emission, "high_density_threshold") => |c, v| c.high_density_threshold = v,
        (Designator, "final_report_window") => |c, v| c.designator_window = v,
        _ => return None,
    })
}

fn parse_severity(s: &str) -> Option<Option<Severity>> {
    match s {
        "warning" => Some(Some(Severity::Warning)),
        "critical" => Some(Some(Severity::Critical)),
        "off" => Some(None),
        _ => None,
    }
}

/// `allowed` accepts an integer, a `"lo-hi"` / `"a, b-c"` string, or an
/// array of integers and range strings. Values must be non-negative.
fn parse_allowed(v: &Value, origin: &str) -> Result<Vec<RangeInclusive<u64>>, PackError> {
    let bad = || {
        PackError::at(
            origin,
            0,
            "bad 'allowed' value (want integer, \"lo-hi\" or array)".to_string(),
        )
    };
    let mut ranges = Vec::new();
    let items: Vec<Value> = match v {
        Value::Array(a) => a.clone(),
        other => vec![other.clone()],
    };
    for item in items {
        match item {
            Value::Integer(i) if i >= 0 => ranges.push(i as u64..=i as u64),
            Value::String(s) => {
                for part in s.split(',') {
                    let part = part.trim();
                    let (lo, hi) = match part.split_once('-') {
                        Some((a, b)) => (
                            a.trim().parse::<u64>().map_err(|_| bad())?,
                            b.trim().parse::<u64>().map_err(|_| bad())?,
                        ),
                        None => (
                            part.parse::<u64>().map_err(|_| bad())?,
                            part.parse::<u64>().map_err(|_| bad())?,
                        ),
                    };
                    if lo > hi {
                        return Err(PackError::at(origin, 0, format!("allowed range '{part}' is backwards")));
                    }
                    ranges.push(lo..=hi);
                }
            }
            _ => return Err(bad()),
        }
    }
    if ranges.is_empty() {
        return Err(bad());
    }
    ranges.sort_by_key(|r| *r.start());
    Ok(ranges)
}

fn table_only<'a>(v: &'a Value, origin: &str, what: &str) -> Result<&'a Table, PackError> {
    match v {
        Value::Table(t) => Ok(t),
        _ => Err(PackError::at(origin, 0, format!("'{what}' must be a [section]"))),
    }
}

fn check_keys(t: &Table, allowed: &[&str], origin: &str, what: &str) -> Result<(), PackError> {
    for k in t.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(PackError::at(
                origin,
                0,
                format!("unknown key '{k}' in {what} (allowed: {})", allowed.join(", ")),
            ));
        }
    }
    Ok(())
}

impl RulePack {
    /// Parse a pack file's text. `origin` names it in error messages.
    pub fn parse(src: &str, origin: &str) -> Result<RulePack, PackError> {
        let root = minitoml::parse(src).map_err(|e| PackError::at(origin, e.line, e.message))?;
        check_keys(
            &root,
            &["pack", "defaults", "rules", "enum", "capture"],
            origin,
            "pack file",
        )?;

        // [pack] metadata.
        let meta = table_only(
            root.get("pack")
                .ok_or_else(|| PackError::at(origin, 0, "missing [pack] section"))?,
            origin,
            "pack",
        )?;
        check_keys(
            meta,
            &["id", "name", "version", "source", "description"],
            origin,
            "[pack]",
        )?;
        let get_str = |k: &str| -> Result<Option<String>, PackError> {
            match meta.get(k) {
                None => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(PackError::at(origin, 0, format!("pack.{k} must be a string"))),
            }
        };
        let id = get_str("id")?.filter(|s| !s.is_empty());
        let version = match meta.get("version") {
            Some(Value::Integer(i)) if *i > 0 => *i as u64,
            _ => return Err(PackError::at(origin, 0, "pack.version must be a positive integer")),
        };
        let mut pack = RulePack {
            id: id.ok_or_else(|| PackError::at(origin, 0, "pack.id must be a non-empty string"))?,
            name: get_str("name")?.unwrap_or_default(),
            version,
            source: get_str("source")?,
            description: get_str("description")?,
            enum_repeat_seconds: None,
            tick_interval: None,
            rules: BTreeMap::new(),
            enums: Vec::new(),
            captures: Vec::new(),
        };
        if pack.name.is_empty() {
            pack.name = pack.id.clone();
        }

        // [defaults].
        if let Some(v) = root.get("defaults") {
            let d = table_only(v, origin, "defaults")?;
            check_keys(d, &["enum_repeat_seconds", "tick_interval"], origin, "[defaults]")?;
            for (k, slot) in [
                ("enum_repeat_seconds", &mut pack.enum_repeat_seconds),
                ("tick_interval", &mut pack.tick_interval),
            ] {
                if let Some(v) = d.get(k) {
                    let n = num(v).ok_or_else(|| PackError::at(origin, 0, format!("defaults.{k} must be a number")))?;
                    if !(n > 0.0 && n.is_finite()) {
                        return Err(PackError::at(origin, 0, format!("defaults.{k} must be > 0")));
                    }
                    *slot = Some(n);
                }
            }
        }

        // [rules.<name>].
        if let Some(v) = root.get("rules") {
            let rules = table_only(v, origin, "rules")?;
            for (name, v) in rules {
                let rule = Rule::from_name(name).ok_or_else(|| {
                    PackError::at(
                        origin,
                        0,
                        format!("unknown rule '{name}' (expected entity-timeout, id-conflict or position-jump)"),
                    )
                })?;
                let t = table_only(v, origin, &format!("rules.{name}"))?;
                let mut ov = RuleOverlay::default();
                for (k, v) in t {
                    match k.as_str() {
                        "enabled" => {
                            ov.enabled = Some(match v {
                                Value::Bool(b) => *b,
                                _ => {
                                    return Err(PackError::at(
                                        origin,
                                        0,
                                        format!("rules.{name}.enabled must be true/false"),
                                    ))
                                }
                            });
                        }
                        "severity" => {
                            let s = match v {
                                Value::String(s) => s.as_str(),
                                _ => {
                                    return Err(PackError::at(
                                        origin,
                                        0,
                                        format!("rules.{name}.severity must be a string"),
                                    ))
                                }
                            };
                            match parse_severity(s) {
                                Some(sev) => {
                                    ov.severity = sev;
                                    if sev.is_none() {
                                        ov.enabled = Some(false);
                                    }
                                }
                                None => {
                                    return Err(PackError::at(
                                        origin,
                                        0,
                                        format!("rules.{name}.severity must be warning, critical or off"),
                                    ))
                                }
                            }
                        }
                        _ => {
                            let set = set_threshold(rule, k).ok_or_else(|| {
                                PackError::at(origin, 0, format!("unknown threshold '{k}' for rule '{name}'"))
                            })?;
                            let n = num(v).ok_or_else(|| {
                                PackError::at(origin, 0, format!("rules.{name}.{k} must be a number"))
                            })?;
                            if !(n >= 0.0 && n.is_finite()) {
                                return Err(PackError::at(origin, 0, format!("rules.{name}.{k} must be >= 0")));
                            }
                            let mut probe = RuleConfig::default();
                            set(&mut probe, n);
                            ov.values.insert(k.clone(), n);
                        }
                    }
                }
                pack.rules.insert(rule, ov);
            }
        }

        // [[enum]].
        if let Some(v) = root.get("enum") {
            let entries = match v {
                Value::Tables(ts) => ts,
                _ => return Err(PackError::at(origin, 0, "'enum' must be a [[section]]")),
            };
            let mut seen = BTreeMap::new();
            for t in entries {
                check_keys(t, &["field", "allowed", "severity"], origin, "[[enum]]")?;
                let field = match t.get("field") {
                    Some(Value::String(s)) => s,
                    _ => return Err(PackError::at(origin, 0, "[[enum]] needs field = \"...\"")),
                };
                let spec = field_spec(field)
                    .ok_or_else(|| PackError::at(origin, 0, format!("unknown enum field '{field}'")))?;
                let mut severity = None;
                let mut off = false;
                if let Some(v) = t.get("severity") {
                    let s = match v {
                        Value::String(s) => s.as_str(),
                        _ => return Err(PackError::at(origin, 0, "enum severity must be a string")),
                    };
                    match parse_severity(s) {
                        Some(sev) => {
                            severity = sev;
                            off = s == "off";
                        }
                        None => {
                            return Err(PackError::at(
                                origin,
                                0,
                                "enum severity must be warning, critical or off",
                            ))
                        }
                    }
                }
                // Disabling a check needs no allowed set.
                let allowed = match (t.get("allowed"), off) {
                    (Some(v), _) => parse_allowed(v, origin)?,
                    (None, true) => Vec::new(),
                    (None, false) => return Err(PackError::at(origin, 0, format!("[[enum]] {field} needs 'allowed'"))),
                };
                if seen.insert(spec.name, ()).is_some() {
                    return Err(PackError::at(origin, 0, format!("duplicate [[enum]] for '{field}'")));
                }
                pack.enums.push(EnumEntry {
                    spec,
                    allowed,
                    severity,
                    off,
                    source: None,
                });
            }
        }

        // [[capture]].
        if let Some(v) = root.get("capture") {
            let entries = match v {
                Value::Tables(ts) => ts,
                _ => return Err(PackError::at(origin, 0, "'capture' must be a [[section]]")),
            };
            for t in entries {
                check_keys(t, &["type", "min_speed", "every"], origin, "[[capture]]")?;
                let prefix = match t.get("type") {
                    Some(Value::String(s)) => parse_type_prefix(s, origin)?,
                    _ => {
                        return Err(PackError::at(
                            origin,
                            0,
                            "[[capture]] needs type = \"*\" or e.g. \"1.2\"",
                        ))
                    }
                };
                let min_speed = match t.get("min_speed") {
                    None => 0.0,
                    Some(v) => num(v)
                        .filter(|n| *n >= 0.0 && n.is_finite())
                        .ok_or_else(|| PackError::at(origin, 0, "capture min_speed must be a number >= 0"))?,
                };
                let every = match t.get("every") {
                    Some(Value::String(s)) if s == "off" => None,
                    Some(v) => Some(num(v).filter(|n| *n >= 0.0 && n.is_finite()).ok_or_else(|| {
                        PackError::at(
                            origin,
                            0,
                            "capture every must be seconds >= 0 (0 = every PDU) or \"off\"",
                        )
                    })?),
                    None => return Err(PackError::at(origin, 0, "[[capture]] needs every = seconds or \"off\"")),
                };
                let rule = CaptureRule {
                    prefix,
                    min_speed,
                    every,
                    pack: pack.id.clone(),
                };
                if pack
                    .captures
                    .iter()
                    .any(|c| c.prefix == rule.prefix && c.min_speed == rule.min_speed)
                {
                    return Err(PackError::at(
                        origin,
                        0,
                        format!(
                            "duplicate [[capture]] for type '{}' at min_speed {}",
                            rule.type_label(),
                            rule.min_speed
                        ),
                    ));
                }
                pack.captures.push(rule);
            }
        }
        Ok(pack)
    }
}

/// The result of layering packs: base first, most specific last.
#[derive(Debug)]
pub struct Merged {
    /// `"id vN"` labels in layer order.
    pub packs: Vec<String>,
    pub config: RuleConfig,
    pub enabled: BTreeMap<Rule, bool>,
    pub severities: BTreeMap<Rule, Severity>,
    /// Pack id that last touched each behavioural rule (for alert citation).
    pub rule_pack: BTreeMap<Rule, String>,
    /// Effective enum checks, keyed by field.
    pub enum_checks: Vec<EnumCheck>,
    pub enum_repeat_seconds: f64,
    /// Effective `[[capture]]` tiers (ADR 0009).
    pub capture: Vec<CaptureRule>,
}

impl Merged {
    /// The base DIS pack compiled into the binary.
    pub fn builtin() -> Result<Merged, PackError> {
        let base = RulePack::parse(BASE_PACK, "<builtin>")?;
        Ok(Merged::merge([base]))
    }

    /// Base pack plus pack files layered on top, in order.
    pub fn load(paths: &[impl AsRef<Path>]) -> Result<Merged, PackError> {
        Merged::load_with(None, paths)
    }

    /// Base pack, then SISO-REF-010's enumerations if given (ADR 0010 tier
    /// E), then pack files: a site pack can still widen or turn off a
    /// SISO-derived check.
    pub fn load_with(siso: Option<&crate::siso::Siso>, paths: &[impl AsRef<Path>]) -> Result<Merged, PackError> {
        let mut packs = vec![RulePack::parse(BASE_PACK, "<builtin>")?];
        packs.extend(siso.map(|s| s.pack()));
        for p in paths {
            let p = p.as_ref();
            let origin = p.display().to_string();
            let text =
                std::fs::read_to_string(p).map_err(|e| PackError::at(&origin, 0, format!("cannot read: {e}")))?;
            packs.push(RulePack::parse(&text, &origin)?);
        }
        Ok(Merged::merge(packs))
    }

    /// Merge already-parsed packs, lowest layer first.
    pub fn merge(packs: impl IntoIterator<Item = RulePack>) -> Merged {
        let mut m = Merged {
            packs: Vec::new(),
            config: RuleConfig::default(),
            enabled: [
                Rule::EntityTimeout,
                Rule::IdConflict,
                Rule::PositionJump,
                Rule::PduStructure,
                Rule::PduPadding,
                Rule::PduFamily,
                Rule::SimanHandshake,
                Rule::Radio,
                Rule::DuplicateDelivery,
                Rule::Heartbeat,
                Rule::EntityLifecycle,
                Rule::FireDetonation,
                Rule::DirectedEnergy,
                Rule::EntityDamage,
                Rule::Collision,
                Rule::Attribute,
                Rule::Emission,
                Rule::Designator,
            ]
            .into_iter()
            .map(|r| (r, true))
            .collect(),
            severities: [
                (Rule::EntityTimeout, Severity::Warning),
                (Rule::IdConflict, Severity::Critical),
                (Rule::PositionJump, Severity::Warning),
                (Rule::PduStructure, Severity::Critical),
                (Rule::PduPadding, Severity::Warning),
                (Rule::PduFamily, Severity::Warning),
                (Rule::SimanHandshake, Severity::Warning),
                (Rule::Radio, Severity::Warning),
                (Rule::DuplicateDelivery, Severity::Warning),
                (Rule::Heartbeat, Severity::Warning),
                (Rule::EntityLifecycle, Severity::Warning),
                (Rule::FireDetonation, Severity::Warning),
                (Rule::DirectedEnergy, Severity::Warning),
                (Rule::EntityDamage, Severity::Warning),
                (Rule::Collision, Severity::Warning),
                (Rule::Attribute, Severity::Warning),
                (Rule::Emission, Severity::Warning),
                (Rule::Designator, Severity::Warning),
            ]
            .into_iter()
            .collect(),
            rule_pack: BTreeMap::new(),
            enum_checks: Vec::new(),
            enum_repeat_seconds: DEFAULT_ENUM_REPEAT,
            capture: Vec::new(),
        };
        let mut checks: BTreeMap<&'static str, EnumCheck> = BTreeMap::new();
        for p in packs {
            m.packs.push(format!("{} v{}", p.id, p.version));
            if let Some(r) = p.enum_repeat_seconds {
                m.enum_repeat_seconds = r;
            }
            if let Some(t) = p.tick_interval {
                m.config.tick_interval = t;
            }
            for (rule, ov) in p.rules {
                m.rule_pack.insert(rule, p.id.clone());
                if let Some(e) = ov.enabled {
                    m.enabled.insert(rule, e);
                }
                if let Some(s) = ov.severity {
                    m.severities.insert(rule, s);
                }
                for (k, v) in ov.values {
                    if let Some(set) = set_threshold(rule, &k) {
                        set(&mut m.config, v);
                    }
                }
            }
            for c in p.captures {
                m.capture
                    .retain(|o| !(o.prefix == c.prefix && o.min_speed == c.min_speed));
                m.capture.push(c);
            }
            for e in p.enums {
                if e.off {
                    checks.remove(e.spec.name);
                    continue;
                }
                let severity = e
                    .severity
                    .or_else(|| checks.get(e.spec.name).map(|c| c.severity))
                    .unwrap_or(Severity::Warning);
                checks.insert(
                    e.spec.name,
                    EnumCheck {
                        spec: e.spec,
                        allowed: e.allowed,
                        severity,
                        pack: p.id.clone(),
                        source: e.source,
                    },
                );
            }
        }
        m.enum_checks = checks.into_values().collect();
        m
    }

    /// The capture tier for an entity of type `t` moving at `speed` m/s:
    /// among matching entries, the highest `min_speed` wins (observed
    /// behaviour beats declared type), then the longest type prefix.
    pub fn capture_rule(&self, t: &EntityType, speed: f64) -> Option<&CaptureRule> {
        pick_capture(&self.capture, t, speed)
    }
}

/// The merged base pack, parsed once. Panics only if the embedded file is
/// broken, which the pack tests catch.
pub fn builtin() -> &'static Merged {
    static BASE: std::sync::OnceLock<Merged> = std::sync::OnceLock::new();
    BASE.get_or_init(|| Merged::builtin().expect("built-in base pack must parse"))
}
