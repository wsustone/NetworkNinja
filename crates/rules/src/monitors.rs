//! User monitors (ADR 0008 slice 3): conditions an exercise controller sets
//! on the same metrics `/api/query` charts and on the alert stream, each
//! opening one alert per group (`by`), through the engine's normal alert
//! path (ack, mute, event log, dashboard). Kept as `[[monitor]]` blocks:
//!
//! ```toml
//! [[monitor]]
//! id = "site7-silent"
//! name = "Site 7 federate silent"
//! type = "absence"              # threshold | absence | event-count
//! metric = "pdu.count"
//! where.exercise = 1
//! where.site = 7
//! by = ["sender"]
//! for = 15                      # absence: seconds of silence
//! severity = "critical"
//!
//! [[monitor]]
//! id = "noisy-sender"
//! name = "Noisy sender"
//! type = "event-count"
//! event = "enum-violation"      # a rule name or check id, or "*"
//! by = ["sender"]
//! window = 300
//! condition = ">= 20"
//!
//! [[monitor]]
//! id = "quiet-and-noisy"
//! type = "composite"
//! of = "site7-silent && !noisy-sender"
//! by = ["sender"]
//! ```
//!
//! - **threshold**: the metric, folded over the last `window` seconds per
//!   group (`agg`, as `/api/query`), meets `condition` for `for` seconds.
//! - **absence**: a group that reported in the last ten minutes has sent
//!   nothing for `for` seconds (a federate gone quiet). Counters only.
//! - **event-count**: alert firings matching `event` and `where` in the last
//!   `window` seconds, per group, meet `condition` (default `>= 1`) for
//!   `for` seconds.
//! - **composite**: a boolean expression (`&&`, `||`, `!`, parentheses) over
//!   other monitors' ids, true for a group when the monitors it names are
//!   (or, negated, aren't) firing for that group, held for `for` seconds. Its
//!   `by` must be dimensions every monitor it names groups by (none: any
//!   group counts); composites of composites aren't allowed.
//!
//! Metric windows read the in-memory buckets, so windows and `for` are at
//! most [`MAX_WINDOW`] seconds. (The ADR's `name` for an event-count's rule
//! is `event` here, so `name` can stay the monitor's display name.)

use crate::engine::Severity;
use crate::minitoml::{Table, Value};
use nn_state::metrics::{Dim, Metric, Metrics, TagPairs};
use nn_state::query::{evaluate, Fold, Query};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Longest window or `for` a monitor may have: the metrics kept in memory.
pub const MAX_WINDOW: i64 = nn_state::metrics::HISTORY_SECS as i64;
/// How far back an absence looks for groups that used to report.
const SEEN_WITHIN: i64 = MAX_WINDOW;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Threshold,
    Absence,
    EventCount,
    Composite,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Threshold => "threshold",
            Kind::Absence => "absence",
            Kind::EventCount => "event-count",
            Kind::Composite => "composite",
        }
    }

    fn from_name(s: &str) -> Option<Kind> {
        [Kind::Threshold, Kind::Absence, Kind::EventCount, Kind::Composite]
            .into_iter()
            .find(|k| k.name() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Op {
    Gt,
    Ge,
    Lt,
    Le,
}

/// `> 5`, `>= 20`, `< 1`, `<= 0.5`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Condition {
    pub op: Op,
    pub value: f64,
}

impl Condition {
    pub fn parse(s: &str) -> Result<Condition, String> {
        let s = s.trim();
        let (op, rest) = [(">=", Op::Ge), ("<=", Op::Le), (">", Op::Gt), ("<", Op::Lt)]
            .into_iter()
            .find_map(|(p, op)| s.strip_prefix(p).map(|r| (op, r)))
            .ok_or_else(|| format!("condition '{s}' must start with >, >=, < or <="))?;
        let value = rest
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .ok_or_else(|| format!("condition '{s}' needs a number after the operator"))?;
        Ok(Condition { op, value })
    }

    pub fn holds(&self, v: f64) -> bool {
        match self.op {
            Op::Gt => v > self.value,
            Op::Ge => v >= self.value,
            Op::Lt => v < self.value,
            Op::Le => v <= self.value,
        }
    }
}

impl std::fmt::Display for Condition {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let op = match self.op {
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Lt => "<",
            Op::Le => "<=",
        };
        write!(f, "{op} {}", self.value)
    }
}

/// A composite's expression over monitor ids.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Ref(String),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

impl Expr {
    /// `a && (b || !c)`: `!` binds tightest, then `&&`, then `||`.
    pub fn parse(src: &str) -> Result<Expr, String> {
        let mut toks = Vec::new();
        let cs: Vec<char> = src.chars().collect();
        let mut i = 0;
        while i < cs.len() {
            let c = cs[i];
            if c.is_whitespace() {
                i += 1;
            } else if "()!".contains(c) {
                toks.push(c.to_string());
                i += 1;
            } else if (c == '&' || c == '|') && cs.get(i + 1) == Some(&c) {
                toks.push(format!("{c}{c}"));
                i += 2;
            } else if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                let start = i;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '-' || cs[i] == '_') {
                    i += 1;
                }
                toks.push(cs[start..i].iter().collect());
            } else {
                return Err(format!(
                    "'{c}' in \"{src}\" (use monitor ids with &&, ||, ! and parentheses)"
                ));
            }
        }
        let mut pos = 0;
        let e = Self::or(&toks, &mut pos)?;
        match toks.get(pos) {
            None => Ok(e),
            Some(t) => Err(format!("unexpected '{t}' in \"{src}\"")),
        }
    }

    fn or(t: &[String], p: &mut usize) -> Result<Expr, String> {
        let mut e = Self::and(t, p)?;
        while t.get(*p).map(String::as_str) == Some("||") {
            *p += 1;
            e = Expr::Or(Box::new(e), Box::new(Self::and(t, p)?));
        }
        Ok(e)
    }

    fn and(t: &[String], p: &mut usize) -> Result<Expr, String> {
        let mut e = Self::not(t, p)?;
        while t.get(*p).map(String::as_str) == Some("&&") {
            *p += 1;
            e = Expr::And(Box::new(e), Box::new(Self::not(t, p)?));
        }
        Ok(e)
    }

    fn not(t: &[String], p: &mut usize) -> Result<Expr, String> {
        let tok = t.get(*p).ok_or("the expression ends early")?;
        *p += 1;
        match tok.as_str() {
            "!" => Ok(Expr::Not(Box::new(Self::not(t, p)?))),
            "(" => {
                let e = Self::or(t, p)?;
                if t.get(*p).map(String::as_str) != Some(")") {
                    return Err("a '(' isn't closed".into());
                }
                *p += 1;
                Ok(e)
            }
            "&&" | "||" | ")" => Err(format!("expected a monitor id, got '{tok}'")),
            id => Ok(Expr::Ref(id.to_string())),
        }
    }

    /// The monitor ids it names, in order.
    pub fn refs(&self) -> Vec<&str> {
        match self {
            Expr::Ref(id) => vec![id.as_str()],
            Expr::Not(e) => e.refs(),
            Expr::And(a, b) | Expr::Or(a, b) => {
                let mut v = a.refs();
                v.extend(b.refs());
                v
            }
        }
    }

    pub fn eval(&self, firing: &dyn Fn(&str) -> bool) -> bool {
        match self {
            Expr::Ref(id) => firing(id),
            Expr::Not(e) => !e.eval(firing),
            Expr::And(a, b) => a.eval(firing) && b.eval(firing),
            Expr::Or(a, b) => a.eval(firing) || b.eval(firing),
        }
    }
}

impl std::fmt::Display for Expr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // Parenthesise an || inside an &&, and anything compound under a !.
        let sub = |e: &Expr, f: &mut std::fmt::Formatter, paren: bool| {
            if paren {
                write!(f, "({e})")
            } else {
                write!(f, "{e}")
            }
        };
        match self {
            Expr::Ref(id) => write!(f, "{id}"),
            Expr::Not(e) => {
                write!(f, "!")?;
                sub(e, f, !matches!(**e, Expr::Ref(_) | Expr::Not(_)))
            }
            Expr::And(a, b) => {
                sub(a, f, matches!(**a, Expr::Or(..)))?;
                write!(f, " && ")?;
                sub(b, f, matches!(**b, Expr::Or(..) | Expr::And(..)))
            }
            Expr::Or(a, b) => {
                sub(a, f, false)?;
                write!(f, " || ")?;
                sub(b, f, matches!(**b, Expr::Or(..)))
            }
        }
    }
}

/// One user monitor.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorDef {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    /// Threshold and absence: the metric.
    pub metric: Option<Metric>,
    /// Event-count: the rule name or check id to count, or `*`.
    pub event: Option<String>,
    /// Composite: the expression over other monitors.
    pub of: Option<Expr>,
    pub filter: Vec<(Dim, String)>,
    pub by: Vec<Dim>,
    pub agg: Fold,
    pub window: i64,
    pub condition: Option<Condition>,
    /// Seconds the condition must hold before the alert opens (absence: the
    /// silence it takes).
    pub for_secs: i64,
    pub severity: Severity,
}

/// Dimensions an event-count may filter and group on.
const EVENT_DIMS: [Dim; 6] = [Dim::Exercise, Dim::Site, Dim::App, Dim::Entity, Dim::Sender, Dim::Rule];

fn string(v: &Value, what: &str) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        Value::Integer(i) => Ok(i.to_string()),
        _ => Err(format!("{what} must be a string")),
    }
}

fn number(v: &Value, what: &str) -> Result<f64, String> {
    match v {
        Value::Integer(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        _ => Err(format!("{what} must be a number")),
    }
}

impl MonitorDef {
    /// One `[[monitor]]` table, validated.
    pub fn from_table(t: &Table) -> Result<MonitorDef, String> {
        const KEYS: [&str; 13] = [
            "id",
            "name",
            "type",
            "metric",
            "event",
            "of",
            "where",
            "by",
            "agg",
            "window",
            "condition",
            "for",
            "severity",
        ];
        if let Some(k) = t.keys().find(|k| !KEYS.contains(&k.as_str())) {
            return Err(format!("unknown key '{k}' (expected one of: {})", KEYS.join(", ")));
        }
        let get = |k: &str, what: &str| t.get(k).map(|v| string(v, what)).transpose();
        let id = get("id", "id")?.ok_or("a monitor needs an id")?;
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(format!("id '{id}' must be letters, digits, - or _"));
        }
        let what = |k: &str| format!("monitor '{id}' {k}");
        let kind_s = get("type", "type")?.ok_or_else(|| format!("monitor '{id}' needs a type"))?;
        let kind = Kind::from_name(&kind_s).ok_or_else(|| {
            format!("monitor '{id}': unknown type '{kind_s}' (expected threshold, absence, event-count or composite)")
        })?;
        let name = get("name", &what("name"))?.unwrap_or_else(|| id.clone());
        if kind == Kind::Composite {
            if let Some(k) = ["metric", "event", "where", "agg", "window", "condition"]
                .into_iter()
                .find(|k| t.contains_key(*k))
            {
                return Err(format!(
                    "monitor '{id}': a composite takes of, by, for and severity, not {k}"
                ));
            }
        } else if t.contains_key("of") {
            return Err(format!("monitor '{id}': only a composite takes of"));
        }
        let of = match kind {
            Kind::Composite => {
                let src = get("of", &what("of"))?
                    .ok_or_else(|| format!("monitor '{id}': a composite needs of, e.g. of = \"a && !b\""))?;
                let e = Expr::parse(&src).map_err(|e| format!("monitor '{id}' of: {e}"))?;
                if e.refs().contains(&id.as_str()) {
                    return Err(format!("monitor '{id}' can't name itself in of"));
                }
                Some(e)
            }
            _ => None,
        };
        let (metric, event) = match kind {
            Kind::Composite => (None, None),
            Kind::EventCount => (None, Some(get("event", &what("event"))?.unwrap_or_else(|| "*".into()))),
            _ => {
                let m = get("metric", &what("metric"))?.ok_or_else(|| format!("monitor '{id}' needs a metric"))?;
                let metric = Metric::from_name(&m).ok_or_else(|| {
                    format!(
                        "monitor '{id}': unknown metric '{m}' (expected one of {})",
                        Metric::ALL.iter().map(|m| m.name()).collect::<Vec<_>>().join(", ")
                    )
                })?;
                if kind == Kind::Absence && metric.is_gauge() {
                    return Err(format!(
                        "monitor '{id}': absence needs a counter (e.g. pdu.count); {m} is a gauge"
                    ));
                }
                (Some(metric), None)
            }
        };
        // A composite's `by` is checked against the monitors it names, in
        // `check_composites`.
        let dims: Vec<Dim> = match (metric, kind) {
            (Some(m), _) => m.dims().to_vec(),
            (None, Kind::Composite) => Dim::ALL.to_vec(),
            (None, _) => EVENT_DIMS.to_vec(),
        };
        let dim = |s: &str| -> Result<Dim, String> {
            let d = Dim::from_name(s).ok_or_else(|| format!("monitor '{id}': unknown dimension '{s}'"))?;
            if !dims.contains(&d) {
                return Err(format!(
                    "monitor '{id}': no dimension '{s}' here (it has {})",
                    dims.iter().map(|d| d.name()).collect::<Vec<_>>().join(", ")
                ));
            }
            Ok(d)
        };
        let mut filter = Vec::new();
        match t.get("where") {
            None => {}
            Some(Value::Table(w)) => {
                for (k, v) in w {
                    filter.push((dim(k)?, string(v, &what(&format!("where.{k}")))?));
                }
            }
            Some(_) => return Err(format!("monitor '{id}': give filters as where.DIM = value")),
        }
        let mut by = Vec::new();
        match t.get("by") {
            None => {}
            Some(Value::Array(a)) => {
                for v in a {
                    let d = dim(&string(v, &what("by"))?)?;
                    if !by.contains(&d) {
                        by.push(d);
                    }
                }
            }
            Some(v) => by.push(dim(&string(v, &what("by"))?)?),
        }
        let agg = match get("agg", &what("agg"))? {
            Some(s) => Fold::from_name(&s)
                .ok_or_else(|| format!("monitor '{id}': unknown agg '{s}' (sum, avg, min, max, count, rate)"))?,
            None if metric.is_some_and(|m| m.is_gauge()) => Fold::Avg,
            None => Fold::Rate,
        };
        if agg == Fold::Rate && metric.is_some_and(|m| m.is_gauge()) {
            return Err(format!(
                "monitor '{id}': rate applies to counters; use avg, min, max or sum"
            ));
        }
        let secs = |k: &str, default: i64| -> Result<i64, String> {
            let v = t
                .get(k)
                .map(|v| number(v, &what(k)))
                .transpose()?
                .unwrap_or(default as f64);
            if !(0.0..=MAX_WINDOW as f64).contains(&v) {
                return Err(format!("monitor '{id}': {k} must be 0-{MAX_WINDOW} s, got {v}"));
            }
            Ok(v.round() as i64)
        };
        let window = secs("window", 60)?.max(1);
        let for_secs = secs("for", if kind == Kind::Absence { 15 } else { 0 })?;
        if kind == Kind::Absence && for_secs < 1 {
            return Err(format!(
                "monitor '{id}': an absence needs for (the silence), at least 1 s"
            ));
        }
        let condition = match get("condition", &what("condition"))? {
            Some(c) => Some(Condition::parse(&c).map_err(|e| format!("monitor '{id}': {e}"))?),
            None if kind == Kind::Threshold => {
                return Err(format!(
                    "monitor '{id}': a threshold needs a condition, e.g. condition = \"> 5\""
                ))
            }
            None if kind == Kind::EventCount => Some(Condition { op: Op::Ge, value: 1.0 }),
            None => None,
        };
        let severity = match get("severity", &what("severity"))?.as_deref() {
            None | Some("warning") => Severity::Warning,
            Some("critical") => Severity::Critical,
            Some(s) => return Err(format!("monitor '{id}': severity '{s}' must be warning or critical")),
        };
        Ok(MonitorDef {
            id,
            name,
            kind,
            metric,
            event,
            of,
            filter,
            by,
            agg,
            window,
            condition,
            for_secs,
            severity,
        })
    }

    /// Every `[[monitor]]` block of a file's text, composites checked
    /// against the rest ([`check_composites`]).
    pub fn parse_all(src: &str) -> Result<Vec<MonitorDef>, String> {
        let out = Self::parse_blocks(src)?;
        check_composites(&out)?;
        Ok(out)
    }

    /// The blocks alone: a composite may name monitors defined elsewhere.
    pub fn parse_blocks(src: &str) -> Result<Vec<MonitorDef>, String> {
        let root = crate::minitoml::parse(src).map_err(|e| e.to_string())?;
        if let Some(k) = root.keys().find(|k| k.as_str() != "monitor") {
            return Err(format!(
                "unknown section '{k}' (a monitors file holds [[monitor]] blocks)"
            ));
        }
        let mut out: Vec<MonitorDef> = Vec::new();
        match root.get("monitor") {
            None => {}
            Some(Value::Tables(ts)) => {
                for (i, t) in ts.iter().enumerate() {
                    let m = MonitorDef::from_table(t).map_err(|e| format!("[[monitor]] #{}: {e}", i + 1))?;
                    if out.iter().any(|o| o.id == m.id) {
                        return Err(format!("two monitors have id '{}'", m.id));
                    }
                    out.push(m);
                }
            }
            Some(_) => return Err("monitors are [[monitor]] blocks".into()),
        }
        Ok(out)
    }

    /// The monitor as a `[[monitor]]` block.
    pub fn to_toml(&self) -> String {
        let q = |s: &str| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""));
        let mut s = format!(
            "[[monitor]]\nid = {}\nname = {}\ntype = {}\n",
            q(&self.id),
            q(&self.name),
            q(self.kind.name())
        );
        if let Some(m) = self.metric {
            s += &format!("metric = {}\n", q(m.name()));
        }
        if let Some(e) = &self.event {
            s += &format!("event = {}\n", q(e));
        }
        if let Some(e) = &self.of {
            s += &format!("of = {}\n", q(&e.to_string()));
        }
        for (d, v) in &self.filter {
            s += &format!("where.{} = {}\n", d.name(), q(v));
        }
        if !self.by.is_empty() {
            let b: Vec<String> = self.by.iter().map(|d| q(d.name())).collect();
            s += &format!("by = [{}]\n", b.join(", "));
        }
        if self.metric.is_some() {
            s += &format!("agg = {}\n", q(self.agg.name()));
        }
        if !matches!(self.kind, Kind::Absence | Kind::Composite) {
            s += &format!("window = {}\n", self.window);
        }
        if let Some(c) = &self.condition {
            s += &format!("condition = {}\n", q(&c.to_string()));
        }
        s += &format!("for = {}\n", self.for_secs);
        s += &format!(
            "severity = {}\n\n",
            q(match self.severity {
                Severity::Critical => "critical",
                Severity::Warning => "warning",
            })
        );
        s
    }

    /// What the monitor watches, for messages: `pdu.count rate over 60 s
    /// where site=7 by sender`.
    pub fn describe(&self) -> String {
        let what = match (self.metric, &self.event) {
            (Some(m), _) if self.kind == Kind::Absence => format!("{} silent for {} s", m.name(), self.for_secs),
            (Some(m), _) => format!("{} {} over {} s", m.name(), self.agg.name(), self.window),
            (None, Some(e)) => format!("{e} firings over {} s", self.window),
            _ if self.of.is_some() => format!("{}", self.of.as_ref().unwrap()),
            _ => String::new(),
        };
        let wh: Vec<String> = self.filter.iter().map(|(d, v)| format!("{}={v}", d.name())).collect();
        let by: Vec<&str> = self.by.iter().map(|d| d.name()).collect();
        format!(
            "{what}{}{}",
            if wh.is_empty() {
                String::new()
            } else {
                format!(" where {}", wh.join(", "))
            },
            if by.is_empty() {
                String::new()
            } else {
                format!(" by {}", by.join(", "))
            }
        )
    }
}

/// Composites must name monitors that exist and aren't composites, and
/// group only by dimensions all of them group by.
pub fn check_composites(defs: &[MonitorDef]) -> Result<(), String> {
    for d in defs {
        let Some(of) = &d.of else { continue };
        for r in of.refs() {
            let target = defs
                .iter()
                .find(|o| o.id == r)
                .ok_or_else(|| format!("composite '{}' names '{r}', which isn't a monitor", d.id))?;
            if target.kind == Kind::Composite {
                return Err(format!(
                    "composite '{}' names '{r}', another composite (name its monitors instead)",
                    d.id
                ));
            }
            if let Some(b) = d.by.iter().find(|b| !target.by.contains(b)) {
                return Err(format!(
                    "composite '{}' groups by {}, which '{r}' doesn't",
                    d.id,
                    b.name()
                ));
            }
        }
    }
    Ok(())
}

/// An alert firing, as an event-count monitor sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct EventRec {
    pub at: f64,
    pub rule_name: String,
    pub rule_id: String,
    pub tags: TagPairs,
}

/// What changed for one monitor group.
#[derive(Debug, Clone, PartialEq)]
pub enum Change {
    Fire { value: f64 },
    Resolve,
}

#[derive(Debug, Clone, Default)]
struct GroupState {
    breach_since: Option<f64>,
    firing: bool,
    value: f64,
}

/// The monitors in force, their groups' state, and the recent alert firings
/// event-counts count.
#[derive(Debug, Default)]
pub struct Monitors {
    pub defs: Vec<MonitorDef>,
    state: BTreeMap<(String, TagPairs), GroupState>,
    events: VecDeque<EventRec>,
}

/// The current value per group, and whether it breaches.
fn measure(
    def: &MonitorDef,
    now: f64,
    metrics: &Metrics,
    events: &VecDeque<EventRec>,
) -> BTreeMap<TagPairs, (f64, bool)> {
    let to = now.floor() as i64;
    let mut out = BTreeMap::new();
    match def.kind {
        Kind::Threshold => {
            let q = query(def, to - def.window, to);
            let cells = metrics.cells(q.metric, q.from, q.to, |t| q.matches(t));
            for s in evaluate(&q, cells) {
                if let Some(&(_, v)) = s.points.first() {
                    let breach = def.condition.is_some_and(|c| c.holds(v));
                    out.insert(s.tags, (v, breach));
                }
            }
        }
        Kind::Absence => {
            // Groups that reported in the last ten minutes, and those still
            // reporting in the last `for` seconds.
            let seen = query(def, to - SEEN_WITHIN, to);
            let recent = query(def, to - def.for_secs, to);
            let total = |q: &Query| -> BTreeMap<TagPairs, f64> {
                let cells = metrics.cells(q.metric, q.from, q.to, |t| q.matches(t));
                evaluate(q, cells)
                    .into_iter()
                    .map(|s| (s.tags, s.points.iter().map(|p| p.1).sum::<f64>()))
                    .collect()
            };
            let now_vals = total(&recent);
            for (g, v) in total(&seen) {
                if v <= 0.0 {
                    continue;
                }
                let quiet = now_vals.get(&g).copied().unwrap_or(0.0) <= 0.0;
                out.insert(g, (if quiet { 0.0 } else { 1.0 }, quiet));
            }
        }
        Kind::EventCount => {
            let from = now - def.window as f64;
            let mut counts: BTreeMap<TagPairs, f64> = BTreeMap::new();
            for e in events.iter().filter(|e| e.at > from && e.at <= now) {
                let name_ok = match def.event.as_deref() {
                    None | Some("*") => true,
                    Some(n) => e.rule_name == n || e.rule_id == n,
                };
                let where_ok = def
                    .filter
                    .iter()
                    .all(|(d, v)| e.tags.iter().any(|(td, tv)| td == d && tv.eq_ignore_ascii_case(v)));
                if name_ok && where_ok {
                    let g: TagPairs = e.tags.iter().filter(|(d, _)| def.by.contains(d)).cloned().collect();
                    *counts.entry(g).or_default() += 1.0;
                }
            }
            for (g, v) in counts {
                out.insert(g, (v, def.condition.is_some_and(|c| c.holds(v))));
            }
        }
        Kind::Composite => {}
    }
    out
}

/// A composite's groups and whether its expression holds for each, given
/// the other monitors' state: a monitor counts for a group when one of its
/// firing groups has the group's values.
fn measure_composite(
    def: &MonitorDef,
    state: &BTreeMap<(String, TagPairs), GroupState>,
) -> BTreeMap<TagPairs, (f64, bool)> {
    let Some(of) = &def.of else { return BTreeMap::new() };
    let refs = of.refs();
    let project = |g: &TagPairs| -> TagPairs { g.iter().filter(|(d, _)| def.by.contains(d)).cloned().collect() };
    let mut firing: BTreeMap<&str, BTreeSet<TagPairs>> = BTreeMap::new();
    for ((id, g), s) in state {
        if s.firing && refs.contains(&id.as_str()) {
            firing.entry(id.as_str()).or_default().insert(project(g));
        }
    }
    let mut groups: BTreeSet<TagPairs> = firing.values().flatten().cloned().collect();
    if def.by.is_empty() {
        groups.insert(Vec::new());
    }
    groups
        .into_iter()
        .map(|g| {
            let holds = of.eval(&|id| firing.get(id).is_some_and(|gs| gs.contains(&g)));
            (g, (if holds { 1.0 } else { 0.0 }, holds))
        })
        .collect()
}

fn query(def: &MonitorDef, from: i64, to: i64) -> Query {
    Query {
        metric: def.metric.expect("a metric monitor"),
        filter: def.filter.clone(),
        by: def.by.clone(),
        agg: if def.kind == Kind::Absence { Fold::Sum } else { def.agg },
        window: (to - from).max(1),
        from,
        to: to.max(from + 1),
    }
}

impl Monitors {
    /// Replace the monitors; groups of monitors that changed or went start
    /// over (their open alerts are the caller's to resolve, see
    /// [`Monitors::firing`]).
    pub fn set(&mut self, defs: Vec<MonitorDef>) {
        self.state.retain(|(id, _), _| defs.iter().any(|d| &d.id == id));
        for d in &defs {
            if self.defs.iter().find(|o| o.id == d.id) != Some(d) {
                self.state.retain(|(id, _), _| id != &d.id);
            }
        }
        self.defs = defs;
    }

    /// Open groups: (monitor id, group, value).
    pub fn firing(&self) -> impl Iterator<Item = (&str, &TagPairs, f64)> {
        self.state
            .iter()
            .filter(|(_, s)| s.firing)
            .map(|((id, g), s)| (id.as_str(), g, s.value))
    }

    /// An alert firing, for event-counts. Kept for [`MAX_WINDOW`].
    pub fn record(&mut self, e: EventRec) {
        while self.events.front().is_some_and(|f| f.at < e.at - MAX_WINDOW as f64) {
            self.events.pop_front();
        }
        self.events.push_back(e);
    }

    /// Evaluate every monitor at `now`: the groups that opened or resolved.
    pub fn evaluate(&mut self, now: f64, metrics: &Metrics) -> Vec<(usize, TagPairs, Change)> {
        let mut out = Vec::new();
        // Composites last, so they see this round's state of what they name.
        let order: Vec<usize> = (0..self.defs.len())
            .filter(|&i| self.defs[i].kind != Kind::Composite)
            .chain((0..self.defs.len()).filter(|&i| self.defs[i].kind == Kind::Composite))
            .collect();
        for i in order {
            let def = &self.defs[i];
            let values = if def.kind == Kind::Composite {
                measure_composite(def, &self.state)
            } else {
                measure(def, now, metrics, &self.events)
            };
            // Groups seen now, and groups that were open but have no value.
            let mut groups: BTreeSet<TagPairs> = values.keys().cloned().collect();
            groups.extend(
                self.state
                    .keys()
                    .filter(|(id, _)| id == &def.id)
                    .map(|(_, g)| g.clone()),
            );
            for g in groups {
                let (v, breach) = values.get(&g).copied().unwrap_or((0.0, false));
                let s = self.state.entry((def.id.clone(), g.clone())).or_default();
                s.value = v;
                if breach {
                    let since = *s.breach_since.get_or_insert(now);
                    if !s.firing && now - since >= def.for_secs as f64 {
                        s.firing = true;
                        out.push((i, g, Change::Fire { value: v }));
                    }
                } else {
                    s.breach_since = None;
                    if s.firing {
                        s.firing = false;
                        out.push((i, g, Change::Resolve));
                    }
                }
            }
            self.state
                .retain(|(id, _), s| id != &def.id || s.firing || s.breach_since.is_some());
        }
        out
    }

    /// "Would have fired N times": replay `def` over `[from, to]` every
    /// `step` seconds on what memory still holds. Returns (times it would
    /// have opened, the groups that did).
    pub fn preview(
        &self,
        def: &MonitorDef,
        metrics: &Metrics,
        (from, to, step): (f64, f64, f64),
    ) -> (usize, BTreeSet<TagPairs>) {
        // A composite replays the monitors it names alongside it.
        let mut defs: Vec<MonitorDef> = match &def.of {
            Some(of) => self
                .defs
                .iter()
                .filter(|d| of.refs().contains(&d.id.as_str()))
                .cloned()
                .collect(),
            None => Vec::new(),
        };
        defs.retain(|d| d.id != def.id);
        defs.push(def.clone());
        let me = defs.len() - 1;
        let mut sim = Monitors {
            defs,
            state: BTreeMap::new(),
            events: self.events.clone(),
        };
        let (mut fired, mut groups) = (0, BTreeSet::new());
        let mut t = from;
        while t <= to {
            for (i, g, c) in sim.evaluate(t, metrics) {
                if let (true, Change::Fire { .. }) = (i == me, c) {
                    fired += 1;
                    groups.insert(g);
                }
            }
            t += step.max(1.0);
        }
        (fired, groups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_state::metrics::Tags;
    use std::net::SocketAddr;

    fn defs(src: &str) -> Vec<MonitorDef> {
        MonitorDef::parse_all(src).unwrap()
    }

    #[test]
    fn monitors_parse_validate_and_print_back() {
        let src = r#"
[[monitor]]
id = "site7-silent"
name = "Site 7 federate silent"
type = "absence"
metric = "pdu.count"
where.exercise = 1
where.site = 7
by = ["sender"]
for = 15
severity = "critical"

[[monitor]]
id = "noisy-sender"
type = "event-count"
event = "enum-violation"
by = ["sender"]
window = 300
condition = ">= 20"
"#;
        let d = defs(src);
        assert_eq!(d[0].kind, Kind::Absence);
        assert_eq!(d[0].filter, vec![(Dim::Exercise, "1".into()), (Dim::Site, "7".into())]);
        assert_eq!(d[0].severity, Severity::Critical);
        assert_eq!(
            d[1].condition,
            Some(Condition {
                op: Op::Ge,
                value: 20.0
            })
        );
        assert_eq!(d[1].name, "noisy-sender", "name defaults to the id");
        // Printed back, they parse to the same monitors.
        let back: String = d.iter().map(|m| m.to_toml()).collect();
        assert_eq!(defs(&back), d, "{back}");
        let err = |s: &str| MonitorDef::parse_all(s).unwrap_err();
        assert!(
            err("[[monitor]]\nid = \"x\"\ntype = \"threshold\"\nmetric = \"pdu.count\"\n")
                .contains("needs a condition")
        );
        assert!(
            err("[[monitor]]\nid = \"x\"\ntype = \"absence\"\nmetric = \"entity.active\"\n")
                .contains("needs a counter")
        );
        assert!(err("[[monitor]]\nid = \"x\"\ntype = \"threshold\"\nmetric = \"pdu.count\"\nwhere.colour = 1\ncondition = \"> 1\"\n").contains("unknown dimension"));
        assert!(err("[[monitor]]\nid = \"x\"\ntype = \"threshold\"\nmetric = \"pdu.count\"\nwindow = 4000\ncondition = \"> 1\"\n").contains("0-600"));
        assert!(
            err("[[monitor]]\nid = \"a b\"\ntype = \"absence\"\nmetric = \"pdu.count\"\n").contains("letters, digits")
        );
        assert!(Condition::parse("about 5").is_err());
    }

    fn src(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 7, 10], port))
    }

    /// Entity State counts from two senders on site 7, the second stopping
    /// at `stop` seconds.
    fn traffic(stop: i64, until: i64) -> Metrics {
        let mut m = Metrics::default();
        for t in 0..until {
            for (port, last) in [(3000, until), (3001, stop)] {
                if t < last {
                    let tags = Tags {
                        exercise: Some(1),
                        site: Some(7),
                        pdu_type: Some("EntityState"),
                        sender: Some(src(port)),
                        ..Default::default()
                    };
                    m.record(t as f64 + 0.5, nn_state::metrics::Metric::PduCount, tags, 2.0);
                }
            }
        }
        m
    }

    #[test]
    fn an_absence_opens_one_alert_for_the_silent_sender_and_resolves() {
        let mut ms = Monitors::default();
        ms.set(defs("[[monitor]]\nid = \"quiet\"\ntype = \"absence\"\nmetric = \"pdu.count\"\nwhere.site = 7\nby = [\"sender\"]\nfor = 15\n"));
        let m = traffic(100, 200);
        let mut opened = Vec::new();
        for t in (60..200).step_by(5) {
            opened.extend(ms.evaluate(t as f64, &m));
        }
        assert_eq!(opened.len(), 1, "{opened:?}");
        let (_, g, c) = &opened[0];
        assert_eq!(g, &vec![(Dim::Sender, src(3001).to_string())]);
        assert_eq!(c, &Change::Fire { value: 0.0 });
        assert_eq!(ms.firing().count(), 1);
        // The sender comes back: the alert resolves.
        let mut back = traffic(100, 200);
        for t in 200..230 {
            let tags = Tags {
                exercise: Some(1),
                site: Some(7),
                pdu_type: Some("EntityState"),
                sender: Some(src(3001)),
                ..Default::default()
            };
            back.record(t as f64 + 0.5, nn_state::metrics::Metric::PduCount, tags, 2.0);
        }
        let resolved = ms.evaluate(229.0, &back);
        assert_eq!(resolved.iter().map(|r| &r.2).collect::<Vec<_>>(), [&Change::Resolve]);
    }

    #[test]
    fn a_threshold_must_hold_for_its_for() {
        let mut ms = Monitors::default();
        // Each sender sends 2 PDUs/s: above 1/s holds from the first window.
        ms.set(defs("[[monitor]]\nid = \"busy\"\ntype = \"threshold\"\nmetric = \"pdu.count\"\nby = [\"sender\"]\nwindow = 10\ncondition = \"> 1\"\nfor = 20\n"));
        let m = traffic(1000, 200);
        assert!(ms.evaluate(100.0, &m).is_empty(), "breach starts");
        assert!(ms.evaluate(110.0, &m).is_empty(), "10 s in");
        assert_eq!(ms.evaluate(121.0, &m).len(), 2, "both senders after 20 s");
        assert!(ms.evaluate(130.0, &m).is_empty(), "already open");
    }

    #[test]
    fn event_counts_count_matching_firings_per_group_and_preview() {
        let mut ms = Monitors::default();
        let def = defs("[[monitor]]\nid = \"noisy\"\ntype = \"event-count\"\nevent = \"enum-violation\"\nby = [\"sender\"]\nwindow = 60\ncondition = \">= 3\"\n").remove(0);
        ms.set(vec![def.clone()]);
        let ev = |at: f64, rule: &str, sender: &str| EventRec {
            at,
            rule_name: rule.into(),
            rule_id: rule.into(),
            tags: vec![(Dim::Sender, sender.into())],
        };
        for t in [1.0, 2.0, 3.0] {
            ms.record(ev(t, "enum-violation", "a"));
            ms.record(ev(t, "entity-timeout", "b"));
        }
        let m = Metrics::default();
        let c = ms.evaluate(10.0, &m);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].1, vec![(Dim::Sender, "a".to_string())]);
        // A minute later the firings have left the window: it resolves.
        assert_eq!(ms.evaluate(70.0, &m)[0].2, Change::Resolve);
        // Preview from scratch: it would have fired once, for sender a.
        let (n, groups) = Monitors {
            events: ms.events.clone(),
            ..Default::default()
        }
        .preview(&def, &m, (0.0, 80.0, 5.0));
        assert_eq!((n, groups.len()), (1, 1));
    }

    #[test]
    fn composite_expressions_parse_print_and_validate() {
        for (src, back) in [
            ("a && (b || !c)", "a && (b || !c)"),
            ("!(a || b) && c", "!(a || b) && c"),
            ("a || b && c", "a || b && c"),
            ("(a && b) || c", "a && b || c"),
        ] {
            let e = Expr::parse(src).unwrap();
            assert_eq!(e.to_string(), back, "{src}");
            assert_eq!(Expr::parse(back).unwrap(), e, "{back} reads back the same");
        }
        assert_eq!(Expr::parse("a && !b").unwrap().refs(), ["a", "b"]);
        for bad in ["a &&", "a & b", "(a || b", "a b", "&& a", ""] {
            assert!(Expr::parse(bad).is_err(), "{bad}");
        }
        let base = "[[monitor]]\nid = \"q\"\ntype = \"absence\"\nmetric = \"pdu.count\"\nby = [\"sender\"]\n";
        let err = |extra: &str| MonitorDef::parse_all(&format!("{base}{extra}")).unwrap_err();
        assert!(err("[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"q && gone\"\n").contains("isn't a monitor"));
        assert!(
            err("[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"q\"\nby = [\"site\"]\n").contains("doesn't")
        );
        assert!(
            err("[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"q\"\nmetric = \"pdu.count\"\n")
                .contains("not metric")
        );
        assert!(err("[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"c || q\"\n").contains("itself"));
        assert!(err("[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"q\"\n[[monitor]]\nid = \"d\"\ntype = \"composite\"\nof = \"c\"\n").contains("another composite"));
        // A valid one prints back the same.
        let d = defs(&format!(
            "{base}[[monitor]]\nid = \"c\"\ntype = \"composite\"\nof = \"!q\"\nby = [\"sender\"]\nfor = 5\n"
        ));
        let back: String = d.iter().map(|m| m.to_toml()).collect();
        assert_eq!(defs(&back), d, "{back}");
        assert_eq!(d[1].describe(), "!q by sender");
    }

    #[test]
    fn composites_fire_per_group_on_the_monitors_they_name() {
        let mut ms = Monitors::default();
        // Sender 3001 stops at 100 s: it goes quiet and stops being busy;
        // 3000 stays busy throughout.
        ms.set(defs(
            r#"
[[monitor]]
id = "quiet"
type = "absence"
metric = "pdu.count"
by = ["sender"]
for = 15

[[monitor]]
id = "busy"
type = "threshold"
metric = "pdu.count"
by = ["sender"]
window = 10
condition = "> 1"

[[monitor]]
id = "gone"
type = "composite"
of = "quiet && !busy"
by = ["sender"]

[[monitor]]
id = "working"
type = "composite"
of = "busy && !quiet"
by = ["sender"]

[[monitor]]
id = "anyone-quiet"
type = "composite"
of = "quiet"
"#,
        ));
        let m = traffic(100, 200);
        let mut fired: Vec<(String, TagPairs)> = Vec::new();
        for t in (60..200).step_by(5) {
            for (i, g, c) in ms.evaluate(t as f64, &m) {
                if let Change::Fire { .. } = c {
                    fired.push((ms.defs[i].id.clone(), g));
                }
            }
        }
        let of = |id: &str| -> Vec<&TagPairs> { fired.iter().filter(|(i, _)| i == id).map(|(_, g)| g).collect() };
        let s = |p: u16| vec![(Dim::Sender, src(p).to_string())];
        assert_eq!(of("gone"), [&s(3001)]);
        assert_eq!(of("working"), [&s(3000), &s(3001)], "both work before 3001 stops");
        assert_eq!(of("anyone-quiet"), [&Vec::new()], "no by: one group");
        // 3001's "working" resolved when it went quiet; 3000's is still open.
        let open: Vec<_> = ms
            .firing()
            .filter(|(id, _, _)| *id == "working")
            .map(|(_, g, _)| g.clone())
            .collect();
        assert_eq!(open, [s(3000)]);
        // Preview replays the monitors a composite names.
        let gone = ms.defs[2].clone();
        let (n, groups) = Monitors {
            defs: ms.defs.clone(),
            ..Default::default()
        }
        .preview(&gone, &m, (60.0, 199.0, 5.0));
        assert_eq!((n, groups.into_iter().collect::<Vec<_>>()), (1, vec![s(3001)]));
    }
}
