//! A simulation's fix report: every problem its entities and senders had,
//! with what happened, why it matters, how to fix it and the clause, as
//! Markdown to paste into an email or CSV for a spreadsheet. Built from the
//! event log entries (store rows or the in-memory log) at `/api/report`.

use crate::names::Names;
use nn_rules::explain;
use std::collections::{BTreeMap, BTreeSet};

/// One alert firing or decode error, read back from its log entry.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Event {
    pub at: f64,
    /// `alert` or `error`.
    pub kind: String,
    /// The check's id (an enum check's is its field).
    pub rule: String,
    pub rule_name: String,
    pub finding: String,
    pub severity: String,
    pub entity: String,
    pub sender: String,
    pub message: String,
    pub facts: Vec<(String, String)>,
    pub exercise: Option<u8>,
}

/// A JSON string value starting at `b[i]` (just after the opening quote):
/// the unescaped text and the index after the closing quote.
fn read_str(b: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = Vec::new();
    while i < b.len() {
        match b[i] {
            b'"' => return Some((String::from_utf8_lossy(&out).into_owned(), i + 1)),
            b'\\' => {
                let c = *b.get(i + 1)?;
                i += 2;
                match c {
                    b'n' => out.push(b'\n'),
                    b't' => out.push(b'\t'),
                    b'r' => out.push(b'\r'),
                    b'u' => {
                        let hex = std::str::from_utf8(b.get(i..i + 4)?).ok()?;
                        let ch = char::from_u32(u32::from_str_radix(hex, 16).ok()?).unwrap_or('\u{fffd}');
                        out.extend(ch.to_string().as_bytes());
                        i += 4;
                    }
                    c => out.push(c),
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    None
}

/// The index just after `"key":` (and any spaces) in a JSON object's text.
fn value_at(text: &str, key: &str) -> Option<usize> {
    let pat = format!("\"{key}\":");
    let i = text.find(&pat)? + pat.len();
    Some(i + text[i..].len() - text[i..].trim_start().len())
}

/// A string value of a JSON object's text, unescaped.
pub fn json_string(text: &str, key: &str) -> Option<String> {
    str_of(text, key)
}

fn str_of(text: &str, key: &str) -> Option<String> {
    let i = value_at(text, key)?;
    let b = text.as_bytes();
    (b.get(i) == Some(&b'"')).then(|| read_str(b, i + 1).map(|(s, _)| s))?
}

fn num_of(text: &str, key: &str) -> Option<f64> {
    let i = value_at(text, key)?;
    let rest = &text[i..];
    let end = rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == 'e' || c == '+'))
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// `"facts":[["name","value"],...]`.
fn facts_of(text: &str) -> Vec<(String, String)> {
    let Some(mut i) = value_at(text, "facts") else {
        return Vec::new();
    };
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut strs = Vec::new();
    let mut depth = 0;
    while i < b.len() {
        match b[i] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 1 && strs.len() == 2 {
                    let v = strs.pop().unwrap();
                    out.push((strs.pop().unwrap(), v));
                }
                strs.clear();
                if depth == 0 {
                    break;
                }
            }
            b'"' => {
                let Some((s, next)) = read_str(b, i + 1) else { break };
                strs.push(s);
                i = next;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out
}

impl Event {
    /// A log entry's event, if it is an alert firing or a decode error.
    pub fn from_json(entry: &str) -> Option<Event> {
        let kind = str_of(entry, "kind")?;
        let firing = kind == "error" || (kind == "alert" && str_of(entry, "state").as_deref() == Some("firing"));
        if !firing {
            return None;
        }
        let rule = str_of(entry, "rule").unwrap_or_else(|| "decode-error".into());
        Some(Event {
            at: num_of(entry, "at").unwrap_or(0.0),
            rule_name: str_of(entry, "rule_name").unwrap_or_else(|| rule.clone()),
            finding: str_of(entry, "finding").unwrap_or_default(),
            severity: str_of(entry, "severity").unwrap_or_else(|| "critical".into()),
            entity: str_of(entry, "entity").unwrap_or_default(),
            sender: str_of(entry, "sender")
                .or_else(|| str_of(entry, "source"))
                .unwrap_or_default(),
            message: str_of(entry, "message").unwrap_or_default(),
            facts: facts_of(entry),
            exercise: num_of(entry, "exercise").map(|x| x as u8),
            kind,
            rule,
        })
    }

    /// The simulation (site:app) the event is about, from its entity.
    fn simulation(&self) -> Option<String> {
        let mut p = self.entity.split(':');
        let (s, a, e) = (p.next()?, p.next()?, p.next()?);
        (p.next().is_none() && self.entity != "0:0:0" && !e.is_empty()).then(|| format!("{s}:{a}"))
    }
}

/// The clause a message cites ("IEEE 1278.1 5.7.3.3.2 e), draft D16r18"),
/// and the message without the citation.
pub fn split_cite(msg: &str) -> (String, Option<String>) {
    for (open, close) in [(" (IEEE 1278.1 ", "draft D16r18)"), ("; IEEE 1278.1 ", "draft D16r18")] {
        if let Some(i) = msg.find(open) {
            if let Some(j) = msg[i..].find(close) {
                let clause = msg[i + open.len()..i + j].trim_end_matches([' ', ',']).to_string();
                let rest = format!("{}{}", &msg[..i], &msg[i + j + close.len()..]);
                return (rest, Some(clause));
            }
        }
    }
    (msg.to_string(), None)
}

/// One problem: a check and finding, over the simulation's entities.
#[derive(Debug, Clone)]
pub struct Problem {
    pub rule: String,
    pub rule_name: String,
    pub finding: String,
    pub severity: String,
    pub firings: usize,
    pub entities: BTreeSet<String>,
    pub senders: BTreeSet<String>,
    pub first: f64,
    pub last: f64,
    /// The most recent firing.
    pub latest: Event,
}

impl Problem {
    pub fn explanation(&self) -> Option<&'static explain::Explanation> {
        explain::explain(&self.rule_name, &self.finding)
    }

    pub fn title(&self) -> String {
        match self.explanation() {
            Some(x) if x.kind == "*" && !self.finding.is_empty() && self.finding != "*" => {
                format!("{} ({})", x.title, self.finding)
            }
            Some(x) => x.title.to_string(),
            None if self.rule_name == "enum-violation" => "Bad enumeration value".into(),
            None => self.rule_name.clone(),
        }
    }

    pub fn check(&self) -> String {
        if self.rule_name == "enum-violation" || self.finding.is_empty() || self.finding == "*" {
            self.rule.clone()
        } else {
            format!("{} · {}", self.rule_name, self.finding)
        }
    }
}

/// A simulation's problems, worst first.
#[derive(Debug, Clone)]
pub struct Report {
    pub simulation: String,
    pub name: Option<String>,
    pub exercise: Option<u8>,
    pub since: f64,
    pub until: f64,
    pub senders: BTreeSet<String>,
    pub problems: Vec<Problem>,
}

/// Group `events` into the problems of `simulation` (site:app): alerts on
/// its entities, and decode errors from `senders`, the addresses that
/// report its entities.
pub fn build(
    events: &[Event],
    simulation: &str,
    senders: &BTreeSet<String>,
    names: &Names,
    (exercise, since, until): (Option<u8>, f64, f64),
) -> Report {
    let mut groups: BTreeMap<(String, String), Problem> = BTreeMap::new();
    let mut seen_senders = senders.clone();
    let sev = |s: &str| if s == "critical" { 2 } else { 1 };
    for e in events {
        if exercise.is_some_and(|x| e.kind == "alert" && e.exercise != Some(x)) {
            continue;
        }
        let mine = match e.kind.as_str() {
            "alert" => e.simulation().as_deref() == Some(simulation),
            _ => senders.contains(&e.sender),
        };
        if !mine {
            continue;
        }
        if !e.sender.is_empty() {
            seen_senders.insert(e.sender.clone());
        }
        let key = (e.rule.clone(), e.finding.clone());
        let p = groups.entry(key).or_insert_with(|| Problem {
            rule: e.rule.clone(),
            rule_name: e.rule_name.clone(),
            finding: e.finding.clone(),
            severity: e.severity.clone(),
            firings: 0,
            entities: BTreeSet::new(),
            senders: BTreeSet::new(),
            first: e.at,
            last: e.at,
            latest: e.clone(),
        });
        p.firings += 1;
        if sev(&e.severity) > sev(&p.severity) {
            p.severity = e.severity.clone();
        }
        if e.simulation().is_some() {
            p.entities.insert(e.entity.clone());
        }
        if !e.sender.is_empty() {
            p.senders.insert(e.sender.clone());
        }
        p.first = p.first.min(e.at);
        if e.at >= p.last {
            p.last = e.at;
            p.latest = e.clone();
        }
    }
    let mut problems: Vec<Problem> = groups.into_values().collect();
    problems.sort_by(|a, b| sev(&b.severity).cmp(&sev(&a.severity)).then(b.firings.cmp(&a.firings)));
    Report {
        simulation: simulation.to_string(),
        name: names.of_simulation(simulation).map(str::to_string),
        exercise,
        since,
        until,
        senders: seen_senders,
        problems,
    }
}

/// `2026-11-01 15:20:39 UTC`.
pub fn utc(t: f64) -> String {
    let secs = t.max(0.0) as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn list(items: &BTreeSet<String>, max: usize) -> String {
    let mut v: Vec<&str> = items.iter().map(String::as_str).take(max).collect();
    if items.len() > max {
        v.push("…");
    }
    v.join(", ")
}

impl Report {
    fn who(&self) -> String {
        match &self.name {
            Some(n) => format!("simulation {} ({n})", self.simulation),
            None => format!("simulation {}", self.simulation),
        }
    }

    fn sender_list(&self, names: &Names) -> String {
        let v: Vec<String> = self
            .senders
            .iter()
            .map(|s| match names.of_sender(s) {
                Some(n) => format!("{s} ({n})"),
                None => s.clone(),
            })
            .collect();
        if v.is_empty() {
            "none seen".into()
        } else {
            v.join(", ")
        }
    }

    /// The report as Markdown, for an email or a ticket.
    pub fn markdown(&self, names: &Names, version: &str) -> String {
        let mut s = format!("# NetworkNinja fix report: {}\n\n", self.who());
        let period = if self.since > 0.0 {
            format!("{} to {}", utc(self.since), utc(self.until))
        } else {
            format!("everything stored up to {}", utc(self.until))
        };
        s += &format!(
            "{}{period}. Senders: {}. Generated by nn-server {version}.\n\n",
            self.exercise.map_or(String::new(), |x| format!("Exercise {x}, ")),
            self.sender_list(names)
        );
        if self.problems.is_empty() {
            s += "No problems in this period.\n";
            return s;
        }
        let (crit, warn) = self.problems.iter().fold((0, 0), |(c, w), p| {
            if p.severity == "critical" {
                (c + 1, w)
            } else {
                (c, w + 1)
            }
        });
        let firings: usize = self.problems.iter().map(|p| p.firings).sum();
        let ents: BTreeSet<&String> = self.problems.iter().flat_map(|p| &p.entities).collect();
        s += &format!(
            "**{} problem{}** ({crit} critical, {warn} warning): {firings} alert firing{} on {} entit{}.\n\n",
            self.problems.len(),
            if self.problems.len() == 1 { "" } else { "s" },
            if firings == 1 { "" } else { "s" },
            ents.len(),
            if ents.len() == 1 { "y" } else { "ies" }
        );
        s += "| # | Problem | Severity | Firings | Entities | Last seen |\n|---|---|---|---|---|---|\n";
        for (i, p) in self.problems.iter().enumerate() {
            s += &format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                i + 1,
                p.title().replace('|', "\\|"),
                p.severity,
                p.firings,
                p.entities.len(),
                utc(p.last)
            );
        }
        for (i, p) in self.problems.iter().enumerate() {
            let (what, clause) = split_cite(&p.latest.message);
            s += &format!("\n## {}. {}\n\n", i + 1, p.title());
            s += &format!(
                "**Check:** `{}` · **Severity:** {} · **Firings:** {} · **First seen:** {} · **Last seen:** {}\n\n",
                p.check(),
                p.severity,
                p.firings,
                utc(p.first),
                utc(p.last)
            );
            if !p.entities.is_empty() {
                s += &format!("**Entities ({}):** {}\n\n", p.entities.len(), list(&p.entities, 40));
            }
            s += &format!("**What happened** (latest): {}\n\n", what.trim());
            if !p.latest.facts.is_empty() {
                s += "| | |\n|---|---|\n";
                for (k, v) in &p.latest.facts {
                    s += &format!("| {} | {} |\n", k.replace('|', "\\|"), v.replace('|', "\\|"));
                }
                s += "\n";
            }
            if let Some(x) = p.explanation() {
                s += &format!("**Why it matters:** {}\n\n", x.impact);
                s += &format!("**Likely causes:** {}\n\n", x.causes);
                s += &format!("**How to fix:** {}\n\n", x.fix);
            }
            if let Some(c) = clause {
                s += &format!("**Reference:** IEEE 1278.1 {c} (draft D16r18)\n");
            }
        }
        s
    }

    /// The report as CSV, one row per problem.
    pub fn csv(&self) -> String {
        let q = |v: &str| format!("\"{}\"", v.replace('"', "\"\""));
        let mut s = String::from(
            "simulation,name,problem,check,severity,firings,entities,first_seen,last_seen,latest_message,how_to_fix,reference\n",
        );
        for p in &self.problems {
            let (what, clause) = split_cite(&p.latest.message);
            let fix = p.explanation().map_or("", |x| x.fix);
            let row = [
                self.simulation.clone(),
                self.name.clone().unwrap_or_default(),
                p.title(),
                p.check(),
                p.severity.clone(),
                p.firings.to_string(),
                list(&p.entities, usize::MAX),
                utc(p.first),
                utc(p.last),
                what.trim().to_string(),
                fix.to_string(),
                clause.map(|c| format!("IEEE 1278.1 {c}")).unwrap_or_default(),
            ];
            s += &row.iter().map(|v| q(v)).collect::<Vec<_>>().join(",");
            s += "\n";
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::Target;

    const TIMEOUT: &str = r#"{"seq":5,"kind":"alert","at":1793520000.5,"state":"firing","severity":"warning","pack":"dis-base","rule":"entity-timeout","entity":"9:9:1","exercise":1,"sender":"10.0.5.10:3000","message":"9:9:1 (S9V01) sent no Entity State for 12.1 s","rule_name":"entity-timeout","finding":"silent","facts":[["silent for","12.1 s"],["marking","S9 \"V01\""]]}"#;

    #[test]
    fn log_entries_read_back_with_escapes_and_facts() {
        let e = Event::from_json(TIMEOUT).unwrap();
        assert_eq!(e.rule_name, "entity-timeout");
        assert_eq!(e.finding, "silent");
        assert_eq!(
            e.facts,
            vec![
                ("silent for".into(), "12.1 s".into()),
                ("marking".into(), "S9 \"V01\"".into())
            ]
        );
        assert_eq!(e.simulation().as_deref(), Some("9:9"));
        assert!(Event::from_json(&TIMEOUT.replace("firing", "resolved")).is_none());
        let err = Event::from_json(
            r#"{"seq":7,"kind":"error","at":2,"count":1,"source":"10.0.5.10:3000","message":"1 decode error"}"#,
        )
        .unwrap();
        assert_eq!(
            (err.rule.as_str(), err.sender.as_str()),
            ("decode-error", "10.0.5.10:3000")
        );
    }

    #[test]
    fn citations_split_off_both_forms() {
        let (m, c) = split_cite(
            "no DE Fire for 1.5 s (heartbeat x); receivers mark the shot off (IEEE 1278.1 5.4.5.3 b), draft D16r18)",
        );
        assert_eq!(
            (m.as_str(), c.as_deref()),
            (
                "no DE Fire for 1.5 s (heartbeat x); receivers mark the shot off",
                Some("5.4.5.3 b)")
            )
        );
        let (m, c) =
            split_cite("none for 24.1 s (heartbeat HBT_PDU_IFF 10 s × 2.4; IEEE 1278.1 5.7.6.3, draft D16r18)");
        assert_eq!(
            (m.as_str(), c.as_deref()),
            ("none for 24.1 s (heartbeat HBT_PDU_IFF 10 s × 2.4)", Some("5.7.6.3"))
        );
        assert_eq!(split_cite("plain").1, None);
    }

    #[test]
    fn a_simulations_problems_group_and_render() {
        let mut events = Vec::new();
        for (i, ent) in ["9:9:1", "9:9:2", "9:9:3"].iter().enumerate() {
            let mut e = Event::from_json(TIMEOUT).unwrap();
            e.entity = ent.to_string();
            e.at += i as f64;
            events.push(e);
        }
        // Another simulation's alert, and a decode error from 9:9's sender.
        let mut other = events[0].clone();
        other.entity = "8:1:1".into();
        events.push(other);
        events.push(Event {
            at: 1793520010.0,
            kind: "error".into(),
            rule: "decode-error".into(),
            rule_name: "decode-error".into(),
            finding: String::new(),
            severity: "critical".into(),
            sender: "10.0.5.10:3000".into(),
            message: "1 decode error from 10.0.5.10:3000".into(),
            ..Default::default()
        });
        let mut names = Names::default();
        names.set(Target::simulation("9:9").unwrap(), "JSAF cell B");
        names.set(Target::address("10.0.5.10").unwrap(), "VBS4 host");
        let senders: BTreeSet<String> = ["10.0.5.10:3000".to_string()].into();
        let r = build(&events, "9:9", &senders, &names, (Some(1), 1793519000.0, 1793520100.0));
        assert_eq!(r.problems.len(), 2);
        assert_eq!(r.problems[0].title(), "Unreadable PDU", "critical first");
        assert_eq!(r.problems[1].title(), "Entity stopped reporting");
        assert_eq!(r.problems[1].entities.len(), 3);
        let md = r.markdown(&names, "0.1.2");
        assert!(
            md.starts_with("# NetworkNinja fix report: simulation 9:9 (JSAF cell B)"),
            "{md}"
        );
        assert!(md.contains("10.0.5.10:3000 (VBS4 host)"), "{md}");
        assert!(md.contains("**Entities (3):** 9:9:1, 9:9:2, 9:9:3"), "{md}");
        assert!(md.contains("| marking | S9 \"V01\" |"), "{md}");
        assert!(md.contains("**How to fix:**"), "{md}");
        assert!(!md.contains("8:1:1"), "another simulation's alert: {md}");
        let csv = r.csv();
        assert_eq!(csv.lines().count(), 3, "{csv}");
        assert!(
            csv.contains("\"Entity stopped reporting\",\"entity-timeout · silent\",\"warning\",\"3\""),
            "{csv}"
        );
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0.0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_793_520_000.0), "2026-11-01 08:00:00 UTC");
        assert_eq!(utc(951_782_400.0), "2000-02-29 00:00:00 UTC");
    }
}
