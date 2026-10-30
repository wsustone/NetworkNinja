//! The conformance summary behind `/api/events/summary` (ADR 0008 slice 2):
//! violations — alert firings and decode errors — grouped by up to two of
//! sender, rule, site, entity, pack, severity and exercise, with counts per
//! severity, first and last seen, and the alerts still open.
//!
//! The party a violation is pinned on is its sender, so `by=sender,rule` is
//! the "who is non-compliant, with what, how often, when last" table.
//! Decode errors count under rule `decode-error`.

use crate::store::Violation;
use std::collections::{BTreeMap, BTreeSet};

/// Most `by` dimensions (one pivot).
pub const MAX_BY: usize = 2;
/// Entities listed per group; the full count rides alongside.
const ENTITIES_LISTED: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SDim {
    Sender,
    Rule,
    Site,
    Entity,
    Pack,
    Severity,
    Exercise,
}

impl SDim {
    const ALL: [SDim; 7] = [
        SDim::Sender,
        SDim::Rule,
        SDim::Site,
        SDim::Entity,
        SDim::Pack,
        SDim::Severity,
        SDim::Exercise,
    ];

    pub fn name(self) -> &'static str {
        match self {
            SDim::Sender => "sender",
            SDim::Rule => "rule",
            SDim::Site => "site",
            SDim::Entity => "entity",
            SDim::Pack => "pack",
            SDim::Severity => "severity",
            SDim::Exercise => "exercise",
        }
    }

    /// This violation's value on the dimension; `-` when it has none.
    fn of(self, v: &Violation) -> String {
        let error = v.kind == "error";
        let dash = || "-".to_string();
        match self {
            SDim::Sender => v.sender.clone().unwrap_or_else(|| "unknown".into()),
            SDim::Rule if error => "decode-error".into(),
            SDim::Rule => v.rule.clone().unwrap_or_else(dash),
            SDim::Pack if error => "decoder".into(),
            SDim::Pack => v.pack.clone().unwrap_or_else(dash),
            SDim::Site => v
                .entity
                .as_deref()
                .and_then(|e| e.split(':').next())
                .map(str::to_string)
                .unwrap_or_else(dash),
            SDim::Entity => v.entity.clone().unwrap_or_else(dash),
            SDim::Severity if error => "error".into(),
            SDim::Severity => v.severity.clone().unwrap_or_else(dash),
            SDim::Exercise => v.exercise.map(|x| x.to_string()).unwrap_or_else(dash),
        }
    }
}

/// `by` as a comma list of 1–2 dimension names.
pub fn parse_by(s: &str) -> Result<Vec<SDim>, String> {
    let mut by = Vec::new();
    for name in s.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        let d = SDim::ALL.into_iter().find(|d| d.name() == name).ok_or_else(|| {
            format!(
                "unknown dimension '{name}' (expected {})",
                SDim::ALL.map(|d| d.name()).join(", ")
            )
        })?;
        if !by.contains(&d) {
            by.push(d);
        }
    }
    if by.is_empty() || by.len() > MAX_BY {
        return Err(format!("by takes 1 to {MAX_BY} dimensions"));
    }
    Ok(by)
}

/// What the live monitor knows about one sender: the `site:app` pairs it
/// has reported entities for, how many entities, and when last heard.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SenderInfo {
    pub claims: BTreeSet<String>,
    pub entities: usize,
    pub last_seen: f64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Group {
    pub key: Vec<(SDim, String)>,
    pub total: u64,
    pub critical: u64,
    pub warning: u64,
    pub errors: u64,
    pub first: f64,
    pub last: f64,
    /// Alerts in this group still firing now.
    pub open: u64,
    pub entities: BTreeSet<String>,
}

/// Group `rows` (violations) and `open` (alerts firing now, as violations)
/// by `by`. Groups come largest first; ties by key.
pub fn summarize(by: &[SDim], rows: &[Violation], open: &[Violation]) -> Vec<Group> {
    let key_of = |v: &Violation| -> Vec<(SDim, String)> { by.iter().map(|d| (*d, d.of(v))).collect() };
    let mut groups: BTreeMap<Vec<(SDim, String)>, Group> = BTreeMap::new();
    for v in rows {
        let g = groups.entry(key_of(v)).or_insert_with(|| Group {
            first: v.at,
            last: v.at,
            ..Default::default()
        });
        g.total += 1;
        match (v.kind.as_str(), v.severity.as_deref()) {
            ("error", _) => g.errors += 1,
            (_, Some("critical")) => g.critical += 1,
            _ => g.warning += 1,
        }
        g.first = g.first.min(v.at);
        g.last = g.last.max(v.at);
        if let Some(e) = &v.entity {
            g.entities.insert(e.clone());
        }
    }
    for v in open {
        let g = groups.entry(key_of(v)).or_insert_with(|| Group {
            first: v.at,
            last: v.at,
            ..Default::default()
        });
        g.open += 1;
        if let Some(e) = &v.entity {
            g.entities.insert(e.clone());
        }
    }
    let mut out: Vec<Group> = groups
        .into_iter()
        .map(|(key, mut g)| {
            g.key = key;
            g
        })
        .collect();
    out.sort_by(|a, b| (b.total + b.open).cmp(&(a.total + a.open)).then(a.key.cmp(&b.key)));
    out
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn num(x: f64) -> String {
    if x.is_finite() {
        format!("{:.3}", x)
    } else {
        "0".into()
    }
}

/// The endpoint's JSON. `senders` is included when grouping by sender, so
/// the dashboard can show compliant senders (no violations) too.
pub fn summary_json(
    by: &[SDim],
    since: f64,
    groups: &[Group],
    senders: Option<&BTreeMap<String, SenderInfo>>,
) -> String {
    let gs: Vec<String> = groups
        .iter()
        .map(|g| {
            let tags: Vec<String> = g
                .key
                .iter()
                .map(|(d, v)| format!("\"{}\":\"{}\"", d.name(), esc(v)))
                .collect();
            let ents: Vec<String> = g
                .entities
                .iter()
                .take(ENTITIES_LISTED)
                .map(|e| format!("\"{}\"", esc(e)))
                .collect();
            format!(
                "{{\"tags\":{{{}}},\"total\":{},\"critical\":{},\"warning\":{},\"errors\":{},\"open\":{},\"first\":{},\"last\":{},\"entities\":[{}],\"entity_count\":{}}}",
                tags.join(","),
                g.total,
                g.critical,
                g.warning,
                g.errors,
                g.open,
                num(g.first),
                num(g.last),
                ents.join(","),
                g.entities.len()
            )
        })
        .collect();
    let mut s = format!(
        "{{\"by\":[{}],\"since\":{},\"total\":{},\"groups\":[{}]",
        by.iter()
            .map(|d| format!("\"{}\"", d.name()))
            .collect::<Vec<_>>()
            .join(","),
        num(since),
        groups.iter().map(|g| g.total).sum::<u64>(),
        gs.join(",")
    );
    if let Some(senders) = senders {
        let ss: Vec<String> = senders
            .iter()
            .map(|(addr, i)| {
                format!(
                    "\"{}\":{{\"claims\":[{}],\"entities\":{},\"last_seen\":{}}}",
                    esc(addr),
                    i.claims
                        .iter()
                        .map(|c| format!("\"{}\"", esc(c)))
                        .collect::<Vec<_>>()
                        .join(","),
                    i.entities,
                    num(i.last_seen)
                )
            })
            .collect();
        s.push_str(&format!(",\"senders\":{{{}}}", ss.join(",")));
    }
    s.push('}');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(at: f64, sender: &str, rule: &str, entity: &str, sev: &str) -> Violation {
        Violation {
            at,
            kind: "alert".into(),
            rule: Some(rule.into()),
            pack: Some("dis-base".into()),
            entity: Some(entity.into()),
            sender: Some(sender.into()),
            severity: Some(sev.into()),
            exercise: Some(1),
        }
    }

    fn error(at: f64, sender: &str) -> Violation {
        Violation {
            at,
            kind: "error".into(),
            sender: Some(sender.into()),
            ..Default::default()
        }
    }

    #[test]
    fn groups_by_sender_and_rule_with_open_alerts() {
        let rows = vec![
            alert(10.0, "a:1", "position-jump", "1:1:3", "warning"),
            alert(20.0, "a:1", "position-jump", "1:1:4", "warning"),
            alert(15.0, "a:1", "id-conflict", "1:1:2", "critical"),
            alert(30.0, "b:2", "entity-state.force_id", "2:1:1", "warning"),
            error(40.0, "b:2"),
            error(41.0, "b:2"),
        ];
        let open = vec![alert(15.0, "a:1", "id-conflict", "1:1:2", "critical")];

        let g = summarize(&parse_by("sender").unwrap(), &rows, &open);
        assert_eq!(g.len(), 2);
        assert_eq!(g[0].key, vec![(SDim::Sender, "a:1".to_string())]);
        assert_eq!((g[0].total, g[0].critical, g[0].warning, g[0].open), (3, 1, 2, 1));
        assert_eq!((g[0].first, g[0].last), (10.0, 20.0));
        assert_eq!(g[0].entities.len(), 3);
        assert_eq!((g[1].total, g[1].errors), (3, 2));

        let g = summarize(&parse_by("sender,rule").unwrap(), &rows, &open);
        let cell = |s: &str, r: &str| {
            g.iter()
                .find(|x| x.key == vec![(SDim::Sender, s.to_string()), (SDim::Rule, r.to_string())])
                .map(|x| (x.total, x.open))
        };
        assert_eq!(cell("a:1", "position-jump"), Some((2, 0)));
        assert_eq!(cell("a:1", "id-conflict"), Some((1, 1)));
        assert_eq!(cell("b:2", "decode-error"), Some((2, 0)));

        // Site comes from the entity; decode errors have none.
        let g = summarize(&parse_by("site").unwrap(), &rows, &[]);
        let sites: Vec<_> = g.iter().map(|x| (x.key[0].1.as_str(), x.total)).collect();
        assert_eq!(sites, vec![("1", 3), ("-", 2), ("2", 1)]);
    }

    #[test]
    fn parse_by_validates() {
        assert!(parse_by("").unwrap_err().contains("1 to 2"));
        assert!(parse_by("sender,rule,site").unwrap_err().contains("1 to 2"));
        assert!(parse_by("colour").unwrap_err().contains("unknown dimension 'colour'"));
        assert_eq!(parse_by("rule,rule").unwrap(), vec![SDim::Rule]);
    }

    #[test]
    fn json_lists_compliant_senders() {
        let mut senders = BTreeMap::new();
        senders.insert(
            "c:3".to_string(),
            SenderInfo {
                claims: ["3:1".to_string()].into(),
                entities: 4,
                last_seen: 99.0,
            },
        );
        let by = parse_by("sender").unwrap();
        let j = summary_json(&by, 0.0, &[], Some(&senders));
        assert!(j.contains("\"groups\":[]"), "{j}");
        assert!(
            j.contains("\"senders\":{\"c:3\":{\"claims\":[\"3:1\"],\"entities\":4"),
            "{j}"
        );
    }
}
