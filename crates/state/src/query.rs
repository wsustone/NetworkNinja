//! The one query object behind `/api/query` (ADR 0008 §2): a metric, tag
//! filters, group-by dimensions, an aggregation and a window. Charts,
//! monitors and summary views all evaluate this same shape over
//! [`Cell`]s, whether they came from memory or from SQLite rollups.
//!
//! Gauges are folded in two steps so `sum` means what a chart expects:
//! per time cell, the series in a group add up (mean of each series within
//! the cell); across a point's cells, those sums are averaged. `entity.active`
//! summed by site over a minute is then "entities on that site", not
//! "entity-seconds".

use crate::metrics::{Agg, Cell, Dim, Metric, TagPairs};
use std::collections::BTreeMap;

/// Most points one series may have.
pub const MAX_POINTS: i64 = 2_000;
/// Longest span one query may cover, seconds.
pub const MAX_SPAN: i64 = 31 * 86_400;
/// Most group-by dimensions.
pub const MAX_BY: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fold {
    Sum,
    Avg,
    Min,
    Max,
    Count,
    Rate,
}

impl Fold {
    pub fn name(self) -> &'static str {
        match self {
            Fold::Sum => "sum",
            Fold::Avg => "avg",
            Fold::Min => "min",
            Fold::Max => "max",
            Fold::Count => "count",
            Fold::Rate => "rate",
        }
    }

    fn from_name(s: &str) -> Option<Fold> {
        [Fold::Sum, Fold::Avg, Fold::Min, Fold::Max, Fold::Count, Fold::Rate]
            .into_iter()
            .find(|f| f.name() == s)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub metric: Metric,
    /// `where`: every pair must match (values compare case-insensitively).
    pub filter: Vec<(Dim, String)>,
    pub by: Vec<Dim>,
    pub agg: Fold,
    /// Seconds per point; a window spanning `from..to` makes a toplist.
    pub window: i64,
    pub from: i64,
    pub to: i64,
}

/// One group's points as `(start second, value)`.
#[derive(Debug, Clone, PartialEq)]
pub struct Series {
    pub tags: TagPairs,
    pub points: Vec<(i64, f64)>,
}

fn dim_list(m: Metric) -> String {
    m.dims().iter().map(|d| d.name()).collect::<Vec<_>>().join(", ")
}

impl Query {
    /// Build and validate a query from `name=value` pairs (a query string):
    /// `signal`, `name`, `where.DIM`, `by` (comma-separated), `agg`,
    /// `window`, `from`, `to` (epoch seconds). `to` defaults to `now`, `from`
    /// to ten minutes before it, `window` to 10 s, `agg` to `rate` for
    /// counters and `avg` for gauges. Errors read like pack errors: they say
    /// what was wrong and what would be accepted.
    pub fn parse(pairs: &[(String, String)], now: f64) -> Result<Query, String> {
        let get = |k: &str| pairs.iter().rev().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        match get("signal").unwrap_or("metric") {
            "metric" => {}
            "event" => return Err("signal=event is not supported yet (ADR 0008 slice 2); use /api/log".into()),
            other => return Err(format!("unknown signal '{other}' (expected metric)")),
        }
        let name = get("name").ok_or("missing name (a metric, e.g. name=pdu.count)")?;
        let metric = Metric::from_name(name).ok_or_else(|| {
            format!(
                "unknown metric '{name}' (expected one of {})",
                Metric::ALL.iter().map(|m| m.name()).collect::<Vec<_>>().join(", ")
            )
        })?;
        let dim = |s: &str| -> Result<Dim, String> {
            let d = Dim::from_name(s).ok_or_else(|| format!("unknown dimension '{s}'"))?;
            if !metric.dims().contains(&d) {
                return Err(format!(
                    "{} has no dimension '{s}' (it has {})",
                    metric.name(),
                    dim_list(metric)
                ));
            }
            Ok(d)
        };
        let mut filter = Vec::new();
        for (k, v) in pairs {
            match k.as_str() {
                "signal" | "name" | "by" | "agg" | "window" | "from" | "to" | "token" => {}
                k => match k.strip_prefix("where.") {
                    Some(d) => filter.push((dim(d)?, v.clone())),
                    None => return Err(format!("unknown parameter '{k}'")),
                },
            }
        }
        let mut by = Vec::new();
        for s in get("by")
            .unwrap_or("")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let d = dim(s)?;
            if !by.contains(&d) {
                by.push(d);
            }
        }
        if by.len() > MAX_BY {
            return Err(format!("by takes at most {MAX_BY} dimensions"));
        }
        let agg = match get("agg") {
            None if metric.is_gauge() => Fold::Avg,
            None => Fold::Rate,
            Some(s) => Fold::from_name(s)
                .ok_or_else(|| format!("unknown agg '{s}' (expected sum, avg, min, max, count or rate)"))?,
        };
        if agg == Fold::Rate && metric.is_gauge() {
            return Err(format!(
                "rate applies to counters; {} is a gauge (use avg, sum, min or max)",
                metric.name()
            ));
        }
        let num = |k: &str| -> Result<Option<f64>, String> {
            get(k)
                .map(|v| {
                    v.parse::<f64>()
                        .ok()
                        .filter(|x| x.is_finite())
                        .ok_or_else(|| format!("{k} must be a number, got '{v}'"))
                })
                .transpose()
        };
        let to = num("to")?.unwrap_or(now).ceil() as i64;
        let from = num("from")?.map(|x| x.floor() as i64).unwrap_or(to - 600);
        if from >= to {
            return Err("from must be before to".into());
        }
        if to - from > MAX_SPAN {
            return Err(format!("span too long: {} s (max {MAX_SPAN} s)", to - from));
        }
        let window = match num("window")? {
            None => 10,
            Some(w) if w < 1.0 => return Err("window must be at least 1 s".into()),
            Some(w) => (w as i64).min(to - from),
        };
        let points = (to - from + window - 1) / window;
        if points > MAX_POINTS {
            return Err(format!(
                "window too small: {points} points (max {MAX_POINTS}); widen window or narrow from/to"
            ));
        }
        Ok(Query {
            metric,
            filter,
            by,
            agg,
            window,
            from,
            to,
        })
    }

    pub fn matches(&self, tags: &TagPairs) -> bool {
        self.filter
            .iter()
            .all(|(d, v)| tags.iter().any(|(td, tv)| td == d && tv.eq_ignore_ascii_case(v)))
    }

    /// One value per group over the whole span instead of a timeseries.
    pub fn is_toplist(&self) -> bool {
        self.window >= self.to - self.from
    }

    fn points(&self) -> i64 {
        (self.to - self.from + self.window - 1) / self.window
    }

    /// Seconds point `k` covers (the last one may be cut short by `to`).
    fn width(&self, k: i64) -> f64 {
        let t = self.from + k * self.window;
        ((t + self.window).min(self.to) - t) as f64
    }
}

/// Fold `cells` (already filtered by name and `where`) into one series per
/// group. Counters fill points with no data with 0, so a sender going
/// quiet reads as a drop, not a gap; gauges leave gaps.
pub fn evaluate(q: &Query, cells: impl IntoIterator<Item = Cell>) -> Vec<Series> {
    // (group, point, cell time) → (Σ series means, merged agg)
    let mut per_cell: BTreeMap<(TagPairs, i64, i64), (f64, Agg)> = BTreeMap::new();
    for c in cells {
        if c.at < q.from || c.at >= q.to || c.agg.n == 0 {
            continue;
        }
        let k = (c.at - q.from) / q.window;
        let group: TagPairs = c.tags.iter().filter(|(d, _)| q.by.contains(d)).cloned().collect();
        per_cell
            .entry((group, k, c.at))
            .and_modify(|(m, a)| {
                *m += c.agg.mean();
                a.merge(&c.agg);
            })
            .or_insert((c.agg.mean(), c.agg));
    }
    // group → point → (Σ cell sums, cells, merged agg)
    let mut groups: BTreeMap<TagPairs, BTreeMap<i64, (f64, u64, Agg)>> = BTreeMap::new();
    for ((g, k, _), (m, a)) in per_cell {
        groups
            .entry(g)
            .or_default()
            .entry(k)
            .and_modify(|(s, n, acc)| {
                *s += m;
                *n += 1;
                acc.merge(&a);
            })
            .or_insert((m, 1, a));
    }
    let gauge = q.metric.is_gauge();
    let value = |k: i64, (s, n, a): &(f64, u64, Agg)| -> f64 {
        match q.agg {
            Fold::Sum if gauge => s / *n as f64,
            Fold::Sum => a.sum,
            Fold::Rate => a.sum / q.width(k),
            Fold::Avg => a.mean(),
            Fold::Min => a.min,
            Fold::Max => a.max,
            Fold::Count => a.n as f64,
        }
    };
    groups
        .into_iter()
        .map(|(tags, pts)| {
            let points = if gauge {
                pts.iter().map(|(k, p)| (q.from + k * q.window, value(*k, p))).collect()
            } else {
                (0..q.points())
                    .map(|k| (q.from + k * q.window, pts.get(&k).map_or(0.0, |p| value(k, p))))
                    .collect()
            };
            Series { tags, points }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn pairs(s: &str) -> Vec<(String, String)> {
        s.split('&')
            .filter_map(|kv| kv.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn cell(at: i64, tags: &[(Dim, &str)], vals: &[f64]) -> Cell {
        let mut agg = Agg::of(vals[0]);
        for v in &vals[1..] {
            agg.add(*v);
        }
        Cell {
            at,
            tags: Arc::new(tags.iter().map(|(d, v)| (*d, v.to_string())).collect()),
            agg,
        }
    }

    #[test]
    fn parse_defaults_and_errors() {
        let q = Query::parse(&pairs("name=pdu.count&where.site=7&by=sender"), 1000.5).unwrap();
        assert_eq!((q.from, q.to, q.window, q.agg), (401, 1001, 10, Fold::Rate));
        assert_eq!(q.filter, vec![(Dim::Site, "7".to_string())]);
        assert_eq!(q.by, vec![Dim::Sender]);
        assert_eq!(Query::parse(&pairs("name=entity.active"), 0.0).unwrap().agg, Fold::Avg);

        let err = |s: &str| Query::parse(&pairs(s), 1000.0).unwrap_err();
        assert!(err("by=sender").contains("missing name"));
        assert!(err("name=cpu").contains("unknown metric 'cpu'"));
        assert!(err("name=pdu.count&by=force").contains("pdu.count has no dimension 'force'"));
        assert!(err("name=pdu.count&where.bogus=1").contains("unknown dimension"));
        assert!(err("name=entity.active&agg=rate").contains("is a gauge"));
        assert!(err("name=pdu.count&agg=median").contains("unknown agg"));
        assert!(err("name=pdu.count&from=900&to=800").contains("from must be before to"));
        assert!(err("name=pdu.count&from=0&to=100000&window=1").contains("window too small"));
        assert!(err("name=pdu.count&from=x").contains("from must be a number"));
        assert!(err("name=pdu.count&wat=1").contains("unknown parameter 'wat'"));
        assert!(err("signal=event&name=*").contains("not supported yet"));
    }

    #[test]
    fn counters_rate_by_group_with_zero_fill() {
        let q = Query::parse(&pairs("name=pdu.count&by=sender&window=10&from=0&to=30"), 0.0).unwrap();
        let a = [(Dim::Sender, "a"), (Dim::Site, "1")];
        let b = [(Dim::Sender, "b"), (Dim::Site, "2")];
        let cells = vec![
            cell(0, &a, &[1.0; 20]),
            cell(5, &a, &[1.0; 30]),
            cell(12, &b, &[1.0; 10]),
            cell(29, &a, &[1.0; 10]),
            cell(30, &a, &[1.0; 99]), // outside [from, to)
        ];
        let s = evaluate(&q, cells);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].tags, vec![(Dim::Sender, "a".to_string())]);
        assert_eq!(s[0].points, vec![(0, 5.0), (10, 0.0), (20, 1.0)]);
        assert_eq!(s[1].points, vec![(0, 0.0), (10, 1.0), (20, 0.0)]);

        // The same span as one toplist value per group.
        let q = Query::parse(&pairs("name=pdu.count&by=sender&agg=sum&window=30&from=0&to=30"), 0.0).unwrap();
        assert!(q.is_toplist());
        let s = evaluate(&q, vec![cell(0, &a, &[1.0; 20]), cell(12, &b, &[1.0; 10])]);
        assert_eq!(s[0].points, vec![(0, 20.0)]);
    }

    #[test]
    fn gauges_sum_across_series_then_average_across_cells() {
        // entity.active by site: two kinds on site 1, sampled each second.
        let q = Query::parse(&pairs("name=entity.active&by=site&agg=sum&window=10&from=0&to=20"), 0.0).unwrap();
        let k1 = [(Dim::Site, "1"), (Dim::Kind, "1")];
        let k2 = [(Dim::Site, "1"), (Dim::Kind, "2")];
        let mut cells = Vec::new();
        for t in 0..10 {
            cells.push(cell(t, &k1, &[4.0]));
            cells.push(cell(t, &k2, &[if t < 5 { 2.0 } else { 0.0 }]));
        }
        // A ten-second disk slot holding ten samples of 3: mean 3, not 30.
        cells.push(cell(10, &k1, &[3.0; 10]));
        let s = evaluate(&q, cells);
        assert_eq!(s[0].points, vec![(0, 5.0), (10, 3.0)]);

        let q = Query { agg: Fold::Max, ..q };
        let s = evaluate(&q, vec![cell(0, &k1, &[1.0, 9.0]), cell(3, &k2, &[4.0])]);
        // Gauges leave empty points as gaps.
        assert_eq!(s[0].points, vec![(0, 9.0)]);
    }
}
