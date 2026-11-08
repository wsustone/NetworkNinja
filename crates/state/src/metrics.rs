//! Rolling traffic metrics: one-second buckets of tagged counters and gauges
//! (ADR 0008), plus ten-second slots for the per-entity gauges.
//!
//! Every sample belongs to a series — a [`Metric`] and its [`Tags`] — and
//! each bucket keeps one [`Agg`] (count/sum/min/max) per series. The
//! untagged totals (`pdus`, `by_type`, …) stay alongside for the cheap
//! header rates. [`Metrics::cells`] hands matching series to the query
//! evaluator in [`crate::query`]; [`Metrics::rollup`] folds them into the
//! ten-second rows the server persists.

use nn_decode::{EntityId, EntityType, Pdu, PduBody};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

/// How many seconds of history to keep.
pub const HISTORY_SECS: usize = 600;
/// Width of a rollup row and of a per-entity gauge slot, seconds.
pub const SLOT_SECS: i64 = 10;
const HISTORY_SLOTS: usize = HISTORY_SECS / SLOT_SECS as usize;

/// The metric catalogue. Names are stable API (ADR 0008 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Metric {
    PduCount,
    PduDuplicates,
    BytesCount,
    DatagramCount,
    DecodeErrors,
    EntityActive,
    HeartbeatMean,
    HeartbeatJitter,
    DrError,
    AlertsOpen,
    ClockSkew,
    CaptureDrops,
}

impl Metric {
    pub const ALL: [Metric; 12] = [
        Metric::PduCount,
        Metric::PduDuplicates,
        Metric::BytesCount,
        Metric::DatagramCount,
        Metric::DecodeErrors,
        Metric::EntityActive,
        Metric::HeartbeatMean,
        Metric::HeartbeatJitter,
        Metric::DrError,
        Metric::AlertsOpen,
        Metric::ClockSkew,
        Metric::CaptureDrops,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Metric::PduCount => "pdu.count",
            Metric::PduDuplicates => "pdu.duplicates",
            Metric::BytesCount => "bytes.count",
            Metric::DatagramCount => "datagram.count",
            Metric::DecodeErrors => "decode.errors",
            Metric::EntityActive => "entity.active",
            Metric::HeartbeatMean => "entity.heartbeat_mean",
            Metric::HeartbeatJitter => "entity.heartbeat_jitter",
            Metric::DrError => "entity.dr_error",
            Metric::AlertsOpen => "alerts.open",
            Metric::ClockSkew => "sender.clock_skew",
            Metric::CaptureDrops => "capture.drops",
        }
    }

    pub fn from_name(s: &str) -> Option<Metric> {
        Metric::ALL.into_iter().find(|m| m.name() == s)
    }

    /// Gauges are sampled levels; everything else counts occurrences.
    pub fn is_gauge(self) -> bool {
        matches!(
            self,
            Metric::EntityActive
                | Metric::HeartbeatMean
                | Metric::HeartbeatJitter
                | Metric::DrError
                | Metric::AlertsOpen
                | Metric::ClockSkew
        )
    }

    /// One series per entity: kept in ten-second slots, not one-second buckets.
    pub fn per_entity(self) -> bool {
        matches!(self, Metric::HeartbeatMean | Metric::HeartbeatJitter | Metric::DrError)
    }

    pub fn unit(self) -> &'static str {
        match self {
            Metric::PduCount | Metric::PduDuplicates => "PDUs",
            Metric::BytesCount => "bytes",
            Metric::DatagramCount => "datagrams",
            Metric::DecodeErrors => "errors",
            Metric::EntityActive => "entities",
            Metric::HeartbeatMean | Metric::HeartbeatJitter => "s",
            Metric::DrError => "m",
            Metric::AlertsOpen => "alerts",
            Metric::ClockSkew => "s",
            Metric::CaptureDrops => "datagrams",
        }
    }

    /// The dimensions this metric is tagged with.
    pub fn dims(self) -> &'static [Dim] {
        use Dim::*;
        match self {
            Metric::PduCount => &[Exercise, PduType, Site, Kind, Domain, Sender],
            Metric::PduDuplicates => &[Exercise, PduType, Sender],
            Metric::BytesCount | Metric::DatagramCount | Metric::DecodeErrors => &[Sender],
            Metric::EntityActive => &[Exercise, Site, Kind, Force],
            Metric::HeartbeatMean | Metric::HeartbeatJitter => &[Exercise, Entity, Sender],
            Metric::DrError => &[Exercise, Entity],
            Metric::AlertsOpen => &[Exercise, Pack, Rule, Severity],
            Metric::ClockSkew => &[Exercise, Sender],
            // The kernel counts per socket, not per sender.
            Metric::CaptureDrops => &[],
        }
    }
}

/// A tag dimension shared by metrics, events and alerts (ADR 0008 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dim {
    Exercise,
    Site,
    App,
    Entity,
    Sender,
    PduType,
    Kind,
    Domain,
    Force,
    Pack,
    Rule,
    Severity,
}

impl Dim {
    pub const ALL: [Dim; 12] = [
        Dim::Exercise,
        Dim::Site,
        Dim::App,
        Dim::Entity,
        Dim::Sender,
        Dim::PduType,
        Dim::Kind,
        Dim::Domain,
        Dim::Force,
        Dim::Pack,
        Dim::Rule,
        Dim::Severity,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Dim::Exercise => "exercise",
            Dim::Site => "site",
            Dim::App => "app",
            Dim::Entity => "entity",
            Dim::Sender => "sender",
            Dim::PduType => "pdu_type",
            Dim::Kind => "kind",
            Dim::Domain => "domain",
            Dim::Force => "force",
            Dim::Pack => "pack",
            Dim::Rule => "rule",
            Dim::Severity => "severity",
        }
    }

    pub fn from_name(s: &str) -> Option<Dim> {
        Dim::ALL.into_iter().find(|d| d.name() == s)
    }
}

/// A series' tags; absent tags are `None`. Kept typed (not strings) so a
/// bucket's map keys stay cheap to hash and copy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Tags {
    pub exercise: Option<u8>,
    pub site: Option<u16>,
    pub app: Option<u16>,
    pub entity: Option<EntityId>,
    pub sender: Option<SocketAddr>,
    pub pdu_type: Option<&'static str>,
    pub kind: Option<u8>,
    pub domain: Option<u8>,
    pub force: Option<u8>,
    pub pack: Option<Arc<str>>,
    pub rule: Option<Arc<str>>,
    pub severity: Option<&'static str>,
}

/// Rendered tags, sorted by dimension: what queries filter and group on.
pub type TagPairs = Vec<(Dim, String)>;

impl Tags {
    pub fn get(&self, d: Dim) -> Option<String> {
        match d {
            Dim::Exercise => self.exercise.map(|v| v.to_string()),
            Dim::Site => self.site.map(|v| v.to_string()),
            Dim::App => self.app.map(|v| v.to_string()),
            Dim::Entity => self.entity.map(|v| v.to_string()),
            Dim::Sender => self.sender.map(|v| v.to_string()),
            Dim::PduType => self.pdu_type.map(str::to_string),
            Dim::Kind => self.kind.map(|v| v.to_string()),
            Dim::Domain => self.domain.map(|v| v.to_string()),
            Dim::Force => self.force.map(|v| v.to_string()),
            Dim::Pack => self.pack.as_deref().map(str::to_string),
            Dim::Rule => self.rule.as_deref().map(str::to_string),
            Dim::Severity => self.severity.map(str::to_string),
        }
    }

    pub fn pairs(&self) -> TagPairs {
        Dim::ALL
            .into_iter()
            .filter_map(|d| self.get(d).map(|v| (d, v)))
            .collect()
    }
}

/// `dim=value,dim=value` — the stored form of a series' tags. `%`, `,` and
/// `=` inside values are percent-escaped.
pub fn encode_tags(pairs: &[(Dim, String)]) -> String {
    let esc = |v: &str| v.replace('%', "%25").replace(',', "%2C").replace('=', "%3D");
    pairs
        .iter()
        .map(|(d, v)| format!("{}={}", d.name(), esc(v)))
        .collect::<Vec<_>>()
        .join(",")
}

pub fn decode_tags(s: &str) -> TagPairs {
    let unesc = |v: &str| v.replace("%2C", ",").replace("%3D", "=").replace("%25", "%");
    let mut out: TagPairs = s
        .split(',')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((Dim::from_name(k)?, unesc(v)))
        })
        .collect();
    out.sort();
    out
}

/// Count, sum, min and max of the samples in one series over one cell.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Agg {
    pub n: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
}

impl Agg {
    pub fn of(v: f64) -> Agg {
        Agg {
            n: 1,
            sum: v,
            min: v,
            max: v,
        }
    }
    pub fn add(&mut self, v: f64) {
        self.merge(&Agg::of(v));
    }
    pub fn merge(&mut self, o: &Agg) {
        self.n += o.n;
        self.sum += o.sum;
        self.min = self.min.min(o.min);
        self.max = self.max.max(o.max);
    }
    pub fn mean(&self) -> f64 {
        if self.n == 0 {
            0.0
        } else {
            self.sum / self.n as f64
        }
    }
}

type SeriesMap = HashMap<(Metric, Tags), Agg>;

fn add(map: &mut SeriesMap, metric: Metric, tags: Tags, v: f64) {
    map.entry((metric, tags))
        .and_modify(|a| a.add(v))
        .or_insert_with(|| Agg::of(v));
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    pub second: i64,
    pub datagrams: u64,
    pub bytes: u64,
    pub pdus: u64,
    pub errors: u64,
    pub by_type: BTreeMap<&'static str, u64>,
    pub by_site: BTreeMap<u16, u64>,
    /// Every tagged series sampled in this second.
    pub series: SeriesMap,
}

/// Per-entity gauges for one ten-second slot.
#[derive(Debug, Clone, Default, PartialEq)]
struct Slot {
    start: i64,
    series: SeriesMap,
}

/// Totals over a window, plus per-second rates.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WindowStats {
    pub seconds: f64,
    pub datagrams: u64,
    pub bytes: u64,
    pub pdus: u64,
    pub errors: u64,
    pub by_type: BTreeMap<&'static str, u64>,
    pub by_site: BTreeMap<u16, u64>,
}

impl WindowStats {
    pub fn pdu_rate(&self) -> f64 {
        self.pdus as f64 / self.seconds
    }
    pub fn byte_rate(&self) -> f64 {
        self.bytes as f64 / self.seconds
    }
}

/// One series' aggregate over one time cell: a second in memory, a slot on
/// disk or for per-entity gauges. The unit of input to the query evaluator.
#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub at: i64,
    pub tags: Arc<TagPairs>,
    pub agg: Agg,
}

/// One ten-second rollup row: what the server writes to SQLite.
#[derive(Debug, Clone, PartialEq)]
pub struct Rollup {
    pub metric: Metric,
    pub tags: TagPairs,
    pub at: i64,
    pub agg: Agg,
}

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    buckets: VecDeque<Bucket>,
    slots: VecDeque<Slot>,
}

/// The primary entity of a PDU (the reporting, firing or originating one),
/// for per-site rates and tags.
pub fn entity_of(p: &Pdu) -> Option<EntityId> {
    Some(match &p.body {
        PduBody::EntityState(e) => e.entity_id,
        PduBody::EntityStateUpdate(e) => e.entity_id,
        PduBody::Fire(f) => f.firing_entity,
        PduBody::Detonation(d) => d.firing_entity,
        PduBody::StartResume(s) => s.originating,
        PduBody::StopFreeze(s) => s.originating,
        PduBody::RemoveEntity(r) => r.originating,
        PduBody::Other(_) => return None,
    })
}

pub fn slot_of(second: i64) -> i64 {
    second.div_euclid(SLOT_SECS) * SLOT_SECS
}

impl Metrics {
    fn bucket(&mut self, now: f64) -> &mut Bucket {
        let second = now.floor() as i64;
        if self.buckets.back().is_none_or(|b| b.second < second) {
            self.buckets.push_back(Bucket {
                second,
                ..Default::default()
            });
            while self.buckets.len() > HISTORY_SECS {
                self.buckets.pop_front();
            }
        }
        // Out-of-order arrivals land in the newest bucket.
        self.buckets.back_mut().unwrap()
    }

    fn slot(&mut self, now: f64) -> &mut Slot {
        let start = slot_of(now.floor() as i64);
        if self.slots.back().is_none_or(|s| s.start < start) {
            self.slots.push_back(Slot {
                start,
                ..Default::default()
            });
            while self.slots.len() > HISTORY_SLOTS {
                self.slots.pop_front();
            }
        }
        self.slots.back_mut().unwrap()
    }

    pub fn record_datagram(&mut self, now: f64, sender: SocketAddr, bytes: usize) {
        let b = self.bucket(now);
        b.datagrams += 1;
        b.bytes += bytes as u64;
        let tags = Tags {
            sender: Some(sender),
            ..Default::default()
        };
        add(&mut b.series, Metric::DatagramCount, tags.clone(), 1.0);
        add(&mut b.series, Metric::BytesCount, tags, bytes as f64);
    }

    /// `etype`: the primary entity's type when known (Entity State carries
    /// it; other PDUs take it from the entity table), for `kind`/`domain`.
    pub fn record_pdu(&mut self, now: f64, sender: SocketAddr, pdu: &Pdu, etype: Option<EntityType>) {
        let site = entity_of(pdu).map(|e| e.site);
        let b = self.bucket(now);
        b.pdus += 1;
        *b.by_type.entry(pdu.type_name()).or_insert(0) += 1;
        if let Some(s) = site {
            *b.by_site.entry(s).or_insert(0) += 1;
        }
        let tags = Tags {
            exercise: Some(pdu.header.exercise_id),
            pdu_type: Some(pdu.type_name()),
            site,
            kind: etype.map(|t| t.kind),
            domain: etype.map(|t| t.domain),
            sender: Some(sender),
            ..Default::default()
        };
        add(&mut b.series, Metric::PduCount, tags, 1.0);
    }

    pub fn record_error(&mut self, now: f64, sender: SocketAddr) {
        let b = self.bucket(now);
        b.errors += 1;
        let tags = Tags {
            sender: Some(sender),
            ..Default::default()
        };
        add(&mut b.series, Metric::DecodeErrors, tags, 1.0);
    }

    /// Record a gauge sample (or, for a counter, an increment of `v`).
    pub fn record(&mut self, now: f64, metric: Metric, tags: Tags, v: f64) {
        let map = if metric.per_entity() {
            &mut self.slot(now).series
        } else {
            &mut self.bucket(now).series
        };
        add(map, metric, tags, v);
    }

    /// Totals over the last `secs` whole seconds ending at `now`.
    pub fn window(&self, now: f64, secs: u32) -> WindowStats {
        let end = now.floor() as i64;
        let start = end - secs as i64 + 1;
        let mut w = WindowStats {
            seconds: secs as f64,
            ..Default::default()
        };
        for b in self.buckets.iter().rev().take_while(|b| b.second >= start) {
            if b.second > end {
                continue;
            }
            w.datagrams += b.datagrams;
            w.bytes += b.bytes;
            w.pdus += b.pdus;
            w.errors += b.errors;
            for (k, v) in &b.by_type {
                *w.by_type.entry(k).or_insert(0) += v;
            }
            for (k, v) in &b.by_site {
                *w.by_site.entry(*k).or_insert(0) += v;
            }
        }
        w
    }

    /// The first second this metric's memory history covers, if any: a
    /// query reads memory from here on and the store before it.
    pub fn oldest(&self, metric: Metric) -> Option<i64> {
        if metric.per_entity() {
            self.slots.front().map(|s| s.start)
        } else {
            self.buckets.front().map(|b| b.second)
        }
    }

    /// Cells of `metric` with `from <= at < to` whose tags pass `keep`.
    /// Tags are rendered once per distinct series, not once per cell.
    pub fn cells(&self, metric: Metric, from: i64, to: i64, keep: impl Fn(&TagPairs) -> bool) -> Vec<Cell> {
        let sources: Vec<(i64, &SeriesMap)> = if metric.per_entity() {
            self.slots.iter().map(|s| (s.start, &s.series)).collect()
        } else {
            self.buckets.iter().map(|b| (b.second, &b.series)).collect()
        };
        let mut seen: HashMap<&Tags, Option<Arc<TagPairs>>> = HashMap::new();
        let mut out = Vec::new();
        for (at, series) in sources.into_iter().filter(|(at, _)| *at >= from && *at < to) {
            for ((m, tags), agg) in series {
                if *m != metric {
                    continue;
                }
                let rendered = seen.entry(tags).or_insert_with(|| {
                    let p = tags.pairs();
                    keep(&p).then(|| Arc::new(p))
                });
                if let Some(t) = rendered {
                    out.push(Cell {
                        at,
                        tags: Arc::clone(t),
                        agg: *agg,
                    });
                }
            }
        }
        out
    }

    /// Every series folded into ten-second rows for slots starting in
    /// `[from, to)` (both multiples of [`SLOT_SECS`]).
    pub fn rollup(&self, from: i64, to: i64) -> Vec<Rollup> {
        let mut rows: BTreeMap<(i64, Metric, TagPairs), Agg> = BTreeMap::new();
        let mut fold = |at: i64, series: &SeriesMap| {
            for ((m, tags), agg) in series {
                rows.entry((at, *m, tags.pairs()))
                    .and_modify(|a| a.merge(agg))
                    .or_insert(*agg);
            }
        };
        for b in self.buckets.iter().filter(|b| b.second >= from && b.second < to) {
            fold(slot_of(b.second), &b.series);
        }
        for s in self.slots.iter().filter(|s| s.start >= from && s.start < to) {
            fold(s.start, &s.series);
        }
        rows.into_iter()
            .map(|((at, metric, tags), agg)| Rollup { metric, tags, at, agg })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_decode::*;

    fn pdu(site: u16) -> Pdu {
        Pdu {
            header: PduHeader::new(7, 1, 13, DisTimestamp(0)),
            body: PduBody::StartResume(StartResume {
                originating: EntityId::new(site, 1, 0xffff),
                receiving: EntityId::new(0xffff, 0xffff, 0xffff),
                real_world_time: ClockTime::default(),
                simulation_time: ClockTime::default(),
                request_id: 1,
            }),
        }
    }

    fn sender(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    #[test]
    fn windows_sum_the_right_buckets() {
        let mut m = Metrics::default();
        for i in 0..100 {
            let t = 1000.0 + i as f64 * 0.1; // 10 per second for 10 s
            m.record_datagram(t, sender(5000), 44);
            m.record_pdu(t, sender(5000), &pdu(1 + (i % 2) as u16), None);
        }
        let w1 = m.window(1009.95, 1);
        assert_eq!(w1.pdus, 10);
        let w10 = m.window(1009.95, 10);
        assert_eq!(w10.pdus, 100);
        assert_eq!(w10.bytes, 4400);
        assert!((w10.pdu_rate() - 10.0).abs() < 1e-9);
        assert_eq!(w10.by_site[&1], 50);
        assert_eq!(w10.by_type["StartResume"], 100);
        // A window entirely after the data is empty.
        assert_eq!(m.window(1100.0, 10).pdus, 0);
    }

    #[test]
    fn series_are_tagged_and_roll_up_into_slots() {
        let mut m = Metrics::default();
        for i in 0..40 {
            let t = 1000.0 + i as f64 * 0.5; // 2 per second for 20 s
            let port = 5000 + (i % 2) as u16;
            m.record_datagram(t, sender(port), 100);
            m.record_pdu(t, sender(port), &pdu(1 + (i % 2) as u16), None);
        }
        let cells = m.cells(Metric::PduCount, 1000, 1020, |t| {
            t.contains(&(Dim::Sender, "10.0.0.1:5001".into()))
        });
        assert_eq!(cells.iter().map(|c| c.agg.n).sum::<u64>(), 20);
        assert!(cells
            .iter()
            .all(|c| c.tags.contains(&(Dim::Site, "2".into())) && c.tags.contains(&(Dim::Exercise, "1".into()))));

        let rows = m.rollup(1000, 1020);
        let bytes: Vec<_> = rows.iter().filter(|r| r.metric == Metric::BytesCount).collect();
        // Two senders × two slots, 10 datagrams of 100 bytes each.
        assert_eq!(bytes.len(), 4);
        assert!(bytes.iter().all(|r| r.agg.n == 10 && r.agg.sum == 1000.0), "{bytes:?}");

        // Per-entity gauges land in ten-second slots.
        let tags = Tags {
            entity: Some(EntityId::new(1, 1, 1)),
            ..Default::default()
        };
        m.record(1003.0, Metric::DrError, tags.clone(), 2.0);
        m.record(1007.0, Metric::DrError, tags, 4.0);
        assert_eq!(m.oldest(Metric::DrError), Some(1000));
        let c = m.cells(Metric::DrError, 0, 2000, |_| true);
        assert_eq!(c.len(), 1);
        assert_eq!((c[0].at, c[0].agg.n, c[0].agg.mean()), (1000, 2, 3.0));
    }

    #[test]
    fn tags_encode_round_trip() {
        let pairs = vec![
            (Dim::Sender, "10.0.0.1:5000".to_string()),
            (Dim::Rule, "a,b=c%".to_string()),
        ];
        let s = encode_tags(&pairs);
        assert_eq!(s, "sender=10.0.0.1:5000,rule=a%2Cb%3Dc%25");
        let mut sorted = pairs.clone();
        sorted.sort();
        assert_eq!(decode_tags(&s), sorted);
        assert!(decode_tags("").is_empty());
    }
}
