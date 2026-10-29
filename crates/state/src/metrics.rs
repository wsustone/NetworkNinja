//! Rolling traffic metrics in one-second buckets.

use nn_decode::{Pdu, PduBody};
use std::collections::{BTreeMap, VecDeque};

/// How many seconds of history to keep.
pub const HISTORY_SECS: usize = 600;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Bucket {
    pub second: i64,
    pub datagrams: u64,
    pub bytes: u64,
    pub pdus: u64,
    pub errors: u64,
    pub by_type: BTreeMap<&'static str, u64>,
    pub by_site: BTreeMap<u16, u64>,
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

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    buckets: VecDeque<Bucket>,
}

/// The site a PDU belongs to, for per-site rates.
fn site_of(p: &Pdu) -> Option<u16> {
    Some(match &p.body {
        PduBody::EntityState(e) => e.entity_id.site,
        PduBody::Fire(f) => f.firing_entity.site,
        PduBody::Detonation(d) => d.firing_entity.site,
        PduBody::StartResume(s) => s.originating.site,
        PduBody::StopFreeze(s) => s.originating.site,
        PduBody::RemoveEntity(r) => r.originating.site,
        PduBody::Other(_) => return None,
    })
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

    pub fn record_datagram(&mut self, now: f64, bytes: usize) {
        let b = self.bucket(now);
        b.datagrams += 1;
        b.bytes += bytes as u64;
    }

    pub fn record_pdu(&mut self, now: f64, pdu: &Pdu) {
        let site = site_of(pdu);
        let b = self.bucket(now);
        b.pdus += 1;
        *b.by_type.entry(pdu.type_name()).or_insert(0) += 1;
        if let Some(s) = site {
            *b.by_site.entry(s).or_insert(0) += 1;
        }
    }

    pub fn record_error(&mut self, now: f64) {
        self.bucket(now).errors += 1;
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

    #[test]
    fn windows_sum_the_right_buckets() {
        let mut m = Metrics::default();
        for i in 0..100 {
            let t = 1000.0 + i as f64 * 0.1; // 10 per second for 10 s
            m.record_datagram(t, 44);
            m.record_pdu(t, &pdu(1 + (i % 2) as u16));
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
}
