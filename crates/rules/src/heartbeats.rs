//! Heartbeat timeouts for every PDU type that has one and no rule of its
//! own (ADR 0010; IEEE 1278.1 4.2.7, Table 4): an emitter, IFF system,
//! designator, aggregate, minefield, environmental process, live entity...
//! that stops reporting for longer than its heartbeat × the multiplier.
//!
//! An object is a PDU type plus the PDU's first identifier (the emitting
//! entity, the aggregate, the minefield...). It is only expected once seen,
//! so a monitor started mid-exercise judges nothing it hasn't heard. A final
//! report ends the expectation (`nn_decode::heartbeat::is_final`), and so
//! does its entity being removed or deactivated. Frozen time doesn't count.

use nn_decode::heartbeat::{self, Heartbeat};
use nn_decode::EntityId;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;

/// `[rules.heartbeat]`: per-type overrides of the defaults (by the table's
/// pack keys, seconds; 0 turns a type off) and the multiplier.
#[derive(Debug, Clone, PartialEq)]
pub struct HeartbeatConfig {
    pub seconds: BTreeMap<u8, f64>,
    pub timeout_multiplier: f64,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        HeartbeatConfig {
            seconds: BTreeMap::new(),
            timeout_multiplier: heartbeat::TIMEOUT_MULTIPLIER,
        }
    }
}

impl HeartbeatConfig {
    /// The heartbeat in force for a type: an override, else the default.
    pub fn seconds_for(&self, h: &Heartbeat) -> f64 {
        self.seconds.get(&h.pdu_type).copied().unwrap_or(h.seconds)
    }
}

type Key = (u8, u8, EntityId); // exercise, PDU type, object

#[derive(Debug, Clone)]
struct Object {
    last_seen: f64,
    source: SocketAddr,
    reported: bool,
}

/// A heartbeat finding, for the engine to raise.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub exercise: u8,
    pub id: EntityId,
    pub sender: SocketAddr,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Heartbeats {
    objects: HashMap<Key, Object>,
}

impl Heartbeats {
    /// One PDU's bytes (header included).
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], cfg: &HeartbeatConfig) {
        let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
            return;
        };
        let Some(h) = heartbeat::of(pdu_type).filter(|h| !h.own_rule) else {
            return;
        };
        if cfg.seconds_for(h) <= 0.0 {
            return;
        }
        let Some(id) = pdu
            .get(nn_decode::HEADER_LEN..)
            .and_then(|body| nn_decode::structure::first_id(pdu_type, body))
        else {
            return;
        };
        let key = (exercise, pdu_type, id);
        if heartbeat::is_final(pdu) {
            self.objects.remove(&key);
            return;
        }
        self.objects.insert(
            key,
            Object {
                last_seen: now,
                source,
                reported: false,
            },
        );
    }

    /// Objects past their timeout. `paused(exercise, id)`: frozen, so the
    /// clock restarts; `gone(exercise, id)`: its entity was removed or
    /// deactivated, so nothing more is owed.
    pub fn expire(
        &mut self,
        now: f64,
        cfg: &HeartbeatConfig,
        paused: impl Fn(u8, EntityId) -> bool,
        gone: impl Fn(u8, EntityId) -> bool,
    ) -> Vec<Finding> {
        let mut out = Vec::new();
        self.objects.retain(|&(exercise, pdu_type, id), o| {
            if gone(exercise, id) {
                return false;
            }
            if paused(exercise, id) {
                o.last_seen = now;
                return true;
            }
            let Some(h) = heartbeat::of(pdu_type) else { return false };
            let hb = cfg.seconds_for(h);
            if hb <= 0.0 {
                return false;
            }
            let timeout = hb * cfg.timeout_multiplier;
            let silent = now - o.last_seen;
            if silent > timeout && !o.reported {
                o.reported = true;
                let name = nn_decode::pdu_type_name(pdu_type);
                out.push(Finding {
                    kind: name,
                    exercise,
                    id,
                    sender: o.source,
                    message: format!(
                        "{id} stopped sending {name}: none for {silent:.1} s (heartbeat {} {hb} s × {}; IEEE 1278.1 {}, draft D16r18)",
                        h.symbol, cfg.timeout_multiplier, h.clause
                    ),
                });
            }
            // A long-silent object is gone, not late.
            silent < (10.0 * timeout).max(600.0)
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }

    /// A PDU of `pdu_type` (header plus zeros) from object 1:1:7.
    fn pdu(pdu_type: u8) -> Vec<u8> {
        let l = nn_decode::structure::layout(pdu_type).unwrap();
        let mut b = vec![0u8; l.fixed.max(40)];
        b[1] = 1;
        b[2] = pdu_type;
        b[12..18].copy_from_slice(&[0, 1, 0, 1, 0, 7]);
        b
    }

    #[test]
    fn a_silent_emitter_is_reported_once_after_its_timeout() {
        let cfg = HeartbeatConfig::default();
        let mut h = Heartbeats::default();
        h.observe(0.0, src(), &pdu(23), &cfg);
        let never = |_, _| false;
        assert!(h.expire(11.9, &cfg, never, never).is_empty());
        let f = h.expire(12.1, &cfg, never, never);
        assert_eq!(f.len(), 1);
        assert!(
            f[0].message
                .starts_with("1:1:7 stopped sending ElectromagneticEmission"),
            "{}",
            f[0].message
        );
        assert!(h.expire(20.0, &cfg, never, never).is_empty(), "once per silence");
        // It comes back and goes quiet again: reported again.
        h.observe(30.0, src(), &pdu(23), &cfg);
        assert_eq!(h.expire(43.0, &cfg, never, never).len(), 1);
    }

    #[test]
    fn final_reports_freezes_removals_and_overrides() {
        let mut cfg = HeartbeatConfig::default();
        let never = |_, _| false;
        // A Designator with Power 0 is off: nothing more is owed.
        let mut h = Heartbeats::default();
        h.observe(0.0, src(), &pdu(24), &cfg);
        assert!(h.expire(100.0, &cfg, never, never).is_empty(), "power 0 is final");
        // Frozen time doesn't count; a removed entity owes nothing.
        let mut h = Heartbeats::default();
        h.observe(0.0, src(), &pdu(28), &cfg);
        assert!(h.expire(100.0, &cfg, |_, _| true, never).is_empty());
        assert!(
            h.expire(110.0, &cfg, never, never).is_empty(),
            "the clock restarted at the resume"
        );
        assert!(h.expire(200.0, &cfg, never, |_, _| true).is_empty());
        // A site can lengthen a heartbeat, or turn a type off.
        cfg.seconds.insert(28, 60.0);
        let mut h = Heartbeats::default();
        h.observe(0.0, src(), &pdu(28), &cfg);
        assert!(h.expire(100.0, &cfg, never, never).is_empty());
        assert_eq!(h.expire(145.0, &cfg, never, never).len(), 1);
        cfg.seconds.insert(23, 0.0);
        let mut h = Heartbeats::default();
        h.observe(0.0, src(), &pdu(23), &cfg);
        assert!(h.expire(1000.0, &cfg, never, never).is_empty());
    }
}
