//! Cross-cutting header checks (ADR 0010 deep-check plan item 10), on every
//! PDU's first 12 bytes.
//!
//! Rule `timestamp` (IEEE 1278.1 4.6.3, 4.6.5, 6.2.88), per object: the
//! sender, PDU type and the PDU's first identifier:
//! - `type-changed`: its PDUs switch between absolute and relative
//!   timestamps (4.6.3 b 2 ii, c 2 ii).
//! - `backwards`: its timestamp goes back by more than `backwards_tolerance`
//!   (the hour wrap allowed; a freeze or resume starts over) (4.6.3 c 2 i).
//! - `clock-ahead` / `clock-behind`: an absolute timestamp more than
//!   TIMESTAMP_AHEAD / TIMESTAMP_BEHIND from the time it was received
//!   (4.6.5 b). Keyed by simulation, so one skewed simulator is one alert.
//!
//! Rule `exercise-id`: `switched`, a sender that carried one exercise ID
//! for `exercise_window` seconds sends a PDU with another (a gateway or a
//! misconfigured application), once per sender and exercise.
//!
//! [`clock_skew`] is the same skew the monitor charts as `sender.clock_skew`.
//!
//! Rule `pdu-status` (6.2.67, Table 99), DIS v7:
//! - `undefined-bits`: bits set that the PDU type doesn't define, which
//!   are to be 0. (Table 99 stops at type 41; later types get LVC and
//!   CEI, and Entity State Update the TEI too, as 5.9.4 asks.)
//! - `bad-value`: DTI, RAI or IAI set to 3, which none defines.
//! - `ism-mismatch`: an IFF PDU's IFF Simulation Mode disagrees with its
//!   Change/Options Simulation Mode.

use crate::interactions::Finding;
use nn_decode::structure::{layout, IdField};
use nn_decode::EntityId;
use nn_state::EntityKey;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

/// The PDU Status bits a type defines (Table 99): TEI 0, LVC 1-2, CEI 3,
/// and FTI / DTI / RAI / IAI / ISM in 4-5.
pub fn defined_status_bits(pdu_type: u8) -> u8 {
    const TEI: u8 = 0b1;
    const LVC_CEI: u8 = 0b1110;
    match pdu_type {
        1 | 23 | 24 | 41 | 67 => TEI | LVC_CEI,
        2 => LVC_CEI | 0b1_0000,
        3 => LVC_CEI | 0b11_0000,
        25..=27 | 31 | 32 => TEI | LVC_CEI | 0b11_0000,
        28 => TEI | LVC_CEI | 0b1_0000,
        _ => LVC_CEI,
    }
}

fn status_name(bits: u8) -> String {
    let names = ["TEI", "LVC", "LVC", "CEI", "bit 4", "bit 5", "bit 6", "bit 7"];
    let v: Vec<&str> = (0..8).filter(|b| bits >> b & 1 == 1).map(|b| names[b]).collect();
    v.join(", ")
}

/// The rule's limits, in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub ahead: f64,
    pub behind: f64,
    pub backwards_tolerance: f64,
}

#[derive(Debug, Clone, Copy)]
struct Seen {
    absolute: bool,
    past_hour: f64,
    at: f64,
}

#[derive(Debug, Default)]
pub struct Header {
    objects: HashMap<(SocketAddr, u8, [u8; 6]), Seen>,
    /// Per sender, each exercise ID's (first, last) PDU time.
    exercises: HashMap<SocketAddr, HashMap<u8, (f64, f64)>>,
    reported_switch: HashSet<(SocketAddr, u8)>,
    last_prune: f64,
}

/// Seconds an absolute timestamp runs ahead (+) or behind (-) `now`; `None`
/// for a relative one or a short PDU.
pub fn clock_skew(now: f64, pdu: &[u8]) -> Option<f64> {
    let raw = u32::from_be_bytes(pdu.get(4..8)?.try_into().ok()?);
    (raw & 1 == 1).then(|| wrapped(now.rem_euclid(3600.0), (raw >> 1) as f64 * 3600.0 / (1u64 << 31) as f64))
}

impl Header {
    /// A sender switching exercise ID. `window`: how long it must have
    /// carried only the other one.
    pub fn exercise(&mut self, now: f64, source: SocketAddr, pdu: &[u8], window: f64) -> Option<Finding> {
        let exercise = *pdu.get(1)?;
        let seen = self.exercises.entry(source).or_default();
        let fresh = !seen.contains_key(&exercise);
        let e = seen.entry(exercise).or_insert((now, now));
        e.1 = now;
        if !fresh || seen.len() < 2 {
            return None;
        }
        // Every other exercise it carried: one, recent, and long enough.
        let others: Vec<(u8, (f64, f64))> = seen
            .iter()
            .filter(|(x, _)| **x != exercise)
            .map(|(x, t)| (*x, *t))
            .collect();
        let &[(old, (first, last))] = others.as_slice() else {
            return None;
        };
        if now - last > window || last - first < window || !self.reported_switch.insert((source, exercise)) {
            return None;
        }
        Some(Finding {
            kind: "switched",
            key: EntityKey {
                exercise,
                id: EntityId::new(0, 0, 0),
            },
            sender: source,
            message: format!(
                "{source} sent exercise {old} for {:.0} s, then a {} with exercise {exercise}: one application, one exercise, unless it's a gateway",
                last - first,
                nn_decode::pdu_type_name(pdu[2])
            ),
            facts: vec![
                ("sender", source.to_string()),
                ("exercise before", format!("{old} ({:.0} s)", last - first)),
                ("exercise now", exercise.to_string()),
            ],
        })
    }
}

/// Seconds `b` is after `a`, both seconds past the hour, wrapped to
/// -1800..1800.
fn wrapped(a: f64, b: f64) -> f64 {
    let mut d = b - a;
    while d > 1800.0 {
        d -= 3600.0;
    }
    while d < -1800.0 {
        d += 3600.0;
    }
    d
}

impl Header {
    /// One PDU's bytes, received at `now` (seconds since the epoch, steady).
    /// `restarted(exercise, since)`: a freeze or resume since then.
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        limits: &Limits,
        restarted: impl Fn(u8, f64) -> bool,
    ) -> (Vec<Finding>, Vec<Finding>) {
        let (mut stamps, mut status) = (Vec::new(), Vec::new());
        if pdu.len() < 12 {
            return (stamps, status);
        }
        let (version, exercise, pdu_type) = (pdu[0], pdu[1], pdu[2]);
        let raw = u32::from_be_bytes([pdu[4], pdu[5], pdu[6], pdu[7]]);
        let (absolute, past_hour) = (raw & 1 == 1, (raw >> 1) as f64 * 3600.0 / (1u64 << 31) as f64);
        // The object: the PDU's first identifier.
        let mut id = [0u8; 6];
        let mut object = EntityId::new(0, 0, 0);
        if let Some(l) = layout(pdu_type) {
            let u = |b: &[u8], i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
            match l.id {
                IdField::Entity(at) | IdField::Simulation(at) => {
                    if let Some(b) = pdu.get(at..at + 6) {
                        id.copy_from_slice(b);
                        object = EntityId::new(u(b, 0), u(b, 2), u(b, 4));
                    }
                }
                // Live entity IDs: one-byte site and application.
                IdField::Live(at) => {
                    if let Some(b) = pdu.get(at..at + 4) {
                        id[..4].copy_from_slice(b);
                        object = EntityId::new(b[0] as u16, b[1] as u16, u(b, 2));
                    }
                }
            }
        }
        let simulation = EntityKey {
            exercise,
            id: EntityId::new(object.site, object.application, 0xffff),
        };
        let name = nn_decode::pdu_type_name(pdu_type);
        let kind_of = |a: bool| if a { "absolute" } else { "relative" };
        let key = (source, pdu_type, id);
        if let Some(prev) = self.objects.get(&key).copied() {
            if prev.absolute != absolute {
                stamps.push(Finding {
                    kind: "type-changed",
                    key: simulation,
                    sender: source,
                    message: format!(
                        "{name} for {object}: the timestamp turned {} after {}; keep one kind for an object's life{}",
                        kind_of(absolute),
                        kind_of(prev.absolute),
                        cite("4.6.3 b) 2) ii), c) 2) ii)")
                    ),
                    facts: vec![
                        ("object", format!("{name} {object}")),
                        (
                            "timestamp",
                            format!("{} (was {})", kind_of(absolute), kind_of(prev.absolute)),
                        ),
                    ],
                });
            } else if !restarted(exercise, prev.at) {
                let d = wrapped(prev.past_hour, past_hour);
                if d < -limits.backwards_tolerance {
                    stamps.push(Finding {
                        kind: "backwards",
                        key: simulation,
                        sender: source,
                        message: format!(
                            "{name} for {object}: the timestamp went back {:.1} s; a sender's clock runs forward{}",
                            -d,
                            cite("4.6.3 c) 2) i)")
                        ),
                        facts: vec![
                            ("object", format!("{name} {object}")),
                            ("went back", format!("{:.1} s", -d)),
                            ("timestamp", kind_of(absolute).into()),
                        ],
                    });
                }
            }
        }
        self.objects.insert(
            key,
            Seen {
                absolute,
                past_hour,
                at: now,
            },
        );
        if absolute {
            let skew = wrapped(now.rem_euclid(3600.0), past_hour);
            let (kind, limit, what) = if skew > 0.0 {
                ("clock-ahead", limits.ahead, "ahead of")
            } else {
                ("clock-behind", limits.behind, "behind")
            };
            if skew.abs() > limit {
                stamps.push(Finding {
                    kind,
                    key: simulation,
                    sender: source,
                    message: format!(
                        "{}:{}'s absolute timestamps run {:.1} s {what} the time they arrive (allowed {limit:.0} s): its clock isn't synchronized{}",
                        object.site,
                        object.application,
                        skew.abs(),
                        cite("4.6.3 b) 1), 4.6.5 b)")
                    ),
                    facts: vec![
                        ("simulation", format!("{}:{}", object.site, object.application)),
                        ("skew", format!("{skew:+.1} s")),
                        ("allowed", format!("{limit:.0} s")),
                    ],
                });
            }
        }
        if version >= 7 {
            let bits = pdu[10];
            let mut push = |kind: &'static str, message: String, facts: crate::engine::Facts| {
                status.push(Finding {
                    kind,
                    key: EntityKey { exercise, id: object },
                    sender: source,
                    message: format!("{name} from {object}: {message}{}", cite("6.2.67, Table 99")),
                    facts,
                });
            };
            let extra = bits & !defined_status_bits(pdu_type);
            if extra != 0 {
                push(
                    "undefined-bits",
                    format!(
                        "PDU Status sets {} ({bits:#010b}), which this PDU type doesn't define; they must be 0",
                        status_name(extra)
                    ),
                    vec![
                        ("PDU Status", format!("{bits:#010b}")),
                        ("undefined bits set", format!("{extra:#010b}")),
                    ],
                );
            }
            let two = (bits >> 4) & 0b11;
            let field = match pdu_type {
                3 => Some("Detonation Type Indicator"),
                25..=27 => Some("Radio Attached Indicator"),
                31 | 32 => Some("Intercom Attached Indicator"),
                _ => None,
            };
            if let (Some(field), 3) = (field, two) {
                push(
                    "bad-value",
                    format!("{field} is 3, which isn't defined (0-2)"),
                    vec![(field, "3".into())],
                );
            }
            if pdu_type == 28 {
                if let Some(&options) = pdu.get(41) {
                    let (ism, mode) = ((bits >> 4) & 1, (options >> 5) & 1);
                    if ism != mode {
                        push(
                            "ism-mismatch",
                            format!(
                                "IFF Simulation Mode is {ism} but Change/Options Simulation Mode is {mode}; they match"
                            ),
                            vec![
                                ("IFF Simulation Mode (PDU Status)", ism.to_string()),
                                ("Simulation Mode (Change/Options)", mode.to_string()),
                            ],
                        );
                    }
                }
            }
        }
        if now - self.last_prune > 60.0 {
            self.last_prune = now;
            self.objects.retain(|_, s| now - s.at < 600.0);
            for seen in self.exercises.values_mut() {
                seen.retain(|_, t| now - t.1 < 600.0);
            }
            self.exercises.retain(|_, seen| !seen.is_empty());
        }
        (stamps, status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const L: Limits = Limits {
        ahead: 5.0,
        behind: 5.0,
        backwards_tolerance: 0.5,
    };

    /// An Entity State header for 1:1:1 stamped `past_hour` seconds.
    fn pdu(pdu_type: u8, past_hour: f64, absolute: bool, status: u8) -> Vec<u8> {
        let mut b = vec![0u8; 60];
        b[0] = 7;
        b[1] = 1;
        b[2] = pdu_type;
        let ticks = (past_hour / 3600.0 * (1u64 << 31) as f64) as u32;
        b[4..8].copy_from_slice(&(ticks << 1 | absolute as u32).to_be_bytes());
        b[10] = status;
        b[12..18].copy_from_slice(&[0, 1, 0, 1, 0, 1]);
        b
    }

    fn run(h: &mut Header, now: f64, b: &[u8]) -> Vec<&'static str> {
        let (a, s) = h.observe(now, src(), b, &L, |_, _| false);
        a.iter().chain(&s).map(|f| f.kind).collect()
    }

    #[test]
    fn a_steady_clock_and_defined_bits_are_silent() {
        let mut h = Header::default();
        let base = 7200.0;
        for i in 0..10 {
            let t = base + 5.0 * i as f64;
            // Absolute, on time; the hour wraps at 3600.
            assert!(run(&mut h, t, &pdu(1, t.rem_euclid(3600.0), true, 0b1111)).is_empty());
        }
        // Across the hour: 3599 then 2.
        let mut h = Header::default();
        assert!(run(&mut h, 3599.0, &pdu(1, 3599.0, true, 0)).is_empty());
        assert!(run(&mut h, 3602.0, &pdu(1, 2.0, true, 0)).is_empty());
        // Relative timestamps aren't compared with the clock.
        assert!(run(&mut Header::default(), 100.0, &pdu(1, 3000.0, false, 0)).is_empty());
        assert_eq!(
            clock_skew(100.0, &pdu(1, 130.0, true, 0)).map(|s| s.round()),
            Some(30.0)
        );
        assert_eq!(
            clock_skew(3599.0, &pdu(1, 1.0, true, 0)).map(|s| s.round()),
            Some(2.0),
            "the hour wraps"
        );
        assert_eq!(clock_skew(100.0, &pdu(1, 130.0, false, 0)), None);
    }

    #[test]
    fn a_sender_switching_exercise_is_named_once() {
        let mut h = Header::default();
        let on = |ex: u8| {
            let mut b = pdu(1, 0.0, true, 0);
            b[1] = ex;
            b
        };
        for t in 0..80 {
            assert!(h.exercise(t as f64, src(), &on(1), 60.0).is_none());
        }
        assert_eq!(h.exercise(80.0, src(), &on(2), 60.0).map(|f| f.kind), Some("switched"));
        assert!(h.exercise(81.0, src(), &on(2), 60.0).is_none(), "once");
        // Not when it had sent the other only briefly (a quick fix).
        let mut h = Header::default();
        h.exercise(0.0, src(), &on(1), 60.0);
        assert!(h.exercise(5.0, src(), &on(2), 60.0).is_none());
    }

    #[test]
    fn each_finding_is_named() {
        let mut h = Header::default();
        run(&mut h, 10.0, &pdu(1, 10.0, true, 0));
        assert_eq!(run(&mut h, 15.0, &pdu(1, 15.0, false, 0)), ["type-changed"]);
        let mut h = Header::default();
        run(&mut h, 10.0, &pdu(1, 10.0, false, 0));
        assert_eq!(run(&mut h, 15.0, &pdu(1, 4.0, false, 0)), ["backwards"]);
        // A freeze or resume between them: no baseline.
        let mut h = Header::default();
        h.observe(10.0, src(), &pdu(1, 10.0, false, 0), &L, |_, _| false);
        assert!(h
            .observe(15.0, src(), &pdu(1, 4.0, false, 0), &L, |_, _| true)
            .0
            .is_empty());
        assert_eq!(
            run(&mut Header::default(), 100.0, &pdu(1, 130.0, true, 0)),
            ["clock-ahead"]
        );
        assert_eq!(
            run(&mut Header::default(), 100.0, &pdu(1, 80.0, true, 0)),
            ["clock-behind"]
        );
        assert_eq!(
            run(&mut Header::default(), 10.0, &pdu(1, 10.0, true, 0b1_0000)),
            ["undefined-bits"]
        );
        assert_eq!(
            run(&mut Header::default(), 10.0, &pdu(3, 10.0, true, 0b11_0000)),
            ["bad-value"]
        );
        let mut iff = pdu(28, 10.0, true, 0b1_0000);
        iff[41] = 0;
        assert_eq!(run(&mut Header::default(), 10.0, &iff), ["ism-mismatch"]);
        // v6: its status byte is padding.
        let mut v6 = pdu(1, 10.0, true, 0xff);
        v6[0] = 6;
        assert!(run(&mut Header::default(), 10.0, &v6).is_empty());
    }
}
