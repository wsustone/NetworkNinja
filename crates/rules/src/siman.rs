//! Simulation Management handshakes (ADR 0010 step 5, IEEE 1278.1 5.6.5 and
//! 5.12.4): every request a simulation must answer gets its answer.
//!
//! | Request | Answer |
//! | --- | --- |
//! | Create Entity, Remove Entity, Start/Resume, Stop/Freeze (and -R) | Acknowledge (-R), with the matching Acknowledge Flag |
//! | Action Request (-R) | Action Response (-R) |
//! | Data Query, Set Data (-R) | Data (-R) |
//! | Set Record-R, Record Query-R | Record-R |
//!
//! An answer matches a request when it comes back from the simulation the
//! request named, is addressed to the requester, and carries its Request ID.
//! Only requests to one specific simulation or entity must be answered: a
//! broadcast ("all simulations") can't say who owes an answer, and a
//! simulation's requests about its own entities are announcements. -R
//! requests that ask for unacknowledged service (a Required Reliability
//! Service of 1) need no answer either. Broadcast requests are still
//! remembered, so their answers aren't mistaken for unsolicited ones.
//!
//! Findings, all point events of the `siman-handshake` rule:
//! - no answer within `response_timeout` (default 12 s, TI_TIMER2_DFLT);
//! - an Acknowledge whose flag doesn't match the request it answers;
//! - an Acknowledge or Action Response that answers no request seen
//!   (reported only once the monitor has watched for longer than the
//!   timeout, so a request sent before it started isn't missed).

use nn_decode::EntityId;
use std::collections::BTreeMap;
use std::net::SocketAddr;

/// A simulation address: site and application.
pub type SimAddr = (u16, u16);

/// What a request expects back: the answer's PDU type, and for an
/// Acknowledge its flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Expect {
    pdu_type: u8,
    ack_flag: Option<u16>,
}

/// Request types: (request type, Request ID offset, reliability offset for
/// -R types, what it expects).
fn request(pdu_type: u8) -> Option<(usize, Option<usize>, Expect)> {
    let ack = |pdu_type, flag| Expect {
        pdu_type,
        ack_flag: Some(flag),
    };
    let ans = |pdu_type| Expect {
        pdu_type,
        ack_flag: None,
    };
    Some(match pdu_type {
        11 => (24, None, ack(15, 1)),
        12 => (24, None, ack(15, 2)),
        13 => (40, None, ack(15, 3)),
        14 => (36, None, ack(15, 4)),
        16 => (24, None, ans(17)),
        18 => (24, None, ans(20)),
        19 => (24, None, ans(20)),
        51 => (28, Some(24), ack(55, 1)),
        52 => (28, Some(24), ack(55, 2)),
        53 => (44, Some(40), ack(55, 3)),
        54 => (36, Some(34), ack(55, 4)),
        56 => (28, Some(24), ans(57)),
        58 => (28, Some(24), ans(60)),
        59 => (28, Some(24), ans(60)),
        64 => (24, Some(28), ans(63)),
        65 => (24, Some(28), ans(63)),
        _ => return None,
    })
}

/// Answer types: (Request ID offset, Acknowledge Flag offset). Data and
/// Record-R may also be sent unprompted, so only Acknowledge and Action
/// Response can be "unsolicited".
fn answer(pdu_type: u8) -> Option<(usize, Option<usize>, bool)> {
    Some(match pdu_type {
        15 | 55 => (28, Some(24), true),
        17 | 57 => (24, None, true),
        20 | 60 | 63 => (24, None, false),
        _ => return None,
    })
}

/// The usage clause each request's answer rule comes from (draft D16r18).
fn clause(pdu_type: u8) -> &'static str {
    match pdu_type {
        11 => "5.6.5.2.4",
        12 => "5.6.5.3.4",
        13 => "5.6.5.4.4",
        14 => "5.6.5.5.5",
        16 => "5.6.5.7.4",
        18 => "5.6.5.9.4",
        19 => "5.6.5.10.4",
        15 | 55 => "5.6.5.6.3",
        17 | 57 => "5.6.5.8.3",
        _ => "5.12.3.2",
    }
}

#[derive(Debug, Clone)]
struct Pending {
    at: f64,
    pdu_type: u8,
    expect: Expect,
    /// The simulation that owes the answer; `None` for a broadcast.
    responder: Option<SimAddr>,
    originating: EntityId,
    receiving: EntityId,
    /// Answered, or already reported as unanswered.
    settled: bool,
}

/// A handshake finding, for the engine to raise.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    /// "no-answer", "wrong-flag" or "unsolicited".
    pub kind: &'static str,
    pub exercise: u8,
    /// The entity or simulation the finding is about.
    pub id: EntityId,
    /// The sender at fault, when known.
    pub sender: Option<SocketAddr>,
    /// For a missing answer, the simulation that owes it, so the engine
    /// can look up its address.
    pub owes: Option<SimAddr>,
    pub message: String,
    pub facts: crate::engine::Facts,
}

#[derive(Debug, Default)]
pub struct Handshakes {
    /// (exercise, requester, Request ID) → requests with that ID.
    pending: BTreeMap<(u8, SimAddr, u32), Vec<Pending>>,
    /// When the monitor first saw traffic.
    started: Option<f64>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

/// A real simulation address: not a wildcard (65535) and not "no
/// simulation" (0).
fn specific(id: &EntityId) -> Option<SimAddr> {
    let real = |v: u16| v != 0 && v != 0xffff;
    (real(id.site) && real(id.application)).then_some((id.site, id.application))
}

fn name(pdu_type: u8) -> &'static str {
    nn_decode::pdu_type_name(pdu_type)
}

impl Handshakes {
    /// One PDU's bytes (header included). Returns findings it settles now:
    /// a wrong flag or an unsolicited answer.
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], timeout: f64) -> Vec<Finding> {
        let started = *self.started.get_or_insert(now);
        let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
            return Vec::new();
        };
        let (Some(orig), Some(recv)) = (id_at(pdu, 12), id_at(pdu, 18)) else {
            return Vec::new();
        };
        if let Some((req_at, rel_at, expect)) = request(pdu_type) {
            let Some(request_id) = u32_at(pdu, req_at) else {
                return Vec::new();
            };
            let Some(requester) = specific(&orig) else {
                return Vec::new();
            };
            // Required Reliability Service 1 = unacknowledged.
            let unacknowledged = rel_at.and_then(|at| pdu.get(at)).is_some_and(|&r| r == 1);
            let responder = specific(&recv).filter(|r| *r != requester && !unacknowledged);
            let list = self.pending.entry((exercise, requester, request_id)).or_default();
            // A retry of the same request keeps the first one's clock.
            if !list.iter().any(|p| p.pdu_type == pdu_type && !p.settled) {
                list.push(Pending {
                    at: now,
                    pdu_type,
                    expect,
                    responder,
                    originating: orig,
                    receiving: recv,
                    settled: false,
                });
            }
            return Vec::new();
        }
        let Some((req_at, flag_at, must_match)) = answer(pdu_type) else {
            return Vec::new();
        };
        let (Some(request_id), Some(requester)) = (u32_at(pdu, req_at), specific(&recv)) else {
            return Vec::new();
        };
        let flag = flag_at.and_then(|at| u16_at(pdu, at));
        let responder = specific(&orig);
        let Some(list) = self.pending.get_mut(&(exercise, requester, request_id)) else {
            if must_match && now - started > timeout {
                return vec![Finding {
                    kind: "unsolicited",
                    exercise,
                    id: orig,
                    sender: Some(source),
                    owes: None,
                    message: format!(
                        "{} {orig} → {recv}, request {request_id}: answers no request seen from {}:{} (IEEE 1278.1 {}, draft D16r18)",
                        name(pdu_type),
                        requester.0,
                        requester.1,
                        clause(pdu_type)
                    ),
                    facts: vec![
                        ("answer", name(pdu_type).to_string()),
                        ("from", orig.to_string()),
                        ("to", recv.to_string()),
                        ("Request ID", request_id.to_string()),
                        ("matching request", "none seen".into()),
                    ],
                }];
            }
            return Vec::new();
        };
        // Request IDs are numbered per request type, so several requests
        // can share one: prefer one this answer fits exactly (type, sender
        // and Acknowledge Flag), unanswered first.
        let fits = |p: &Pending| p.expect.pdu_type == pdu_type && (p.responder.is_none() || p.responder == responder);
        let exact = |p: &Pending| fits(p) && (p.expect.ack_flag.is_none() || p.expect.ack_flag == flag);
        let pick = list
            .iter()
            .position(|p| exact(p) && !p.settled)
            .or_else(|| list.iter().position(exact));
        if let Some(i) = pick {
            list[i].settled = true;
            return Vec::new();
        }
        // No exact fit: a wrong flag, if this answers a request made to
        // this very simulation (a broadcast's answers can't be pinned).
        let Some(p) = list.iter_mut().find(|p| fits(p) && p.responder.is_some() && !p.settled) else {
            return Vec::new();
        };
        p.settled = true;
        vec![Finding {
            kind: "wrong-flag",
            exercise,
            id: orig,
            sender: Some(source),
            owes: None,
            message: format!(
                "{} {orig} → {recv}, request {request_id}: Acknowledge Flag {}, but it answers a {} (flag {}) (IEEE 1278.1 5.6.5.6.3, draft D16r18)",
                name(pdu_type),
                flag.unwrap_or(0),
                name(p.pdu_type),
                p.expect.ack_flag.unwrap_or(0)
            ),
            facts: vec![
                ("request", format!("{} (Request ID {request_id})", name(p.pdu_type))),
                ("Acknowledge Flag", flag.unwrap_or(0).to_string()),
                ("expected", p.expect.ack_flag.unwrap_or(0).to_string()),
            ],
        }]
    }

    /// Requests whose answer is overdue, and forget old ones.
    pub fn expire(&mut self, now: f64, timeout: f64) -> Vec<Finding> {
        let mut out = Vec::new();
        self.pending.retain(|&(exercise, _, request_id), list| {
            list.retain_mut(|p| {
                if now - p.at < timeout {
                    return true;
                }
                if let (false, Some(owes)) = (p.settled, p.responder) {
                    p.settled = true;
                    out.push(Finding {
                        kind: "no-answer",
                        exercise,
                        // Keyed by the simulation, so one that stops
                        // answering is one alert, not one per entity asked.
                        id: EntityId::new(owes.0, owes.1, 0xffff),
                        sender: None,
                        owes: Some(owes),
                        message: format!(
                            "{} {} → {}, request {request_id}: no {} within {timeout:.0} s (IEEE 1278.1 {}, draft D16r18)",
                            name(p.pdu_type),
                            p.originating,
                            p.receiving,
                            name(p.expect.pdu_type),
                            clause(p.pdu_type)
                        ),
                        facts: vec![
                            ("request", format!("{} (Request ID {request_id})", name(p.pdu_type))),
                            ("from", p.originating.to_string()),
                            ("to", p.receiving.to_string()),
                            ("expected answer", name(p.expect.pdu_type).to_string()),
                            ("waited", format!("{timeout:.0} s")),
                        ],
                    });
                }
                // Keep settled and broadcast requests a little longer, so
                // late or repeated answers still find them.
                now - p.at < 5.0 * timeout
            });
            !list.is_empty()
        });
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SM: EntityId = EntityId::new(1, 1, 0xffff);
    const TARGET: EntityId = EntityId::new(2, 1, 1);

    /// A PDU of `pdu_type` (header plus `len` bytes) with the two SIMAN IDs
    /// and `fields` (offset, value, width) set.
    fn pdu(pdu_type: u8, len: usize, orig: EntityId, recv: EntityId, fields: &[(usize, u32, usize)]) -> Vec<u8> {
        let mut b = vec![0u8; len];
        b[0] = 7;
        b[1] = 1;
        b[2] = pdu_type;
        for (i, v) in [
            orig.site,
            orig.application,
            orig.entity,
            recv.site,
            recv.application,
            recv.entity,
        ]
        .into_iter()
        .enumerate()
        {
            b[12 + 2 * i..14 + 2 * i].copy_from_slice(&v.to_be_bytes());
        }
        for &(at, v, w) in fields {
            b[at..at + w].copy_from_slice(&v.to_be_bytes()[4 - w..]);
        }
        b
    }

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }

    #[test]
    fn unacknowledged_r_requests_and_own_entities_need_no_answer() {
        let mut h = Handshakes::default();
        // Action Request-R asking for unacknowledged service (1).
        h.observe(0.0, src(), &pdu(56, 48, SM, TARGET, &[(24, 1, 1), (28, 7, 4)]), 12.0);
        // A simulation's Remove Entity for its own entity.
        h.observe(
            0.0,
            src(),
            &pdu(12, 28, SM, EntityId::new(1, 1, 4), &[(24, 8, 4)]),
            12.0,
        );
        assert!(h.expire(20.0, 12.0).is_empty());
        // The same Action Request-R with acknowledged service (0) does.
        h.observe(30.0, src(), &pdu(56, 48, SM, TARGET, &[(24, 0, 1), (28, 9, 4)]), 12.0);
        let f = h.expire(45.0, 12.0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].owes, Some((2, 1)));
        assert!(
            f[0].message.contains("no ActionResponseR within 12 s"),
            "{}",
            f[0].message
        );
    }

    #[test]
    fn unsolicited_answers_wait_until_the_monitor_has_watched_a_timeout() {
        let mut h = Handshakes::default();
        let stray = pdu(17, 40, TARGET, SM, &[(24, 5, 4)]);
        assert!(h.observe(0.0, src(), &stray, 12.0).is_empty(), "too early to know");
        let f = h.observe(13.0, src(), &stray, 12.0);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, "unsolicited");
        // Data may be sent unprompted.
        assert!(h
            .observe(14.0, src(), &pdu(20, 40, TARGET, SM, &[(24, 5, 4)]), 12.0)
            .is_empty());
    }

    #[test]
    fn a_retried_request_keeps_its_first_clock_and_one_answer_settles_it() {
        let mut h = Handshakes::default();
        let req = pdu(16, 40, SM, TARGET, &[(24, 3, 4)]);
        h.observe(0.0, src(), &req, 12.0);
        h.observe(5.0, src(), &req, 12.0);
        assert_eq!(h.expire(12.5, 12.0).len(), 1, "12 s after the first send");
        let mut h = Handshakes::default();
        h.observe(0.0, src(), &req, 12.0);
        h.observe(5.0, src(), &req, 12.0);
        h.observe(6.0, src(), &pdu(17, 40, TARGET, SM, &[(24, 3, 4)]), 12.0);
        assert!(h.expire(20.0, 12.0).is_empty());
    }
}
