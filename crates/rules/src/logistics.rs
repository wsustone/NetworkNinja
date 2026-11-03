//! Logistics (ADR 0010 Wave 3; IEEE 1278.1 5.5, 7.4), on raw PDU bytes:
//! resupply and repair conversations keyed by (exercise, receiving entity,
//! supplying entity). Point events of the `logistics` rule:
//!
//! - `no-offer`: a resupply Service Request got neither a Resupply Offer nor
//!   a Resupply Cancel from the supplier it named within `response_timeout`
//!   (5.5.5.4 a, c).
//! - `no-receipt`: a Resupply Offer got neither Resupply Received nor
//!   Resupply Cancel within RESUP_SUP_T1 (5.5.3.3, 5.5.6.4).
//! - `received-more`: Resupply Received lists a supply type that wasn't
//!   offered, or more of it than offered (5.5.9).
//! - `no-repair-response`: a Repair Complete got no Repair Response within
//!   REPAR_SUP_T2 (5.5.10.4, 5.5.11.3).
//! - `cancel-result`: a supplier's cancel (Repair Complete with No Repairs
//!   Performed) answered with a result other than Service Canceled by the
//!   Supplier (5.5.11.4).
//! - `supplies-on-repair`: a repair Service Request lists supplies
//!   (5.5.5.2 d).
//! - `unsolicited-offer`, `orphan-received`, `unrequested-repair`,
//!   `orphan-repair-response`: an answer to a request or offer never seen,
//!   once the monitor has watched long enough not to have missed it.
//! - `unknown-supplier`: a Service Request names an entity the exercise
//!   doesn't know (after the same grace).
//!
//! Only PDUs naming two specific entities are judged. Conversations end,
//! owing nothing, when either entity is removed or deactivated; frozen time
//! doesn't count.

use crate::interactions::Finding;
use nn_decode::EntityId;
use nn_state::{EntityKey, EntityTable};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

const SERVICE_REQUEST: u8 = 5;
const RESUPPLY_OFFER: u8 = 6;
const RESUPPLY_RECEIVED: u8 = 7;
const RESUPPLY_CANCEL: u8 = 8;
const REPAIR_COMPLETE: u8 = 9;
const REPAIR_RESPONSE: u8 = 10;
/// Service Type Requested (UID 63).
const RESUPPLY: u8 = 1;
const REPAIR: u8 = 2;
/// Repair (UID 64) and Repair Result (UID 65).
const NO_REPAIRS: u16 = 0;
const CANCELED_BY_SUPPLIER: u8 = 4;

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

/// Supply records (entity type, quantity), `n` of them from `at`.
fn supplies(b: &[u8], n: usize, at: usize) -> Vec<([u8; 8], f32)> {
    (0..n)
        .filter_map(|i| {
            let r = b.get(at + 12 * i..at + 12 * i + 12)?;
            Some((r[..8].try_into().ok()?, f32::from_be_bytes(r[8..12].try_into().ok()?)))
        })
        .collect()
}

fn kind_name(t: &[u8; 8]) -> String {
    let c = u16::from_be_bytes([t[2], t[3]]);
    format!("{}.{}.{}.{}.{}.{}.{}", t[0], t[1], c, t[4], t[5], t[6], t[7])
}

/// The rule's waits, in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Watch this long before calling an answer unsolicited.
    pub grace: f64,
    /// A supplier answers a resupply request (offer or cancel).
    pub response: f64,
    /// RESUP_SUP_T1: an offer is taken or cancelled.
    pub resupply: f64,
    /// REPAR_SUP_T2: a Repair Complete is answered.
    pub repair_response: f64,
}

#[derive(Debug, Clone)]
struct Waiting {
    since: f64,
    /// Who it's waiting on, for the alert.
    owes: SocketAddr,
    offered: Vec<([u8; 8], f32)>,
    repair: u16,
}

type Key = (u8, EntityId, EntityId);

#[derive(Debug, Default)]
pub struct Logistics {
    /// Resupply requests awaiting an offer or cancel.
    requests: HashMap<Key, Waiting>,
    /// Offers awaiting Received or Cancel.
    offers: HashMap<Key, Waiting>,
    /// When each pair last asked for repair.
    repair_asked: HashMap<Key, f64>,
    /// Repair Completes awaiting a Repair Response.
    completes: HashMap<Key, Waiting>,
    /// Answered recently, so a repeat isn't an orphan (pair, PDU type).
    settled: HashMap<(Key, u8), f64>,
    reported_unknown: HashSet<Key>,
    started: Option<f64>,
    last_tick: Option<f64>,
}

impl Logistics {
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        table: &EntityTable,
        limits: &Limits,
    ) -> Vec<Finding> {
        let (Some(&exercise), Some(&pdu_type), Some(receiver), Some(supplier)) =
            (pdu.get(1), pdu.get(2), id_at(pdu, 12), id_at(pdu, 18))
        else {
            return Vec::new();
        };
        // A conversation is between two specific entities: an entity number
        // of 0 or 65535 names none.
        let specific = |id: EntityId| id.entity != 0 && id.entity != 0xffff;
        if !(SERVICE_REQUEST..=REPAIR_RESPONSE).contains(&pdu_type) || !specific(receiver) || !specific(supplier) {
            return Vec::new();
        }
        let started = *self.started.get_or_insert(now);
        let watched = now - started >= limits.grace;
        let key = (exercise, receiver, supplier);
        let ekey = |id: EntityId| EntityKey { exercise, id };
        let mut out = Vec::new();
        let mut push = |kind: &'static str, about: EntityId, message: String, mut facts: crate::engine::Facts| {
            facts.insert(0, ("receiving entity", receiver.to_string()));
            facts.insert(1, ("supplying entity", supplier.to_string()));
            out.push(Finding {
                kind,
                key: ekey(about),
                sender: source,
                message,
                facts,
            });
        };
        // The other party's address, to pin an overdue answer on.
        let addr = |id: EntityId| table.get(&ekey(id)).map(|r| r.last_source);
        let recent = |s: &HashMap<(Key, u8), f64>, t: u8| s.get(&(key, t)).is_some_and(|&at| now - at < 600.0);
        match pdu_type {
            SERVICE_REQUEST => {
                let (Some(&service), Some(&n)) = (pdu.get(24), pdu.get(25)) else {
                    return out;
                };
                if service == REPAIR && n > 0 {
                    push(
                        "supplies-on-repair",
                        receiver,
                        format!(
                            "{receiver} asks {supplier} for repair but lists {n} supply type(s); only a resupply request lists supplies{}",
                            cite("5.5.5.2 d)")
                        ),
                        vec![("service", "Repair (2)".into()), ("supply types", n.to_string())],
                    );
                }
                if watched && table.get(&ekey(supplier)).is_none() && self.reported_unknown.insert(key) {
                    push(
                        "unknown-supplier",
                        receiver,
                        format!(
                            "{receiver} asks {supplier} for service, but {supplier} isn't an entity in the exercise{}",
                            cite("5.5.5")
                        ),
                        vec![("in the entity table", "no".into())],
                    );
                }
                if service == RESUPPLY && !self.offers.contains_key(&key) {
                    self.requests.entry(key).or_insert(Waiting {
                        since: now,
                        owes: addr(supplier).unwrap_or(source),
                        offered: Vec::new(),
                        repair: 0,
                    });
                } else if service == REPAIR {
                    self.repair_asked.insert(key, now);
                }
            }
            RESUPPLY_OFFER => {
                let n = pdu.get(24).copied().unwrap_or(0) as usize;
                let asked = self.requests.remove(&key).is_some() || recent(&self.settled, SERVICE_REQUEST);
                if !asked && watched && !self.offers.contains_key(&key) {
                    push(
                        "unsolicited-offer",
                        supplier,
                        format!(
                            "{supplier} offers supplies to {receiver}, which didn't ask it for resupply{}",
                            cite("5.5.6.3")
                        ),
                        vec![("service request seen", "no".into())],
                    );
                }
                self.settled.insert((key, SERVICE_REQUEST), now);
                self.offers.insert(
                    key,
                    Waiting {
                        since: now,
                        owes: addr(receiver).unwrap_or(source),
                        offered: supplies(pdu, n, 28),
                        repair: 0,
                    },
                );
            }
            RESUPPLY_RECEIVED => {
                let n = pdu.get(24).copied().unwrap_or(0) as usize;
                match self.offers.remove(&key) {
                    Some(offer) => {
                        self.settled.insert((key, RESUPPLY_OFFER), now);
                        for (t, q) in supplies(pdu, n, 28) {
                            let offered = offer.offered.iter().find(|o| o.0 == t).map(|o| o.1);
                            if offered.is_none_or(|o| q > o * 1.0001 + 1e-6) {
                                push(
                                    "received-more",
                                    receiver,
                                    format!(
                                        "{receiver} reports taking {q} of {} from {supplier}, which offered {}{}",
                                        kind_name(&t),
                                        offered.map_or("none".into(), |o| o.to_string()),
                                        cite("5.5.9")
                                    ),
                                    vec![
                                        ("supply type", kind_name(&t)),
                                        ("received", q.to_string()),
                                        ("offered", offered.map_or("none".into(), |o| o.to_string())),
                                    ],
                                );
                                break;
                            }
                        }
                    }
                    None if watched && !recent(&self.settled, RESUPPLY_OFFER) => push(
                        "orphan-received",
                        receiver,
                        format!(
                            "{receiver} reports supplies received from {supplier}, which offered none{}",
                            cite("5.5.7.3")
                        ),
                        vec![("resupply offer seen", "no".into())],
                    ),
                    None => {}
                }
            }
            RESUPPLY_CANCEL => {
                // Either side may cancel, at any point (5.5.8.3).
                if self.requests.remove(&key).is_some() {
                    self.settled.insert((key, SERVICE_REQUEST), now);
                }
                if self.offers.remove(&key).is_some() {
                    self.settled.insert((key, RESUPPLY_OFFER), now);
                }
            }
            REPAIR_COMPLETE => {
                let repair = u16_at(pdu, 24).unwrap_or(0);
                let asked = self.repair_asked.get(&key).is_some_and(|&at| now - at < 600.0);
                if !asked && watched {
                    push(
                        "unrequested-repair",
                        supplier,
                        format!(
                            "{supplier} reports a repair of {receiver}, which didn't ask it for repair{}",
                            cite("5.5.10.3")
                        ),
                        vec![("repair", repair.to_string()), ("service request seen", "no".into())],
                    );
                }
                self.completes.insert(
                    key,
                    Waiting {
                        since: now,
                        owes: addr(receiver).unwrap_or(source),
                        offered: Vec::new(),
                        repair,
                    },
                );
            }
            REPAIR_RESPONSE => {
                let result = pdu.get(24).copied().unwrap_or(0);
                match self.completes.remove(&key) {
                    Some(c) => {
                        self.settled.insert((key, REPAIR_COMPLETE), now);
                        self.repair_asked.remove(&key);
                        if c.repair == NO_REPAIRS && result != CANCELED_BY_SUPPLIER {
                            push(
                                "cancel-result",
                                receiver,
                                format!(
                                    "{supplier} cancelled the repair (No Repairs Performed), so {receiver}'s Repair Response should say Service Canceled by the Supplier (4), not {result}{}",
                                    cite("5.5.11.4")
                                ),
                                vec![("repair", "no repairs performed (0)".into()), ("repair result", result.to_string())],
                            );
                        }
                    }
                    None if watched && !recent(&self.settled, REPAIR_COMPLETE) => push(
                        "orphan-repair-response",
                        receiver,
                        format!(
                            "{receiver} answers a repair by {supplier} that was never reported complete{}",
                            cite("5.5.11.3")
                        ),
                        vec![("repair complete seen", "no".into())],
                    ),
                    None => {}
                }
            }
            _ => {}
        }
        out
    }

    /// Answers overdue; forget old state. Frozen time doesn't count.
    pub fn expire(
        &mut self,
        now: f64,
        limits: &Limits,
        table: &EntityTable,
        frozen: impl Fn(u8, EntityId) -> bool,
    ) -> Vec<Finding> {
        let dt = now - self.last_tick.unwrap_or(now);
        self.last_tick = Some(now);
        let gone = |exercise: u8, id: EntityId| {
            table
                .get(&EntityKey { exercise, id })
                .is_some_and(|r| r.removed || r.deactivated())
        };
        let mut out = Vec::new();
        let mut sweep = |map: &mut HashMap<Key, Waiting>, wait: f64, what: &'static str| {
            map.retain(|&(exercise, receiver, supplier), w| {
                if gone(exercise, receiver) || gone(exercise, supplier) {
                    return false;
                }
                if frozen(exercise, receiver) || frozen(exercise, supplier) {
                    w.since += dt;
                    return true;
                }
                if now - w.since < wait {
                    return true;
                }
                let (kind, who, message, clause) = match what {
                    "offer" => (
                        "no-offer",
                        supplier,
                        format!("{receiver} asked {supplier} for resupply: no Resupply Offer or Resupply Cancel"),
                        "5.5.5.4",
                    ),
                    "receipt" => (
                        "no-receipt",
                        receiver,
                        format!("{supplier} offered {receiver} supplies: no Resupply Received or Resupply Cancel"),
                        "5.5.3.3, 5.5.6.4",
                    ),
                    _ => (
                        "no-repair-response",
                        receiver,
                        format!("{supplier} completed a repair of {receiver}: no Repair Response"),
                        "5.5.10.4",
                    ),
                };
                out.push(Finding {
                    kind,
                    key: EntityKey { exercise, id: who },
                    sender: w.owes,
                    message: format!("{message} within {wait:.0} s{}", cite(clause)),
                    facts: vec![
                        ("receiving entity", receiver.to_string()),
                        ("supplying entity", supplier.to_string()),
                        ("waited", format!("{wait:.0} s")),
                    ],
                });
                false
            });
        };
        sweep(&mut self.requests, limits.response, "offer");
        sweep(&mut self.offers, limits.resupply, "receipt");
        sweep(&mut self.completes, limits.repair_response, "repair");
        self.repair_asked.retain(|_, at| now - *at < 600.0);
        self.settled.retain(|_, at| now - *at < 600.0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const R: EntityId = EntityId::new(1, 1, 1);
    const S: EntityId = EntityId::new(2, 1, 1);
    const FUEL: [u8; 8] = [2, 9, 0, 0, 0, 1, 0, 0];

    fn pdu(t: u8, extra: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0] = 7;
        b[1] = 1;
        b[2] = t;
        for (at, id) in [(12, R), (18, S)] {
            for (i, v) in [id.site, id.application, id.entity].iter().enumerate() {
                b[at + 2 * i..at + 2 * i + 2].copy_from_slice(&v.to_be_bytes());
            }
        }
        b.extend(extra);
        b
    }

    fn with_supplies(head: [u8; 4], q: &[f32]) -> Vec<u8> {
        let mut e = head.to_vec();
        for &v in q {
            e.extend(FUEL);
            e.extend(v.to_be_bytes());
        }
        e
    }
    fn request(service: u8, n: u8) -> Vec<u8> {
        pdu(
            SERVICE_REQUEST,
            &with_supplies([service, n, 0, 0], &vec![100.0; n as usize]),
        )
    }
    fn offer(q: f32) -> Vec<u8> {
        pdu(RESUPPLY_OFFER, &with_supplies([1, 0, 0, 0], &[q]))
    }
    fn received(q: f32) -> Vec<u8> {
        pdu(RESUPPLY_RECEIVED, &with_supplies([1, 0, 0, 0], &[q]))
    }
    fn complete(repair: u16) -> Vec<u8> {
        let mut e = repair.to_be_bytes().to_vec();
        e.extend([0, 0]);
        pdu(REPAIR_COMPLETE, &e)
    }
    fn response(result: u8) -> Vec<u8> {
        pdu(REPAIR_RESPONSE, &[result, 0, 0, 0])
    }

    const L: Limits = Limits {
        grace: 0.0,
        response: 12.0,
        resupply: 60.0,
        repair_response: 12.0,
    };

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    struct Run {
        l: Logistics,
        t: EntityTable,
        found: Vec<Finding>,
    }
    impl Run {
        fn new() -> Run {
            Run {
                l: Logistics::default(),
                t: EntityTable::default(),
                found: Vec::new(),
            }
        }
        fn at(&mut self, now: f64, b: &[u8]) -> &mut Run {
            self.found.extend(self.l.expire(now, &L, &self.t, |_, _| false));
            self.found.extend(self.l.observe(now, src(), b, &self.t, &L));
            self
        }
        fn tick(&mut self, now: f64) -> &mut Run {
            self.found.extend(self.l.expire(now, &L, &self.t, |_, _| false));
            self
        }
        fn kinds(&self) -> Vec<&str> {
            kinds(&self.found)
        }
    }

    #[test]
    fn resupply_and_repair_told_right_are_silent() {
        let mut r = Run::new();
        // Asked twice, offered, taken in part after 55 s.
        r.at(0.0, &request(RESUPPLY, 1)).at(5.0, &request(RESUPPLY, 1));
        r.at(6.0, &offer(80.0)).at(61.0, &received(40.0));
        // Asked, refused with a cancel.
        r.at(100.0, &request(RESUPPLY, 1)).at(101.0, &pdu(RESUPPLY_CANCEL, &[]));
        // Repair: requests every 5 s, complete, response.
        for t in [200.0, 205.0, 210.0] {
            r.at(t, &request(REPAIR, 0));
        }
        r.at(212.0, &complete(1)).at(213.0, &response(1));
        // The supplier cancels a repair, answered properly.
        r.at(300.0, &request(REPAIR, 0)).at(302.0, &complete(NO_REPAIRS));
        r.at(303.0, &response(CANCELED_BY_SUPPLIER)).tick(400.0);
        // The unknown supplier is the only thing said: the table is empty.
        assert!(r.kinds().iter().all(|k| *k == "unknown-supplier"), "{:?}", r.found);
    }

    #[test]
    fn each_finding_is_named() {
        let one = |steps: &[(f64, Vec<u8>)], end: f64| {
            let mut r = Run::new();
            for (t, b) in steps {
                r.at(*t, b);
            }
            r.tick(end);
            r.kinds()
                .into_iter()
                .filter(|k| *k != "unknown-supplier")
                .map(String::from)
                .collect::<Vec<_>>()
        };
        assert_eq!(one(&[(0.0, request(RESUPPLY, 1))], 13.0), ["no-offer"]);
        assert_eq!(
            one(&[(0.0, request(RESUPPLY, 1)), (1.0, offer(10.0))], 62.0),
            ["no-receipt"]
        );
        assert_eq!(
            one(
                &[(0.0, request(RESUPPLY, 1)), (1.0, offer(10.0)), (50.0, received(20.0))],
                60.0
            ),
            ["received-more"]
        );
        assert_eq!(
            one(&[(0.0, request(REPAIR, 0)), (5.0, complete(1))], 18.0),
            ["no-repair-response"]
        );
        assert_eq!(
            one(
                &[(0.0, request(REPAIR, 0)), (5.0, complete(0)), (6.0, response(1))],
                10.0
            ),
            ["cancel-result"]
        );
        assert_eq!(one(&[(0.0, request(REPAIR, 2))], 1.0), ["supplies-on-repair"]);
        assert_eq!(
            one(&[(0.0, offer(1.0)), (1.0, received(1.0))], 2.0),
            ["unsolicited-offer"]
        );
        assert_eq!(one(&[(0.0, received(1.0))], 1.0), ["orphan-received"]);
        assert_eq!(
            one(&[(0.0, complete(1)), (1.0, response(1))], 2.0),
            ["unrequested-repair"]
        );
        assert_eq!(one(&[(0.0, response(1))], 1.0), ["orphan-repair-response"]);
        let mut r = Run::new();
        r.at(0.0, &request(RESUPPLY, 1));
        assert_eq!(r.kinds(), ["unknown-supplier"]);
        r.at(5.0, &request(RESUPPLY, 1));
        assert_eq!(r.kinds(), ["unknown-supplier"], "once per pair");
    }

    #[test]
    fn frozen_time_and_departures_owe_nothing() {
        let mut l = Logistics::default();
        let t = EntityTable::default();
        l.observe(0.0, src(), &request(RESUPPLY, 1), &t, &L);
        l.expire(1.0, &L, &t, |_, _| false);
        assert!(l.expire(30.0, &L, &t, |_, _| true).is_empty(), "frozen");
        assert!(
            l.expire(35.0, &L, &t, |_, _| false).is_empty(),
            "the freeze didn't count"
        );
        assert_eq!(kinds(&l.expire(45.0, &L, &t, |_, _| false)), ["no-offer"]);
    }
}
