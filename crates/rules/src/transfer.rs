//! Transfer Ownership (ADR 0010 Wave 3; IEEE 1278.1 5.9.4, 7.8.4): the
//! transfer of an entity from a divesting to an acquiring simulation,
//! keyed by (exercise, entity). A transaction opens with a TO PDU (push or
//! pull), ends cancelled (a Cancel TO, or an Acknowledge-R Unable to
//! Comply) or completed when the acquiring simulation's first Entity State
//! for the entity arrives. Point events of the `transfer-ownership` rule:
//!
//! - `reliability`: a TO PDU that doesn't ask for Unacknowledged service
//!   (5.9.4.2.1 a 4).
//! - `concurrent`: a transfer request for an entity already in a transfer
//!   with another simulation (a 23).
//! - `inactive-entity`: a transfer request for an entity that isn't Active
//!   (d 2).
//! - `lingering-owner`: the divesting simulation still reports the entity
//!   after `handover_window` (e 6). The `id-conflict` rule leaves this pair
//!   of senders to this rule.
//! - `attributes-changed`: the new owner's Entity Type or Marking differs
//!   from the last the old owner reported (e 7).
//! - `transferred-indicator`: the new owner's Entity States (v7) set the
//!   Transferred Entity Indicator (PDU Status bit 0) wrong: 1 when the
//!   Entity ID's site and application aren't its own, else 0 (e 5).
//! - `no-event-report`: no ownership Event Report (Event Type 17) from the
//!   new owner within TO_AUTO_RESPONSE_TIMER of completion (e 1).
//! - `stalled`: a transaction neither completed nor cancelled within
//!   TO_MAN_RESPONSE_TIMER; the simulation whose timer expired owes a
//!   Cancel TO (f 1 iii).

use crate::interactions::Finding;
use nn_decode::{EntityId, EntityState};
use nn_state::{EntityKey, EntityRecord, EntityTable};
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;

const TRANSFER_OWNERSHIP: u8 = 35;
const EVENT_REPORT: u8 = 21;
const ACKNOWLEDGE_R: u8 = 55;
/// Transfer Type (UID 224).
const PUSH: [u8; 2] = [1, 4];
const PULL: [u8; 4] = [2, 5, 8, 9];
const CANCEL: u8 = 7;
const UNACKNOWLEDGED: u8 = 1;
/// Acknowledge Flag Transfer Ownership (UID 69), Response Flag Unable to
/// Comply (UID 70), Event Type Ownership Report (UID 73).
const ACK_TRANSFER: u16 = 5;
const UNABLE: u16 = 2;
const OWNERSHIP_REPORT: u32 = 17;

type SimAddr = (u16, u16);

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

fn sim(id: EntityId) -> SimAddr {
    (id.site, id.application)
}

fn sim_name(s: SimAddr) -> String {
    format!("{}:{}", s.0, s.1)
}

/// The rule's waits, in seconds.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How long the old owner may keep reporting after the new one starts.
    pub handover: f64,
    /// TO_AUTO_RESPONSE_TIMER: the ownership Event Report.
    pub report: f64,
    /// TO_MAN_RESPONSE_TIMER: a transaction completes or is cancelled.
    pub stall: f64,
}

#[derive(Debug, Clone)]
struct Open {
    request_id: u32,
    divesting: SimAddr,
    acquiring: SimAddr,
    since: f64,
    /// Addresses the acquiring simulation sent this transaction's PDUs from.
    acquirer_addrs: BTreeSet<SocketAddr>,
    requester: SocketAddr,
}

#[derive(Debug, Clone)]
struct Done {
    at: f64,
    acquiring: SimAddr,
    old: BTreeSet<SocketAddr>,
    new: SocketAddr,
    report_due: Option<f64>,
    reported_linger: bool,
    reported_indicator: bool,
}

#[derive(Debug, Default)]
pub struct Transfers {
    open: HashMap<(u8, EntityId), Open>,
    done: HashMap<(u8, EntityId), Done>,
    last_tick: Option<f64>,
}

impl Transfers {
    /// TO, Acknowledge-R and Event Report PDUs' bytes.
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], table: &EntityTable) -> Vec<Finding> {
        let (Some(&exercise), Some(&pdu_type), Some(orig), Some(recv)) =
            (pdu.get(1), pdu.get(2), id_at(pdu, 12), id_at(pdu, 18))
        else {
            return Vec::new();
        };
        let mut out = Vec::new();
        match pdu_type {
            TRANSFER_OWNERSHIP => {
                let (Some(request_id), Some(&reliability), Some(&kind), Some(entity)) =
                    (u32_at(pdu, 24), pdu.get(28), pdu.get(29), id_at(pdu, 30))
                else {
                    return out;
                };
                let key = (exercise, entity);
                if kind == CANCEL {
                    self.open.remove(&key);
                    return out;
                }
                let (divesting, acquiring) = if PUSH.contains(&kind) {
                    (sim(orig), sim(recv))
                } else if PULL.contains(&kind) {
                    (sim(recv), sim(orig))
                } else {
                    return out;
                };
                let ekey = EntityKey { exercise, id: entity };
                let mut push = |kind: &'static str, message: String, facts: crate::engine::Facts| {
                    let mut f = vec![
                        ("entity", entity.to_string()),
                        ("divesting simulation", sim_name(divesting)),
                        ("acquiring simulation", sim_name(acquiring)),
                        ("Request ID", request_id.to_string()),
                    ];
                    f.extend(facts);
                    out.push(Finding {
                        kind,
                        key: ekey,
                        sender: source,
                        message,
                        facts: f,
                    });
                };
                if reliability != UNACKNOWLEDGED {
                    push(
                        "reliability",
                        format!(
                            "Transfer Ownership of {entity}: Required Reliability Service is {reliability}; transfers use Unacknowledged (1){}",
                            cite("5.9.4.2.1 a) 4)")
                        ),
                        vec![("required reliability service", reliability.to_string())],
                    );
                }
                if table.get(&ekey).is_some_and(|r| r.removed || r.deactivated()) {
                    push(
                        "inactive-entity",
                        format!(
                            "Transfer Ownership of {entity}, which isn't Active: only an Active entity may be transferred{}",
                            cite("5.9.4.2.1 d) 2)")
                        ),
                        vec![("entity state", "Deactivated or removed".into())],
                    );
                }
                match self.open.get_mut(&key) {
                    Some(o) if o.request_id == request_id && o.divesting == divesting && o.acquiring == acquiring => {
                        // A repeat of the same request.
                    }
                    Some(o) => {
                        let (other, since) = (o.acquiring, o.since);
                        push(
                            "concurrent",
                            format!(
                                "Transfer Ownership of {entity} to {} while its transfer to {} (since {:.0} s ago) is still open: one transfer per entity at a time{}",
                                sim_name(acquiring),
                                sim_name(other),
                                now - since,
                                cite("5.9.4.2.1 a) 23)")
                            ),
                            vec![("open transfer to", sim_name(other))],
                        );
                    }
                    None => {
                        let mut acquirer_addrs = BTreeSet::new();
                        if sim(orig) == acquiring {
                            acquirer_addrs.insert(source);
                        }
                        self.open.insert(
                            key,
                            Open {
                                request_id,
                                divesting,
                                acquiring,
                                since: now,
                                acquirer_addrs,
                                requester: source,
                            },
                        );
                    }
                }
            }
            ACKNOWLEDGE_R => {
                let (Some(flag), Some(response), Some(request_id)) =
                    (u16_at(pdu, 24), u16_at(pdu, 26), u32_at(pdu, 28))
                else {
                    return out;
                };
                if flag != ACK_TRANSFER {
                    return out;
                }
                let pair = |o: &Open| {
                    o.request_id == request_id
                        && [o.divesting, o.acquiring].contains(&sim(orig))
                        && [o.divesting, o.acquiring].contains(&sim(recv))
                };
                if response == UNABLE {
                    self.open.retain(|&(ex, _), o| ex != exercise || !pair(o));
                } else {
                    for ((ex, _), o) in self.open.iter_mut() {
                        if *ex == exercise && pair(o) && sim(orig) == o.acquiring {
                            o.acquirer_addrs.insert(source);
                        }
                    }
                }
            }
            EVENT_REPORT if u32_at(pdu, 24) == Some(OWNERSHIP_REPORT) => {
                for ((ex, _), d) in self.done.iter_mut() {
                    if *ex == exercise && (d.new == source || sim(orig) == d.acquiring) {
                        d.report_due = None;
                    }
                }
            }
            _ => {}
        }
        out
    }

    /// An Entity State, before it's applied (`rec` still holds the old
    /// owner's last report): completes a transfer, or checks after one.
    pub fn entity_state(
        &mut self,
        now: f64,
        source: SocketAddr,
        es: &EntityState,
        (exercise, version, status): (u8, u8, u8),
        rec: &EntityRecord,
        limits: &Limits,
    ) -> Vec<Finding> {
        let key = (exercise, es.entity_id);
        let ekey = EntityKey {
            exercise,
            id: es.entity_id,
        };
        let mut out = Vec::new();
        if let Some(o) = self.open.get(&key) {
            let from_acquirer = o.acquirer_addrs.contains(&source) || !rec.sources.contains_key(&source);
            if from_acquirer {
                let o = self.open.remove(&key).expect("just seen");
                let old: BTreeSet<SocketAddr> = rec.sources.keys().copied().filter(|s| *s != source).collect();
                let marking = es.marking.text();
                if rec.entity_type != es.entity_type || rec.marking != marking {
                    out.push(Finding {
                        kind: "attributes-changed",
                        key: ekey,
                        sender: source,
                        message: format!(
                            "{} changed hands to {}, which reports it as {} \"{marking}\"; the old owner reported {} \"{}\": the new owner keeps Entity Type and Marking{}",
                            es.entity_id,
                            sim_name(o.acquiring),
                            es.entity_type,
                            rec.entity_type,
                            rec.marking,
                            cite("5.9.4.2.1 e) 7)")
                        ),
                        facts: vec![
                            ("entity type", format!("{} (was {})", es.entity_type, rec.entity_type)),
                            ("marking", format!("\"{marking}\" (was \"{}\")", rec.marking)),
                            ("acquiring simulation", sim_name(o.acquiring)),
                        ],
                    });
                }
                self.done.insert(
                    key,
                    Done {
                        at: now,
                        acquiring: o.acquiring,
                        old,
                        new: source,
                        report_due: Some(now + limits.report),
                        reported_linger: false,
                        reported_indicator: false,
                    },
                );
            }
        }
        let Some(d) = self.done.get_mut(&key) else {
            return out;
        };
        if d.old.contains(&source) {
            if now - d.at > limits.handover && !d.reported_linger {
                d.reported_linger = true;
                out.push(Finding {
                    kind: "lingering-owner",
                    key: ekey,
                    sender: source,
                    message: format!(
                        "{} was transferred to {} {:.0} s ago, but its old owner ({source}) still reports it: the divesting simulation stops once the new owner's first Entity State is out{}",
                        es.entity_id,
                        sim_name(d.acquiring),
                        now - d.at,
                        cite("5.9.4.2.1 e) 6)")
                    ),
                    facts: vec![
                        ("entity", es.entity_id.to_string()),
                        ("old owner", source.to_string()),
                        ("new owner", d.new.to_string()),
                        ("transferred", format!("{:.0} s ago", now - d.at)),
                    ],
                });
            }
        } else if source == d.new && version >= 7 && !d.reported_indicator {
            let expected = sim(es.entity_id) != d.acquiring;
            if (status & 1 == 1) != expected {
                d.reported_indicator = true;
                out.push(Finding {
                    kind: "transferred-indicator",
                    key: ekey,
                    sender: source,
                    message: format!(
                        "{}'s new owner {} sets the Transferred Entity Indicator to {}; it is {} when the Entity ID's site and application {} its own{}",
                        es.entity_id,
                        sim_name(d.acquiring),
                        status & 1,
                        expected as u8,
                        if expected { "aren't" } else { "are" },
                        cite("5.9.4.2.1 e) 5)")
                    ),
                    facts: vec![
                        ("transferred entity indicator", (status & 1).to_string()),
                        ("expected", (expected as u8).to_string()),
                        ("acquiring simulation", sim_name(d.acquiring)),
                    ],
                });
            }
        }
        out
    }

    /// True when `a` and `b` are the old and new owners of a transfer of
    /// this entity: the `id-conflict` rule leaves them to this one.
    pub fn explains(&self, key: &EntityKey, a: SocketAddr, b: SocketAddr) -> bool {
        self.done
            .get(&(key.exercise, key.id))
            .is_some_and(|d| (d.new == a && d.old.contains(&b)) || (d.new == b && d.old.contains(&a)))
    }

    /// Overdue Event Reports and stalled transactions; forget old ones.
    pub fn expire(&mut self, now: f64, limits: &Limits, frozen: impl Fn(u8, EntityId) -> bool) -> Vec<Finding> {
        let dt = now - self.last_tick.unwrap_or(now);
        self.last_tick = Some(now);
        let mut out = Vec::new();
        self.open.retain(|&(exercise, entity), o| {
            if frozen(exercise, entity) {
                o.since += dt;
                return true;
            }
            if now - o.since < limits.stall {
                return true;
            }
            out.push(Finding {
                kind: "stalled",
                key: EntityKey { exercise, id: entity },
                sender: o.requester,
                message: format!(
                    "the transfer of {entity} from {} to {} (Request ID {}) neither completed nor was cancelled within {:.0} s: the simulation whose timer expired sends a Cancel TO{}",
                    sim_name(o.divesting),
                    sim_name(o.acquiring),
                    o.request_id,
                    limits.stall,
                    cite("5.9.4.2.1 f) 1) iii)")
                ),
                facts: vec![
                    ("entity", entity.to_string()),
                    ("divesting simulation", sim_name(o.divesting)),
                    ("acquiring simulation", sim_name(o.acquiring)),
                    ("waited", format!("{:.0} s", limits.stall)),
                ],
            });
            false
        });
        for (&(exercise, entity), d) in self.done.iter_mut() {
            if d.report_due.is_some_and(|due| now > due) {
                d.report_due = None;
                out.push(Finding {
                    kind: "no-event-report",
                    key: EntityKey { exercise, id: entity },
                    sender: d.new,
                    message: format!(
                        "{} took ownership of {entity} but sent no ownership Event Report within {:.0} s{}",
                        sim_name(d.acquiring),
                        limits.report,
                        cite("5.9.4.2.1 e) 1)")
                    ),
                    facts: vec![
                        ("entity", entity.to_string()),
                        ("acquiring simulation", sim_name(d.acquiring)),
                        ("waited", format!("{:.0} s", limits.report)),
                    ],
                });
            }
        }
        self.done.retain(|_, d| now - d.at < 600.0);
        out
    }
}
