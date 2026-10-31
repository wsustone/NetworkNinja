//! Attribute PDU (72) issuance rules (IEEE 1278.1 5.3.6.3, ADR 0010 Wave 1),
//! on raw bytes, one PDU at a time with its neighbours in the datagram: a
//! Coupled PDU Extension is a PDU with the PDU Status Coupled Extension
//! Indicator (bit 3, v7) set and its Attribute PDU immediately after it in
//! the same bundle.
//!
//! Findings, all point events of the `attribute` rule:
//! - `master-type`: a record's type differs from a Master Attribute Record
//!   Type other than MULTIPLES_PRESENT (0) (a 2 iii).
//! - `empty`: no Attribute Record Sets, or a set with no records (a 2 iv).
//! - `pdu-type`: the Attribute Record PDU Type isn't a PDU type, or the
//!   Protocol Version isn't a DIS version (a 2 i-ii).
//! - `self-coupled`: an Attribute PDU with its own CEI set (b 1 iv).
//! - `missing-extension`: a PDU with CEI set not followed by an Attribute
//!   PDU (b 1 ii-iii).
//! - `coupled-mismatch`: a coupled Attribute PDU whose PDU Type or Protocol
//!   Version differs from the PDU it extends (b 5).
//! - `uncoupled-transient`: an uncoupled Attribute PDU extending a transient
//!   PDU type; only state PDUs (those with a heartbeat) may be extended
//!   without coupling (b 2, b 3 i).

use nn_decode::EntityId;
use nn_state::EntityKey;
use std::net::SocketAddr;

pub const ATTRIBUTE: u8 = 72;
/// MULTIPLES_PRESENT (6.1.8).
pub const MULTIPLES_PRESENT: u32 = 0;
/// The PDU Status byte (after the 16-bit length), and its CEI bit.
const STATUS: usize = 10;
const CEI: u8 = 1 << 3;
/// The last assigned PDU type.
const LAST_PDU_TYPE: u8 = 72;

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub key: EntityKey,
    pub sender: SocketAddr,
    pub message: String,
}

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The CEI bit, where the PDU has one: v7, any type but Attribute.
fn coupled(pdu: &[u8]) -> bool {
    pdu.first().is_some_and(|&v| v >= 7)
        && pdu.get(2).is_some_and(|&t| t != ATTRIBUTE)
        && pdu.get(STATUS).is_some_and(|s| s & CEI != 0)
}

/// State PDUs, which may be extended without coupling: those with a
/// heartbeat (Entity State, EE, IFF, ...).
fn state_pdu(pdu_type: u8) -> bool {
    nn_decode::heartbeat::of(pdu_type).is_some()
}

/// Check one PDU of a datagram. `prev` and `next` are the PDUs either side
/// of it in the same datagram.
pub fn check(source: SocketAddr, pdu: &[u8], prev: Option<&[u8]>, next: Option<&[u8]>) -> Vec<Finding> {
    let (Some(&exercise), Some(&pdu_type)) = (pdu.get(1), pdu.get(2)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let id_of = |b: &[u8]| {
        EntityId::new(
            u16_at(b, 12).unwrap_or(0),
            u16_at(b, 14).unwrap_or(0),
            u16_at(b, 16).unwrap_or(0),
        )
    };
    let name = nn_decode::pdu_type_name(pdu_type);
    if pdu_type != ATTRIBUTE {
        if coupled(pdu) && next.and_then(|n| n.get(2)) != Some(&ATTRIBUTE) {
            out.push(Finding {
                kind: "missing-extension",
                key: EntityKey {
                    exercise,
                    id: id_of(pdu),
                },
                sender: source,
                message: format!(
                    "{}: {name} PDU says it is coupled (PDU Status CEI), but no Attribute PDU follows it in the bundle{}",
                    id_of(pdu),
                    cite("5.3.6.3 b)1)iii")
                ),
            });
        }
        return out;
    }
    // Originating Simulation Address: site, application.
    let origin = EntityId::new(u16_at(pdu, 12).unwrap_or(0), u16_at(pdu, 14).unwrap_or(0), 0);
    let key = EntityKey { exercise, id: origin };
    let mut finding = |kind, message: String| {
        out.push(Finding {
            kind,
            key,
            sender: source,
            message: format!("Attribute PDU from {}:{}: {message}", origin.site, origin.application),
        })
    };
    let (Some(&for_type), Some(&for_version), Some(master), Some(sets)) =
        (pdu.get(22), pdu.get(23), u32_at(pdu, 24), u16_at(pdu, 30))
    else {
        return out;
    };
    if pdu.get(STATUS).is_some_and(|s| s & CEI != 0) && pdu[0] >= 7 {
        finding(
            "self-coupled",
            format!(
                "its own PDU Status CEI is set; an Attribute PDU can't be extended{}",
                cite("5.3.6.3 b)1)iv")
            ),
        );
    }
    if for_type > LAST_PDU_TYPE {
        finding(
            "pdu-type",
            format!(
                "Attribute Record PDU Type {for_type} is not a PDU type (0 = Other){}",
                cite("5.3.6.3 a)2)i")
            ),
        );
    } else if for_type != 0 && !(1..=7).contains(&for_version) {
        finding(
            "pdu-type",
            format!(
                "Attribute Record Protocol Version {for_version} is not a DIS version{}",
                cite("5.3.6.3 a)2)ii")
            ),
        );
    }
    match prev.filter(|p| coupled(p)) {
        Some(p) => {
            let (t, v) = (p[2], p[0]);
            if for_type != t || for_version != v {
                finding(
                    "coupled-mismatch",
                    format!(
                        "it extends the {} PDU before it (version {v}), but says PDU Type {for_type}, version {for_version}{}",
                        nn_decode::pdu_type_name(t),
                        cite("5.3.6.3 b)5)")
                    ),
                );
            }
        }
        None if for_type != 0 && for_type <= LAST_PDU_TYPE && !state_pdu(for_type) => finding(
            "uncoupled-transient",
            format!(
                "it extends {} PDUs, a transient type, without Coupled PDU Extension{}",
                nn_decode::pdu_type_name(for_type),
                cite("5.3.6.3 b)3)i")
            ),
        ),
        None => {}
    }
    if sets == 0 {
        finding("empty", format!("no Attribute Record Sets{}", cite("5.3.6.3 a)2)iv")));
    }
    // Record sets: Entity ID (6), record count (2), then records, each a
    // type (4) and a length (2) covering the whole record.
    let mut at = 32;
    let mut wrong = None;
    for _ in 0..sets {
        let (Some(n), Some(entity)) = (u16_at(pdu, at + 6), u16_at(pdu, at + 4)) else {
            break;
        };
        let set_id = format!(
            "{}:{}:{entity}",
            u16_at(pdu, at).unwrap_or(0),
            u16_at(pdu, at + 2).unwrap_or(0)
        );
        at += 8;
        if n == 0 {
            finding(
                "empty",
                format!("record set for {set_id} holds no records{}", cite("5.3.6.3 a)2)iv")),
            );
        }
        for _ in 0..n {
            let (Some(rtype), Some(len)) = (u32_at(pdu, at), u16_at(pdu, at + 4)) else {
                return out;
            };
            if master != MULTIPLES_PRESENT && rtype != master && wrong.is_none() {
                wrong = Some(rtype);
            }
            if len < 6 {
                // Tier S reports the bad length; stop walking.
                return out;
            }
            at += len as usize;
        }
    }
    if let Some(rtype) = wrong {
        finding(
            "master-type",
            format!(
                "Master Attribute Record Type {master}, but a record has type {rtype}; use MULTIPLES_PRESENT (0) for mixed types{}",
                cite("5.3.6.3 a)2)iii")
            ),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    /// A v7 PDU of `pdu_type` with `status`, 24 bytes.
    fn plain(pdu_type: u8, status: u8) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[0] = 7;
        b[1] = 1;
        b[2] = pdu_type;
        b[STATUS] = status;
        b
    }

    /// An Attribute PDU extending `for_type`, master type `master`, one set
    /// per entry of `sets` holding records of those types.
    fn attribute(for_type: u8, master: u32, sets: &[&[u32]]) -> Vec<u8> {
        let mut b = plain(ATTRIBUTE, 0);
        b.resize(32, 0);
        b[12..16].copy_from_slice(&[0, 1, 0, 1]);
        b[22] = for_type;
        b[23] = 7;
        b[24..28].copy_from_slice(&master.to_be_bytes());
        b[30..32].copy_from_slice(&(sets.len() as u16).to_be_bytes());
        for records in sets {
            b.extend([0, 1, 0, 1, 0, 9]);
            b.extend((records.len() as u16).to_be_bytes());
            for t in *records {
                b.extend(t.to_be_bytes());
                b.extend(8u16.to_be_bytes());
                b.extend([0, 0]);
            }
        }
        b
    }

    #[test]
    fn well_formed_extensions_are_silent() {
        // Non-coupled, extending a state PDU (EE), one record type.
        assert!(check(src(), &attribute(23, 3500, &[&[3500, 3500]]), None, None).is_empty());
        // Mixed types under MULTIPLES_PRESENT.
        assert!(check(src(), &attribute(23, 0, &[&[3500], &[3501]]), None, None).is_empty());
        // Coupled to a Fire: the Fire has CEI set and the Attribute follows.
        let fire = plain(2, CEI);
        let a = attribute(2, 3500, &[&[3500]]);
        assert!(check(src(), &fire, None, Some(&a)).is_empty());
        assert!(check(src(), &a, Some(&fire), None).is_empty());
        // Other attributes (PDU Type 0) pertain to no PDU.
        assert!(check(src(), &attribute(0, 0, &[&[3500]]), None, None).is_empty());
    }

    #[test]
    fn each_rule_is_named() {
        assert_eq!(
            kinds(&check(src(), &attribute(23, 3500, &[&[3500, 3501]]), None, None)),
            ["master-type"]
        );
        assert_eq!(kinds(&check(src(), &attribute(23, 3500, &[]), None, None)), ["empty"]);
        assert_eq!(
            kinds(&check(src(), &attribute(23, 3500, &[&[]]), None, None)),
            ["empty"]
        );
        assert_eq!(
            kinds(&check(src(), &attribute(99, 3500, &[&[3500]]), None, None)),
            ["pdu-type"]
        );
        // Extending a Fire without coupling.
        assert_eq!(
            kinds(&check(src(), &attribute(2, 3500, &[&[3500]]), None, None)),
            ["uncoupled-transient"]
        );
        // A coupled Fire with nothing after it, or a Detonation after it.
        let fire = plain(2, CEI);
        assert_eq!(kinds(&check(src(), &fire, None, None)), ["missing-extension"]);
        assert_eq!(
            kinds(&check(src(), &fire, None, Some(&plain(3, 0)))),
            ["missing-extension"]
        );
        // Coupled to a Fire, but says Detonation.
        assert_eq!(
            kinds(&check(src(), &attribute(3, 3500, &[&[3500]]), Some(&fire), None)),
            ["coupled-mismatch"]
        );
        let mut own = attribute(23, 3500, &[&[3500]]);
        own[STATUS] = CEI;
        assert_eq!(kinds(&check(src(), &own, None, None)), ["self-coupled"]);
        // v6 has no PDU Status: the bit is padding.
        let mut v6 = plain(2, CEI);
        v6[0] = 6;
        assert!(check(src(), &v6, None, None).is_empty());
    }
}
