//! Heartbeats (IEEE 1278.1 4.2.7, Table 4): how often a simulation must
//! re-send a PDU type for an object that hasn't changed, so receivers can
//! tell a quiet object from a lost one. Defaults from the symbolic-name
//! table (6.1.8; draft D16r18). A receiver times an object out after its
//! heartbeat × HBT_TIMEOUT_MPLIER (2.4).
//!
//! Entity State (HBT_ESPDU_*, HBT_STATIONARY) and the radio PDUs
//! (HBT_PDU_TRANSMITTER, HBT_PDU_RECEIVER) are listed for reference: their
//! rules (entity-timeout, radio) apply them with type-specific logic.

/// One PDU type's heartbeat requirement.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Heartbeat {
    pub pdu_type: u8,
    /// The symbolic name of the heartbeat parameter.
    pub symbol: &'static str,
    /// Default heartbeat, seconds.
    pub seconds: f64,
    /// The issuance clause that requires it.
    pub clause: &'static str,
    /// Rule-pack key for overriding it in `[rules.heartbeat]`.
    pub key: &'static str,
    /// Applied by its own rule (entity-timeout, radio), not `heartbeat`.
    pub own_rule: bool,
}

/// HBT_TIMEOUT_MPLIER.
pub const TIMEOUT_MULTIPLIER: f64 = 2.4;

const fn hb(pdu_type: u8, symbol: &'static str, seconds: f64, clause: &'static str, key: &'static str) -> Heartbeat {
    Heartbeat {
        pdu_type,
        symbol,
        seconds,
        clause,
        key,
        own_rule: false,
    }
}

const fn own(h: Heartbeat) -> Heartbeat {
    Heartbeat { own_rule: true, ..h }
}

static TABLE: [Heartbeat; 18] = [
    own(hb(1, "HBT_ESPDU_*", 5.0, "5.3.2.3", "entity_state")),
    own(hb(67, "HBT_ESPDU_*", 5.0, "5.3.5.3", "entity_state_update")),
    own(hb(25, "HBT_PDU_TRANSMITTER", 2.0, "5.8.3.3", "transmitter")),
    own(hb(27, "HBT_PDU_RECEIVER", 5.0, "5.8.5.3", "receiver")),
    // Per emitter system, not per entity: rule `emission`.
    own(hb(23, "HBT_PDU_EE", 5.0, "5.7.3.3.2", "electromagnetic_emission")),
    hb(24, "HBT_PDU_DESIGNATOR", 5.0, "5.7.4.3", "designator"),
    hb(28, "HBT_PDU_IFF", 10.0, "5.7.6.3", "iff"),
    hb(29, "HBT_PDU_UA", 180.0, "5.7.5.3", "underwater_acoustic"),
    hb(30, "HBT_PDU_SEES", 180.0, "5.7.7.3", "sees"),
    hb(33, "HBT_PDU_AGGREGATE_STATE", 30.0, "5.9.2.2.3", "aggregate_state"),
    hb(34, "HBT_PDU_ISGROUPOF", 5.0, "5.9.3.4", "is_group_of"),
    hb(37, "HBT_PDU_MINEFIELD_STATE", 5.0, "5.10.2.3", "minefield_state"),
    hb(
        41,
        "HBT_PDU_ENVIRONMENTAL_PROCESS",
        15.0,
        "5.11.2.2.4",
        "environmental_process",
    ),
    hb(42, "HBT_PDU_GRIDDED_DATA", 900.0, "5.11.2.3.5", "gridded_data"),
    hb(46, "HBT_PDU_TSPI", 30.0, "9.4.2.3", "tspi"),
    hb(47, "HBT_PDU_APPEARANCE", 60.0, "9.4.3.3", "appearance"),
    hb(69, "HBT_PDU_ENTITY_DAMAGE", 10.0, "5.4.6.3", "entity_damage_status"),
    // Minefield Data heartbeats only in heartbeat mode; DE Fire only while
    // a shot is in progress: both need their families' rules (later).
    own(hb(68, "HBT_PDU_DE_FIRE", 0.5, "5.4.5.3", "de_fire")),
];

/// Every heartbeat requirement, in the order above.
pub fn table() -> &'static [Heartbeat] {
    &TABLE
}

/// The heartbeat requirement of a PDU type, if it has one.
pub fn of(pdu_type: u8) -> Option<&'static Heartbeat> {
    TABLE.iter().find(|h| h.pdu_type == pdu_type)
}

/// Does this PDU end the object's heartbeat obligation? A Designator with
/// Power 0 (designator off, 5.7.4.3) and an Entity Damage Status with no
/// damage records (damage repaired, 5.4.6.3 e) are final reports.
pub fn is_final(pdu: &[u8]) -> bool {
    match pdu.get(2) {
        Some(24) => pdu
            .get(28..32)
            .is_some_and(|b| f32::from_be_bytes([b[0], b[1], b[2], b[3]]) == 0.0),
        Some(69) => pdu.get(22..24).is_some_and(|b| b == [0, 0]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_type_appears_once_with_its_layout() {
        for h in table() {
            assert_eq!(table().iter().filter(|x| x.pdu_type == h.pdu_type).count(), 1);
            assert!(crate::structure::layout(h.pdu_type).is_some(), "{}", h.symbol);
            assert!(h.seconds > 0.0);
        }
        assert_eq!(of(23).unwrap().seconds, 5.0);
        assert!(of(2).is_none(), "Fire has no heartbeat");
    }
}
