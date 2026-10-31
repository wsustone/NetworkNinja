//! Enumerated fields at fixed offsets in the PDU types that aren't deep
//! decoded (ADR 0010 tier E), each tied to the SISO-REF-010 enumeration
//! (UID) that defines its values.
//!
//! The UIDs are the ones IEEE P1278.1/D16 Rev 18 cites for each field
//! (`[UID n]` in clause 7); offsets are bytes from the PDU start, header
//! included, and follow the layouts in [`crate::structure`]. Bitfield
//! records (Frozen Behavior, appearances, Modifications) are not here: they
//! are SISO bitfields, not enumerations.

/// One enumerated field of a PDU type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnumField {
    pub pdu_type: u8,
    /// Field path as rule packs write it, e.g. "transmitter.transmit_state".
    pub name: &'static str,
    pub offset: usize,
    /// Width in bytes: 1, 2 or 4.
    pub width: u8,
    /// The SISO-REF-010 enumeration that defines the field's values.
    pub uid: u16,
    /// A value defined in SISO-REF-010 (v37), for building valid PDUs.
    /// Mostly 0 ("Other"), but some enumerations don't define 0, and some
    /// fields need a particular value for the PDU to make sense.
    pub valid: u32,
}

impl EnumField {
    /// The field's value in a PDU's bytes, if they reach it.
    pub fn read(&self, pdu: &[u8]) -> Option<u64> {
        let b = pdu.get(self.offset..self.offset + self.width as usize)?;
        Some(b.iter().fold(0u64, |v, &x| v << 8 | x as u64))
    }

    /// The field's value in a PDU body (the bytes after the header).
    pub fn read_body(&self, body: &[u8]) -> Option<u64> {
        let at = self.offset.checked_sub(crate::HEADER_LEN)?;
        let b = body.get(at..at + self.width as usize)?;
        Some(b.iter().fold(0u64, |v, &x| v << 8 | x as u64))
    }

    /// Write `value` into a PDU's bytes (or a body: pass `base` = 12).
    pub fn write(&self, buf: &mut [u8], base: usize, value: u32) {
        let at = self.offset - base;
        let w = self.width as usize;
        buf[at..at + w].copy_from_slice(&value.to_be_bytes()[4 - w..]);
    }
}

const fn f(pdu_type: u8, name: &'static str, offset: usize, width: u8, uid: u16) -> EnumField {
    EnumField {
        pdu_type,
        name,
        offset,
        width,
        uid,
        valid: 0,
    }
}

const fn v(field: EnumField, valid: u32) -> EnumField {
    EnumField { valid, ..field }
}

static FIELDS: [EnumField; 59] = [
    f(4, "collision.collision_type", 30, 1, 189),
    f(5, "service-request.service_type", 24, 1, 63),
    f(9, "repair-complete.repair", 24, 2, 64),
    f(10, "repair-response.repair_result", 24, 1, 65),
    v(f(15, "acknowledge.acknowledge_flag", 24, 2, 69), 1),
    f(15, "acknowledge.response_flag", 26, 2, 70),
    f(16, "action-request.action_id", 28, 4, 71),
    f(17, "action-response.request_status", 28, 4, 72),
    f(21, "event-report.event_type", 24, 4, 73),
    f(23, "electromagnetic-emission.state_update_indicator", 24, 1, 77),
    f(24, "designator.code_name", 18, 2, 80),
    f(24, "designator.designator_code", 26, 2, 81),
    // On and transmitting: the minimal Signal PDU that follows belongs to it.
    v(f(25, "transmitter.transmit_state", 28, 1, 164), 2),
    f(25, "transmitter.input_source", 29, 1, 165),
    f(25, "transmitter.antenna_pattern_type", 68, 2, 167),
    f(25, "transmitter.major_modulation", 90, 2, 155),
    f(25, "transmitter.modulation_system", 94, 2, 163),
    f(25, "transmitter.crypto_system", 96, 2, 166),
    f(27, "receiver.receiver_state", 20, 2, 179),
    f(29, "underwater-acoustic.state_update_indicator", 24, 1, 143),
    f(32, "intercom-control.control_type", 12, 1, 180),
    f(32, "intercom-control.transmit_line_state", 24, 1, 183),
    f(32, "intercom-control.command", 25, 1, 182),
    f(33, "aggregate-state.force_id", 18, 1, 6),
    f(33, "aggregate-state.aggregate_state", 19, 1, 204),
    f(33, "aggregate-state.formation", 28, 4, 205),
    f(34, "is-group-of.grouped_entity_category", 18, 1, 213),
    f(35, "transfer-ownership.required_reliability_service", 28, 1, 74),
    f(35, "transfer-ownership.transfer_type", 29, 1, 224),
    f(37, "minefield-state.force_id", 20, 1, 6),
    f(41, "environmental-process.model_type", 26, 1, 248),
    f(42, "gridded-data.coordinate_system", 24, 2, 244),
    f(42, "gridded-data.constant_grid", 27, 1, 245),
    f(43, "point-object-state.force_id", 26, 1, 6),
    f(44, "linear-object-state.force_id", 26, 1, 6),
    f(45, "areal-object-state.force_id", 26, 1, 6),
    f(51, "create-entity-r.required_reliability_service", 24, 1, 74),
    f(52, "remove-entity-r.required_reliability_service", 24, 1, 74),
    f(53, "start-resume-r.required_reliability_service", 40, 1, 74),
    f(54, "stop-freeze-r.reason", 32, 1, 67),
    f(54, "stop-freeze-r.required_reliability_service", 34, 1, 74),
    v(f(55, "acknowledge-r.acknowledge_flag", 24, 2, 69), 1),
    f(55, "acknowledge-r.response_flag", 26, 2, 70),
    f(56, "action-request-r.required_reliability_service", 24, 1, 74),
    f(56, "action-request-r.action_id", 32, 4, 71),
    f(57, "action-response-r.request_status", 28, 4, 72),
    f(58, "data-query-r.required_reliability_service", 24, 1, 74),
    f(59, "set-data-r.required_reliability_service", 24, 1, 74),
    f(60, "data-r.required_reliability_service", 28, 1, 74),
    f(61, "event-report-r.event_type", 24, 4, 73),
    f(63, "record-r.required_reliability_service", 28, 1, 74),
    f(63, "record-r.event_type", 30, 2, 333),
    f(64, "set-record-r.required_reliability_service", 28, 1, 74),
    f(65, "record-query-r.required_reliability_service", 28, 1, 74),
    f(65, "record-query-r.event_type", 30, 2, 334),
    f(68, "directed-energy-fire.pulse_shape", 78, 1, 312),
    f(70, "io-action.io_warfare_type", 28, 2, 285),
    f(70, "io-action.io_action_type", 32, 2, 287),
    f(71, "io-report.io_report_type", 20, 1, 289),
];

/// Every enumerated field in the table, in PDU Type order.
pub fn enum_fields() -> &'static [EnumField] {
    &FIELDS
}

/// The enumerated fields of one PDU type.
pub fn enum_fields_of(pdu_type: u8) -> impl Iterator<Item = &'static EnumField> {
    FIELDS.iter().filter(move |f| f.pdu_type == pdu_type)
}
