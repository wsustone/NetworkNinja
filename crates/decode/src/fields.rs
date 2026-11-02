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

static FIELDS: [EnumField; 60] = [
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
    f(24, "designator.dead_reckoning_algorithm", 72, 1, 44),
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

/// An enumerated field that repeats inside a PDU's records (one per emitter
/// system or beam, say), so it has no single offset: `values` walks the PDU
/// body (the bytes after the header) and returns every occurrence, in order.
#[derive(Clone, Copy)]
pub struct RepeatedField {
    pub pdu_type: u8,
    /// Field path as rule packs write it, e.g. "electromagnetic-emission.beam_function".
    pub name: &'static str,
    pub uid: u16,
    pub values: fn(&[u8]) -> Vec<u64>,
}

impl std::fmt::Debug for RepeatedField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RepeatedField({})", self.name)
    }
}

/// EE (7.6.2) systems and beams, offsets within the body: each system's
/// 20-byte header (Emitter Name at 4, Function at 6), then its beams, 52
/// bytes plus 8 per Track/Jam target (Beam Function at 44, targets at 45).
/// Stops where the PDU does: tier S reports a short one.
fn ee_walk(body: &[u8], mut each: impl FnMut(Option<usize>, usize)) {
    const SYSTEMS_AT: usize = 28 - crate::HEADER_LEN;
    let Some(&n) = body.get(25 - crate::HEADER_LEN) else {
        return;
    };
    let mut at = SYSTEMS_AT;
    for _ in 0..n {
        let Some(&beams) = body.get(at + 1) else { return };
        if body.len() < at + 20 {
            return;
        }
        each(None, at);
        let mut b = at + 20;
        for _ in 0..beams {
            let Some(&targets) = body.get(b + 45) else { return };
            each(Some(b), at);
            b += 52 + 8 * targets as usize;
        }
        at = b;
    }
}

fn ee_emitter_names(body: &[u8]) -> Vec<u64> {
    let mut v = Vec::new();
    ee_walk(body, |beam, sys| {
        if beam.is_none() {
            v.push(u16::from_be_bytes([body[sys + 4], body[sys + 5]]) as u64);
        }
    });
    v
}

fn ee_emitter_functions(body: &[u8]) -> Vec<u64> {
    let mut v = Vec::new();
    ee_walk(body, |beam, sys| {
        if beam.is_none() {
            v.push(body[sys + 6] as u64);
        }
    });
    v
}

fn ee_beam_functions(body: &[u8]) -> Vec<u64> {
    let mut v = Vec::new();
    ee_walk(body, |beam, _| {
        if let Some(b) = beam {
            v.push(body[b + 44] as u64);
        }
    });
    v
}

static REPEATED: [RepeatedField; 3] = [
    RepeatedField {
        pdu_type: 23,
        name: "electromagnetic-emission.emitter_name",
        uid: 75,
        values: ee_emitter_names,
    },
    RepeatedField {
        pdu_type: 23,
        name: "electromagnetic-emission.emitter_function",
        uid: 76,
        values: ee_emitter_functions,
    },
    RepeatedField {
        pdu_type: 23,
        name: "electromagnetic-emission.beam_function",
        uid: 78,
        values: ee_beam_functions,
    },
];

/// Every repeated enumerated field.
pub fn repeated_fields() -> &'static [RepeatedField] {
    &REPEATED
}

/// The enumerated fields of one PDU type.
pub fn enum_fields_of(pdu_type: u8) -> impl Iterator<Item = &'static EnumField> {
    FIELDS.iter().filter(move |f| f.pdu_type == pdu_type)
}

#[cfg(test)]
mod repeated_tests {
    use super::*;

    /// One system: Emitter Name, Function, and (Beam Function, targets) per beam.
    type System<'a> = (u16, u8, &'a [(u8, u8)]);

    /// An EE body holding these systems.
    fn ee_body(systems: &[System]) -> Vec<u8> {
        let mut b = vec![0u8; 28 - crate::HEADER_LEN];
        b[25 - crate::HEADER_LEN] = systems.len() as u8;
        for (name, function, beams) in systems {
            let mut s = vec![0u8; 20];
            s[1] = beams.len() as u8;
            s[4..6].copy_from_slice(&name.to_be_bytes());
            s[6] = *function;
            for (beam_function, targets) in *beams {
                let mut r = vec![0u8; 52 + 8 * *targets as usize];
                r[44] = *beam_function;
                r[45] = *targets;
                s.extend(r);
            }
            b.extend(s);
        }
        b
    }

    #[test]
    fn ee_fields_are_read_from_every_system_and_beam() {
        let body = ee_body(&[(1800, 4, &[(4, 1), (1, 0)]), (2000, 2, &[(5, 0)])]);
        let get = |name: &str| {
            (repeated_fields()
                .iter()
                .find(|f| f.name.ends_with(name))
                .unwrap()
                .values)(&body)
        };
        assert_eq!(get("emitter_name"), [1800, 2000]);
        assert_eq!(get("emitter_function"), [4, 2]);
        assert_eq!(
            get("beam_function"),
            [4, 1, 5],
            "past the first beam's Track/Jam record"
        );
        // Cut short: what is there is read, nothing past the end.
        let short = &body[..body.len() - 10];
        assert_eq!(get_from(short, "emitter_name"), [1800, 2000]);
        assert_eq!(get_from(short, "beam_function"), [4, 1]);
    }

    fn get_from(body: &[u8], name: &str) -> Vec<u64> {
        (repeated_fields()
            .iter()
            .find(|f| f.name.ends_with(name))
            .unwrap()
            .values)(body)
    }
}
