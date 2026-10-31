//! Tier S structure checks (ADR 0010): every type's smallest valid PDU is
//! clean, and each kind of structural defect is reported as itself.

use nn_decode::structure::{check, layout, layouts, minimal_body, Finding};
use nn_decode::*;

/// A PDU of `pdu_type` with `body` after a standard header; the length
/// field covers the body.
fn pdu(version: u8, pdu_type: u8, body: Vec<u8>) -> Vec<u8> {
    encode_pdu(&Pdu {
        header: PduHeader::new(version, 1, pdu_type, DisTimestamp::default()),
        body: PduBody::Other(body),
    })
}

fn findings(buf: &[u8]) -> Vec<Finding> {
    check(buf).findings
}

fn body(pdu_type: u8) -> Vec<u8> {
    minimal_body(pdu_type).unwrap()
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at - 12..at - 10].copy_from_slice(&v.to_be_bytes());
}

fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at - 12..at - 8].copy_from_slice(&v.to_be_bytes());
}

#[test]
fn table_covers_all_72_types_in_order() {
    assert_eq!(layouts().len(), 72);
    for (i, l) in layouts().iter().enumerate() {
        assert_eq!(l.pdu_type as usize, i + 1);
        assert!(l.fixed >= 12 && l.family >= 1 && l.family <= 13, "{}", l.name);
        for &(at, width) in l.counts {
            assert!(at + width as usize <= l.fixed, "{} count at {at}", l.name);
        }
    }
    assert!(layout(0).is_none() && layout(73).is_none() && layout(200).is_none());
    assert_eq!(pdu_type_name(22), "Comment");
    assert_eq!(pdu_type_name(21), "EventReport");
    assert_eq!(default_family(25), 4);
}

#[test]
fn smallest_valid_pdu_of_every_type_is_clean() {
    for l in layouts() {
        for version in [6, 7] {
            let p = pdu(version, l.pdu_type, body(l.pdu_type));
            assert_eq!(findings(&p), vec![], "{} v{version}", l.name);
        }
    }
    // Alignment padding is part of the minimum.
    assert_eq!(body(40).len() + 12, 28);
}

#[test]
fn deep_decoded_types_agree_with_the_decoder() {
    for t in [1, 2, 3, 12, 13, 14] {
        let p = pdu(7, t, body(t));
        assert!(decode_pdu(&p).is_ok(), "{}", pdu_type_name(t));
    }
}

#[test]
fn count_without_its_records_is_short() {
    let mut b = body(1);
    b[19 - 12] = 2; // two variable parameters, none present
    assert_eq!(
        findings(&pdu(7, 1, b.clone())),
        vec![Finding::Short {
            needed: 176,
            length: 144
        }]
    );
    b.extend([0; 32]);
    assert_eq!(findings(&pdu(7, 1, b)), vec![]);
}

#[test]
fn missing_fixed_bytes_are_short_and_extra_bytes_padded() {
    let mut b = body(4);
    b.truncate(b.len() - 4);
    assert_eq!(findings(&pdu(7, 4, b)), vec![Finding::Short { needed: 60, length: 56 }]);
    let mut b = body(4);
    b.extend([0; 8]);
    assert_eq!(
        findings(&pdu(7, 4, b)),
        vec![Finding::Padded { needed: 60, length: 68 }]
    );
}

#[test]
fn framing_errors() {
    let p = pdu(7, 4, body(4));
    assert_eq!(
        findings(&p[..50]),
        vec![Finding::Truncated {
            length: 60,
            available: 50
        }]
    );
    assert_eq!(findings(&p[..8]), vec![Finding::HeaderTruncated { available: 8 }]);
    let mut bad = p.clone();
    bad[8..10].copy_from_slice(&4u16.to_be_bytes());
    assert_eq!(findings(&bad), vec![Finding::BadLength { length: 4 }]);
}

#[test]
fn wrong_family_is_reported() {
    let mut p = pdu(7, 25, body(25));
    p[3] = 5;
    assert_eq!(findings(&p), vec![Finding::Family { family: 5, expected: 4 }]);
    let f = &findings(&p)[0];
    assert_eq!(f.rule(), "pdu-family");
}

#[test]
fn v6_checks_only_the_1995_types() {
    // Type 37 is checked on v7 but not v6, whose layouts aren't verified yet.
    let mut b = body(37);
    b.truncate(b.len() - 8);
    assert!(!findings(&pdu(7, 37, b.clone())).is_empty());
    assert_eq!(findings(&pdu(6, 37, b)), vec![]);
}

#[test]
fn variable_datums_pad_to_64_bits() {
    // Comment: one variable datum of 12 bits = 8 + 8 bytes.
    let mut b = body(22);
    put_u32(&mut b, 28, 1);
    b.extend([0, 0, 0, 1, 0, 0, 0, 12, 0xab, 0xc0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(findings(&pdu(7, 22, b.clone())), vec![]);
    b.truncate(b.len() - 4);
    assert_eq!(
        findings(&pdu(7, 22, b)),
        vec![Finding::Short { needed: 48, length: 44 }]
    );
}

#[test]
fn emission_lengths_must_match_contents() {
    // EE: one system, one beam, one track/jam target.
    let mut b = body(23);
    b[25 - 12] = 1;
    let mut system = vec![0u8; 20];
    system[0] = 20; // (20 + 52 + 8) / 4 words
    system[1] = 1;
    let mut beam = vec![0u8; 52];
    beam[0] = 15; // (52 + 8) / 4
    beam[45] = 1;
    b.extend(system);
    b.extend(beam);
    b.extend([0; 8]);
    assert_eq!(findings(&pdu(7, 23, b.clone())), vec![]);
    b[28 - 12] = 19;
    assert_eq!(
        findings(&pdu(7, 23, b)),
        vec![Finding::Inconsistent {
            field: "System Data Length",
            declared: 19,
            expected: 20
        }]
    );
}

#[test]
fn signal_data_without_padding_is_a_padding_finding() {
    // 5 bytes of data pad to 8.
    let mut b = body(26);
    put_u16(&mut b, 28, 40);
    b.extend([1; 8]);
    assert_eq!(findings(&pdu(7, 26, b.clone())), vec![]);
    b.truncate(b.len() - 3);
    let f = findings(&pdu(7, 26, b));
    assert_eq!(f, vec![Finding::Unpadded { needed: 40, length: 37 }]);
    assert_eq!(f[0].rule(), "pdu-padding");
}

#[test]
fn transmitter_counts_modulation_antenna_and_records() {
    let mut b = body(25);
    put_u16(&mut b, 30, 1); // one variable transmitter parameter record
    b[100 - 12] = 16; // modulation parameters
    b.extend([0; 16]);
    b.extend([0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(findings(&pdu(7, 25, b.clone())), vec![]);
    let n = b.len();
    b[n - 11] = 2; // record length below its own header
    assert_eq!(
        findings(&pdu(7, 25, b)),
        vec![Finding::Inconsistent {
            field: "Variable Transmitter Parameters Record Length",
            declared: 2,
            expected: 6
        }]
    );
}

#[test]
fn live_entity_flags_select_optional_fields() {
    let mut b = body(47);
    b[16 - 12] = 1 << 3; // marking present
    assert!(!findings(&pdu(7, 47, b.clone())).is_empty());
    b.extend([0; 12]);
    assert_eq!(findings(&pdu(7, 47, b)), vec![]);
    // The entity is the 32-bit live entity ID.
    let mut b = body(48);
    b[0] = 3;
    b[1] = 4;
    b[3] = 9;
    assert_eq!(check(&pdu(7, 48, b)).entity, Some(EntityId::new(3, 4, 9)));
}

#[test]
fn minefield_data_follows_its_filter() {
    // Two mines, one sensor type, scalar detection coefficients present.
    let mut b = body(39);
    b[29 - 12] = 2;
    b[30 - 12] = 1;
    put_u32(&mut b, 32, 1 << 9);
    // sensors 2 + pad 2, locations 24, entity numbers 4 + coefficients 2 + pad 2
    b.extend([0; 36]);
    assert_eq!(findings(&pdu(7, 39, b)), vec![]);
}

#[test]
fn linear_object_counts_its_segments() {
    let mut b = body(44);
    b[27 - 12] = 1;
    b.extend([0; 64]);
    assert_eq!(findings(&pdu(7, 44, b)), vec![]);
}

#[test]
fn enum_fields_lie_inside_their_fixed_layouts() {
    use nn_decode::fields::enum_fields;
    for f in enum_fields() {
        let l = layout(f.pdu_type).unwrap();
        assert!(f.offset >= 12 && f.offset + f.width as usize <= l.fixed, "{}", f.name);
        // Not on top of a count field.
        for &(at, w) in l.counts {
            assert!(
                f.offset + f.width as usize <= at || at + w as usize <= f.offset,
                "{}",
                f.name
            );
        }
    }
}
