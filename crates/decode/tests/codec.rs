use nn_decode::*;

fn header(version: u8, pdu_type: u8) -> PduHeader {
    PduHeader::new(version, 3, pdu_type, DisTimestamp::from_seconds_past_hour(12.5, true))
}

fn entity_state(n_params: usize) -> EntityState {
    EntityState {
        entity_id: EntityId::new(10, 20, 30),
        force_id: 1,
        entity_type: EntityType {
            kind: 1,
            domain: 1,
            country: 225,
            category: 1,
            subcategory: 1,
            specific: 3,
            extra: 0,
        },
        alternative_entity_type: EntityType::default(),
        linear_velocity: Vec3f {
            x: 1.0,
            y: -2.0,
            z: 3.5,
        },
        location: WorldCoord {
            x: -2_430_000.25,
            y: -4_700_000.5,
            z: 3_550_000.75,
        },
        orientation: EulerAngles {
            psi: 0.5,
            theta: -0.1,
            phi: 0.02,
        },
        appearance: appearance::FROZEN,
        dead_reckoning: DeadReckoning {
            algorithm: 2,
            other_parameters: [7; 15],
            linear_acceleration: Vec3f { x: 0.1, y: 0.2, z: 0.3 },
            angular_velocity: Vec3f::default(),
        },
        marking: Marking::ascii("TANK01"),
        capabilities: 0xdead_beef,
        variable_parameters: (0..n_params).map(|i| VariableParameter([i as u8; 16])).collect(),
    }
}

fn sample_pdus(version: u8) -> Vec<Pdu> {
    let eid = EntityId::new(1, 2, 3);
    let event = EventId {
        site: 1,
        application: 2,
        event_number: 99,
    };
    let burst = BurstDescriptor {
        munition_type: EntityType {
            kind: 2,
            domain: 2,
            country: 225,
            category: 1,
            ..Default::default()
        },
        warhead: 1000,
        fuse: 1000,
        quantity: 1,
        rate: 0,
    };
    vec![
        Pdu {
            header: header(version, 1),
            body: PduBody::EntityState(entity_state(0)),
        },
        Pdu {
            header: header(version, 1),
            body: PduBody::EntityState(entity_state(2)),
        },
        Pdu {
            header: header(version, 2),
            body: PduBody::Fire(Fire {
                firing_entity: eid,
                target_entity: EntityId::new(4, 5, 6),
                munition_id: EntityId::new(1, 2, 400),
                event_id: event,
                fire_mission_index: 7,
                location: WorldCoord { x: 1.0, y: 2.0, z: 3.0 },
                descriptor: burst,
                velocity: Vec3f {
                    x: 300.0,
                    y: 0.0,
                    z: 10.0,
                },
                range: 2500.0,
            }),
        },
        Pdu {
            header: header(version, 3),
            body: PduBody::Detonation(Detonation {
                firing_entity: eid,
                target_entity: EntityId::new(4, 5, 6),
                munition_id: EntityId::new(1, 2, 400),
                event_id: event,
                velocity: Vec3f {
                    x: 250.0,
                    y: 0.0,
                    z: -5.0,
                },
                location: WorldCoord { x: 4.0, y: 5.0, z: 6.0 },
                descriptor: burst,
                location_in_entity: Vec3f { x: 0.5, y: 0.0, z: 1.0 },
                result: 1,
                variable_parameters: vec![VariableParameter([9; 16])],
            }),
        },
        Pdu {
            header: header(version, 13),
            body: PduBody::StartResume(StartResume {
                originating: EntityId::new(1, 2, 0xffff),
                receiving: EntityId::new(0xffff, 0xffff, 0xffff),
                real_world_time: ClockTime {
                    hour: 493_000,
                    time_past_hour: 12345,
                },
                simulation_time: ClockTime {
                    hour: 0,
                    time_past_hour: 0,
                },
                request_id: 42,
            }),
        },
        Pdu {
            header: header(version, 14),
            body: PduBody::StopFreeze(StopFreeze {
                originating: EntityId::new(1, 2, 0xffff),
                receiving: EntityId::new(0xffff, 0xffff, 0xffff),
                real_world_time: ClockTime {
                    hour: 493_000,
                    time_past_hour: 99,
                },
                reason: 2,
                frozen_behavior: 1,
                request_id: 43,
            }),
        },
        Pdu {
            header: header(version, 12),
            body: PduBody::RemoveEntity(RemoveEntity {
                originating: EntityId::new(1, 2, 0xffff),
                receiving: EntityId::new(1, 2, 3),
                request_id: 44,
            }),
        },
        Pdu {
            header: header(version, 25),
            body: PduBody::Other(vec![1, 2, 3, 4, 5, 6, 7, 8]),
        },
    ]
}

/// Encode then decode, checking the result equals the input once the header
/// fields the encoder fills in (length, family) are accounted for.
fn roundtrip(pdu: &Pdu) -> Vec<u8> {
    let bytes = encode_pdu(pdu);
    let decoded = decode_pdu(&bytes).expect("decodes");
    let mut expected = pdu.clone();
    expected.header.length = bytes.len() as u16;
    expected.header.protocol_family = default_family(pdu.header.pdu_type);
    assert_eq!(decoded, expected);
    bytes
}

#[test]
fn every_sample_roundtrips_in_v6_and_v7() {
    for version in [6, 7] {
        for pdu in sample_pdus(version) {
            roundtrip(&pdu);
        }
    }
}

#[test]
fn encoded_sizes_match_the_standard() {
    let pdus = sample_pdus(7);
    let sizes: Vec<usize> = pdus.iter().map(|p| encode_pdu(p).len()).collect();
    assert_eq!(
        sizes,
        vec![
            ENTITY_STATE_LEN,
            ENTITY_STATE_LEN + 2 * VARIABLE_PARAM_LEN,
            FIRE_LEN,
            DETONATION_LEN + VARIABLE_PARAM_LEN,
            START_RESUME_LEN,
            STOP_FREEZE_LEN,
            REMOVE_ENTITY_LEN,
            HEADER_LEN + 8,
        ]
    );
}

#[test]
fn v6_header_ignores_status_byte() {
    let mut pdu = sample_pdus(6).remove(0);
    pdu.header.pdu_status = 0x55;
    let bytes = encode_pdu(&pdu);
    assert_eq!(bytes[10], 0);
    assert_eq!(decode_pdu(&bytes).unwrap().header.pdu_status, 0);

    let mut pdu7 = sample_pdus(7).remove(0);
    pdu7.header.pdu_status = 0x55;
    assert_eq!(decode_pdu(&encode_pdu(&pdu7)).unwrap().header.pdu_status, 0x55);
}

#[test]
fn datagram_with_several_pdus_splits_on_length() {
    let pdus = sample_pdus(7);
    let mut datagram = Vec::new();
    for p in &pdus {
        datagram.extend(encode_pdu(p));
    }
    datagram.extend([0u8; 6]); // trailing padding is ignored
    let decoded = decode_datagram(&datagram);
    assert_eq!(decoded.len(), pdus.len());
    assert!(decoded.iter().all(|r| r.is_ok()));
    let types: Vec<u8> = decoded.iter().map(|r| r.as_ref().unwrap().header.pdu_type).collect();
    assert_eq!(types, vec![1, 1, 2, 3, 13, 14, 12, 25]);
}

#[test]
fn truncated_and_inconsistent_pdus_are_errors() {
    let bytes = encode_pdu(&sample_pdus(7).remove(0));
    assert!(matches!(decode_pdu(&bytes[..100]), Err(DecodeError::Truncated { .. })));
    assert!(matches!(decode_pdu(&bytes[..5]), Err(DecodeError::Truncated { .. })));

    // Length field claims one articulation record that is not there.
    let mut wrong = bytes.clone();
    wrong[19] = 1; // number of variable parameters
    assert!(matches!(decode_pdu(&wrong), Err(DecodeError::LengthMismatch { .. })));

    // Length field below the header size.
    let mut tiny = bytes.clone();
    tiny[8..10].copy_from_slice(&4u16.to_be_bytes());
    assert!(matches!(decode_pdu(&tiny), Err(DecodeError::BadLength { length: 4 })));
    assert_eq!(decode_datagram(&tiny).len(), 1);
}

#[test]
fn bad_body_does_not_stop_the_next_pdu() {
    let good = encode_pdu(&sample_pdus(7).remove(6)); // RemoveEntity
                                                      // A Fire PDU 4 bytes short of its body, framed consistently.
    let mut odd = encode_pdu(&sample_pdus(7).remove(2));
    odd.truncate(odd.len() - 4);
    let l = odd.len() as u16;
    odd[8..10].copy_from_slice(&l.to_be_bytes());
    let mut datagram = odd;
    datagram.extend(&good);
    let out = decode_datagram(&datagram);
    assert_eq!(out.len(), 2);
    assert!(matches!(out[0], Err(DecodeError::LengthMismatch { .. })));
    assert!(out[1].is_ok());
}

#[test]
fn other_versions_are_kept_raw() {
    let mut pdu = sample_pdus(7).remove(0);
    pdu.header.protocol_version = 5;
    let decoded = decode_pdu(&encode_pdu(&pdu)).unwrap();
    assert!(matches!(decoded.body, PduBody::Other(ref b) if b.len() == ENTITY_STATE_LEN - HEADER_LEN));
}

#[test]
fn marking_text_and_entity_id_parsing() {
    assert_eq!(Marking::ascii("ALPHA-1").text(), "ALPHA-1");
    assert_eq!(Marking::ascii("A_VERY_LONG_MARKING").text(), "A_VERY_LONG");
    assert_eq!("1:2:3".parse::<EntityId>().unwrap(), EntityId::new(1, 2, 3));
    assert!("1:2".parse::<EntityId>().is_err());
    assert!("1:x:3".parse::<EntityId>().is_err());
}

/// Robustness: mutated and random input must never panic.
///
/// This is a deterministic stand-in for a cargo-fuzz run (not available in
/// every build environment): it flips bytes in valid PDUs, splices them, and
/// feeds pure noise, a few hundred thousand times.
#[test]
fn hostile_input_never_panics() {
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let valid: Vec<Vec<u8>> = [6, 7]
        .iter()
        .flat_map(|&v| sample_pdus(v))
        .map(|p| encode_pdu(&p))
        .collect();

    for i in 0..300_000u32 {
        let mut buf = match i % 3 {
            0 => valid[(next() as usize) % valid.len()].clone(),
            1 => {
                let mut b = valid[(next() as usize) % valid.len()].clone();
                b.extend(&valid[(next() as usize) % valid.len()]);
                b
            }
            _ => (0..(next() % 300) as usize).map(|_| next() as u8).collect(),
        };
        if !buf.is_empty() {
            for _ in 0..(next() % 6) {
                let idx = (next() as usize) % buf.len();
                buf[idx] = next() as u8;
            }
            if next() % 4 == 0 {
                let cut = (next() as usize) % buf.len();
                buf.truncate(cut);
            }
        }
        for pdu in decode_datagram(&buf).into_iter().flatten() {
            // Anything that decodes must re-encode to a decodable PDU.
            let again = encode_pdu(&pdu);
            assert!(decode_pdu(&again).is_ok());
        }
        let _ = decode_pdu(&buf);
    }
}

/// Some senders pad a PDU past its required size. The monitor should still
/// decode it (and let a rule pack flag the padding), not drop it: a dropped
/// Entity State later looks like a dead simulator.
#[test]
fn padded_entity_state_still_decodes() {
    let pdu = &sample_pdus(7)[0];
    let mut bytes = encode_pdu(pdu);
    bytes.extend_from_slice(&[0; 4]);
    let len = bytes.len() as u16;
    bytes[8..10].copy_from_slice(&len.to_be_bytes());
    let decoded = decode_pdu(&bytes).expect("padded Entity State should decode");
    assert!(matches!(decoded.body, PduBody::EntityState(_)));
}
