//! Tier E (ADR 0010): enumerated fields checked against SISO-REF-010.
//!
//! CI uses `fixtures/siso-mini.xml`, a hand-made file in SISO's layout. Set
//! `NN_SISO` to a real SISO-REF-010.xml to also run the full-file checks.

use nn_capture::Datagram;
use nn_decode::*;
use nn_generator::{run, Config, Event, EventKind, Sender, Sink, Target};
use nn_rules::{AlertEvent, Merged, Monitor, RulePack, Siso};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

fn fixture() -> Siso {
    Siso::load(Path::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/siso-mini.xml"
    )))
    .unwrap()
}

fn monitor_with(siso: &Siso) -> Monitor {
    Monitor::with_packs(&Merged::load_with(Some(siso), &[] as &[&str]).unwrap())
}

fn datagram(bytes: Vec<u8>, at: f64) -> Datagram {
    Datagram {
        received_at: UNIX_EPOCH + Duration::from_secs_f64(1_800_000_000.0 + at),
        source: "10.0.1.10:40000".parse().unwrap(),
        destination: None,
        payload: bytes,
        monotonic: None,
        listener: None,
    }
}

/// A minimal PDU of `pdu_type` with `set` applied to its body.
fn pdu(pdu_type: u8, set: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut body = structure::minimal_body(pdu_type).unwrap();
    body[0..6].copy_from_slice(&[0, 1, 0, 1, 0, 9]);
    set(&mut body);
    encode_pdu(&Pdu {
        header: PduHeader::new(7, 1, pdu_type, DisTimestamp::default()),
        body: PduBody::Other(body),
    })
}

fn enum_alerts(events: &[AlertEvent]) -> Vec<(String, String)> {
    events
        .iter()
        .filter(|e| e.alert.rule == nn_rules::Rule::EnumViolation)
        .map(|e| (e.alert.rule_id.clone(), e.reason.clone()))
        .collect()
}

#[test]
fn parses_enums_ranges_and_entities_and_skips_cdata_and_bitfields() {
    let s = fixture();
    assert_eq!(
        (s.title.as_str(), s.version(), s.date.as_str()),
        ("SISO-REF-010-v99", 99, "2026-01-01")
    );
    assert_eq!(s.enums[&4].values, vec![0..=72]);
    assert_eq!(s.enums[&164].values, vec![0..=2]);
    assert_eq!(s.enums[&69].values, vec![1..=2]);
    assert!(s.enums[&500].values.is_empty());
    assert!(!s.enums.contains_key(&999) && !s.enums.contains_key(&68));
    assert!(Siso::parse("<ebv title=\"x\"></ebv>").is_err());
}

#[test]
fn undefined_value_in_a_raw_field_cites_its_uid() {
    let mut m = monitor_with(&fixture());
    let ok = pdu(25, |b| b[28 - 12] = 2);
    assert!(enum_alerts(&m.ingest(&datagram(ok, 0.0)).1).is_empty());
    let bad = pdu(25, |b| b[28 - 12] = 7);
    let v = enum_alerts(&m.ingest(&datagram(bad, 1.0)).1);
    assert_eq!(v.len(), 1, "{v:?}");
    assert_eq!(v[0].0, "transmitter.transmit_state");
    assert_eq!(
        v[0].1,
        "1:1:9 transmitter.transmit_state = 7 is not defined in SISO-REF-010 UID 164 (Transmitter-Transmit State)"
    );
}

#[test]
fn zero_is_not_always_defined() {
    // Acknowledge Flag starts at 1, so an all-zero Acknowledge is flagged.
    let mut m = monitor_with(&fixture());
    let zero = pdu(15, |_| {});
    assert_eq!(enum_alerts(&m.ingest(&datagram(zero, 0.0)).1).len(), 1);
}

#[test]
fn platform_category_is_checked_by_domain() {
    let mut m = monitor_with(&fixture());
    let es = |category: u8, domain: u8| {
        encode_pdu(&Pdu {
            header: PduHeader::new(7, 1, pdu_type::ENTITY_STATE, DisTimestamp::default()),
            body: PduBody::EntityState(EntityState {
                entity_id: EntityId::new(1, 1, 1),
                force_id: 1,
                entity_type: EntityType {
                    kind: 1,
                    domain,
                    country: 225,
                    category,
                    ..Default::default()
                },
                alternative_entity_type: EntityType::default(),
                linear_velocity: Vec3f::default(),
                location: WorldCoord::default(),
                orientation: EulerAngles::default(),
                appearance: 0,
                dead_reckoning: DeadReckoning {
                    algorithm: 2,
                    ..Default::default()
                },
                marking: Marking::ascii("T"),
                capabilities: 0,
                variable_parameters: Vec::new(),
            }),
        })
    };
    assert!(enum_alerts(&m.ingest(&datagram(es(3, 1), 0.0)).1).is_empty());
    let v = enum_alerts(&m.ingest(&datagram(es(9, 1), 1.0)).1);
    assert_eq!(
        v.iter().map(|x| x.0.as_str()).collect::<Vec<_>>(),
        ["entity-state.entity_type.land_category"]
    );
    // Category 9 in the air domain isn't judged by the land list (and the
    // fixture has no air list).
    assert!(enum_alerts(&m.ingest(&datagram(es(9, 2), 2.0)).1).is_empty());
}

#[test]
fn a_site_pack_can_widen_or_turn_off_a_siso_check() {
    let site =
        "[pack]\nid = \"site\"\nversion = 1\n\n[[enum]]\nfield = \"transmitter.transmit_state\"\nallowed = \"0-9\"\n";
    let layers = vec![
        RulePack::parse(include_str!("../../../rulepacks/dis-base.toml"), "base").unwrap(),
        fixture().pack(),
        RulePack::parse(site, "site").unwrap(),
    ];
    let mut m = Monitor::with_packs(&Merged::merge(layers));
    let bad = pdu(25, |b| b[28 - 12] = 7);
    assert!(enum_alerts(&m.ingest(&datagram(bad, 0.0)).1).is_empty());
}

#[test]
fn without_siso_raw_fields_are_not_checked() {
    let mut m = Monitor::with_packs(nn_rules::builtin_packs());
    let bad = pdu(25, |b| b[28 - 12] = 7);
    assert!(enum_alerts(&m.ingest(&datagram(bad, 0.0)).1).is_empty());
}

// ------------------------------------------------- generator traffic

struct Collect(Vec<Datagram>, std::time::SystemTime);

impl Sink for Collect {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        self.0.push(Datagram {
            received_at: self.1 + Duration::from_secs_f64(t),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, s.site as u8, s.host()), 40_000)),
            destination: None,
            payload: d.to_vec(),
            monotonic: None,
            listener: None,
        });
        Ok(())
    }
}

fn traffic(cfg: &Config) -> Vec<Datagram> {
    let mut sink = Collect(Vec::new(), cfg.start_time);
    run(cfg, &mut sink).unwrap();
    sink.0
}

fn all_types(events: Vec<Event>) -> Config {
    Config {
        duration: 30.0,
        all_types: Some(5.0),
        fire_every: Some(5.0),
        events,
        ..Default::default()
    }
}

fn check(siso: &Siso, cfg: &Config) -> Vec<AlertEvent> {
    let mut m = Monitor::with_packs(&Merged::load_with(Some(siso), &[] as &[&str]).unwrap());
    traffic(cfg).iter().flat_map(|d| m.ingest(d).1).collect()
}

fn bad_enum_on(pdu_type: u8) -> Event {
    Event {
        kind: EventKind::BadEnum,
        target: Target::Pdu { site: 1, pdu_type },
        at: 7.0,
    }
}

#[test]
fn generator_traffic_is_clean_and_bad_enum_is_caught() {
    let siso = fixture();
    let events = check(&siso, &all_types(vec![]));
    assert!(events.is_empty(), "{events:?}");
    let events = check(&siso, &all_types(vec![bad_enum_on(27)]));
    let v = enum_alerts(&events);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].1.contains("receiver.receiver_state = 65535") && v[0].1.contains("UID 179"));
}

/// With a real SISO-REF-010.xml (`NN_SISO=path`): every type the generator
/// sends, with each version and profile setting that changes enumerated
/// values, is clean; and a bad value is caught in every type with an
/// enumerated field.
#[test]
fn real_siso_file_when_given() {
    let Ok(path) = std::env::var("NN_SISO") else {
        eprintln!("NN_SISO not set; skipping the full SISO-REF-010 check");
        return;
    };
    let siso = Siso::load(Path::new(&path)).unwrap();
    for version in [6, 7] {
        for dr_algorithm in [2, 6] {
            let cfg = Config {
                version,
                dr_algorithm,
                ..all_types(vec![])
            };
            let events = check(&siso, &cfg);
            assert!(events.is_empty(), "v{version} DR {dr_algorithm}: {events:#?}");
        }
    }
    let types: std::collections::BTreeSet<u8> = fields::enum_fields().iter().map(|f| f.pdu_type).collect();
    for t in types {
        let v = enum_alerts(&check(&siso, &all_types(vec![bad_enum_on(t)])));
        assert_eq!(v.len(), 1, "type {t}: {v:?}");
    }
}
