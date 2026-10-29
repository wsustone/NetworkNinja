//! Rule packs: the base pack parses, packs layer and validate, enum checks
//! fire on bad values (deduplicated), and clean generator traffic passes
//! every check.

use nn_capture::Datagram;
use nn_decode::{encode_pdu, pdu_type, DisTimestamp, EntityId, EntityState, Pdu, PduBody, PduHeader};
use nn_generator::{run, Config, Sender, Sink};
use nn_rules::{AlertState, Merged, Monitor, Rule, RuleConfig, RulePack, Severity};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

fn base() -> RulePack {
    RulePack::parse(include_str!("../../../rulepacks/dis-base.toml"), "<builtin>").unwrap()
}

fn datagram(pdu: &Pdu, t: f64) -> Datagram {
    Datagram {
        received_at: SystemTime::UNIX_EPOCH + Duration::from_secs_f64(1_800_000_000.0 + t),
        source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000)),
        destination: None,
        payload: encode_pdu(pdu),
    }
}

fn entity_state(force_id: u8) -> Pdu {
    Pdu {
        header: PduHeader::new(7, 1, pdu_type::ENTITY_STATE, DisTimestamp::default()),
        body: PduBody::EntityState(EntityState {
            entity_id: EntityId::new(1, 1, 1),
            force_id,
            entity_type: Default::default(),
            alternative_entity_type: Default::default(),
            linear_velocity: Default::default(),
            location: Default::default(),
            orientation: Default::default(),
            appearance: 0,
            dead_reckoning: Default::default(),
            marking: Default::default(),
            capabilities: 0,
            variable_parameters: Vec::new(),
        }),
    }
}

#[test]
fn builtin_pack_parses() {
    let m = Merged::builtin().unwrap();
    assert_eq!(m.packs, vec!["dis-base v1".to_string()]);
    assert!(!m.enum_checks.is_empty());
    assert_eq!(m.config.heartbeat, 5.0);
    assert_eq!(m.config.timeout_multiplier, 2.4);
    assert!(m.enabled.values().all(|e| *e));
    assert_eq!(m.severities[&Rule::IdConflict], Severity::Critical);
}

#[test]
fn enum_violation_fires_then_suppresses_repeats() {
    let mut m = Monitor::new(RuleConfig::default());
    let pdu = entity_state(200);

    let events = m.ingest(&datagram(&pdu, 0.0)).1;
    let v: Vec<_> = events.iter().filter(|e| e.alert.rule == Rule::EnumViolation).collect();
    assert_eq!(v.len(), 1, "expected exactly one violation: {events:?}");
    assert_eq!(v[0].alert.rule_id, "entity-state.force_id");
    assert_eq!(v[0].alert.pack, "dis-base");
    assert_eq!(v[0].alert.key.id, EntityId::new(1, 1, 1));
    assert_eq!(v[0].state, AlertState::Firing);

    // Same violation inside the repeat window stays quiet.
    let events = m.ingest(&datagram(&pdu, 5.0)).1;
    assert!(events.iter().all(|e| e.alert.rule != Rule::EnumViolation));

    // After it, the still-bad value reports again.
    let events = m.ingest(&datagram(&pdu, 61.0)).1;
    assert_eq!(events.iter().filter(|e| e.alert.rule == Rule::EnumViolation).count(), 1);
}

#[test]
fn unknown_pdu_type_flags_the_header() {
    let mut m = Monitor::new(RuleConfig::default());
    let pdu = Pdu {
        header: PduHeader::new(7, 1, 200, DisTimestamp::default()),
        body: PduBody::Other(vec![0; 8]),
    };
    let events = m.ingest(&datagram(&pdu, 0.0)).1;
    let v: Vec<_> = events.iter().filter(|e| e.alert.rule == Rule::EnumViolation).collect();
    assert_eq!(v.len(), 1, "expected exactly one violation: {events:?}");
    assert_eq!(v[0].alert.rule_id, "header.pdu_type");
}

const OVERLAY: &str = r#"
[pack]
id = "site-alpha"
version = 2

[rules.entity-timeout]
timeout_multiplier = 4.0

[rules.id-conflict]
enabled = false

[[enum]]
field = "entity-state.force_id"
allowed = "0-8"
severity = "critical"

[[enum]]
field = "entity-state.marking.character_set"
severity = "off"
"#;

#[test]
fn layering_overrides_thresholds_checks_and_toggles() {
    let m = Merged::merge(vec![base(), RulePack::parse(OVERLAY, "test").unwrap()]);
    assert_eq!(m.packs, ["dis-base v1", "site-alpha v2"]);
    assert_eq!(m.config.timeout_multiplier, 4.0);
    assert_eq!(m.config.heartbeat, 5.0, "untouched thresholds keep the base value");
    assert_eq!(m.enabled.get(&Rule::IdConflict), Some(&false));
    assert_eq!(m.enabled.get(&Rule::EntityTimeout), Some(&true));

    let force = m
        .enum_checks
        .iter()
        .find(|c| c.spec.name == "entity-state.force_id")
        .unwrap();
    assert_eq!(force.allowed, vec![0u64..=8]);
    assert_eq!(force.severity, Severity::Critical);
    assert_eq!(force.pack, "site-alpha");

    // "off" removes the lower layer's check entirely.
    assert!(!m
        .enum_checks
        .iter()
        .any(|c| c.spec.name == "entity-state.marking.character_set"));

    // Alert citation: the last pack to touch each rule.
    assert_eq!(m.rule_pack[&Rule::EntityTimeout], "site-alpha");
    assert_eq!(m.rule_pack[&Rule::PositionJump], "dis-base");
}

#[test]
fn disabled_rule_fires_nothing() {
    let src = "[pack]\nid = \"s\"\nversion = 1\n\n[rules.entity-timeout]\nenabled = false\n";
    let merged = Merged::merge(vec![base(), RulePack::parse(src, "test").unwrap()]);
    let mut disabled = Monitor::with_packs(&merged);
    let mut control = Monitor::new(RuleConfig::default());

    let d = datagram(&entity_state(1), 0.0);
    disabled.ingest(&d);
    control.ingest(&d);
    let now = control.now;
    let off_events = disabled.tick(now + 20.0);
    let on_events = control.tick(now + 20.0);

    assert!(off_events.iter().all(|e| e.alert.rule != Rule::EntityTimeout));
    assert!(on_events.iter().any(|e| e.alert.rule == Rule::EntityTimeout));
}

#[test]
fn invalid_packs_are_rejected() {
    let cases = [
        "id = \"x\"",                             // keys before any section
        "[pack]\nid = \"x\"",                     // no version
        "[pack]\nid = \"x\"\nversion = 0",        // bad version
        "[pack]\nversion = 1",                    // no id
        "[pack]\nid = \"x\"\nversion = 1\nbogus = 1",
        "[pack]\nid = \"x\"\nversion = 1\n\n[rules.nope]\nenabled = true",
        "[pack]\nid = \"x\"\nversion = 1\n\n[rules.entity-timeout]\nbogus = 1.0",
        "[pack]\nid = \"x\"\nversion = 1\n\n[rules.entity-timeout]\nheartbeat = -1",
        "[pack]\nid = \"x\"\nversion = 1\n\n[rules.entity-timeout]\nseverity = \"fatal\"",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"nope\"\nallowed = \"1-2\"",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = \"9-3\"",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = \"x\"",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = \"1-2\"\nseverity = \"fatal\"",
        // Duplicate enum field within one pack.
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = \"1-2\"\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = \"3-4\"",
        // TOML syntax errors.
        "[pack\nid = \"x\"\nversion = 1",
        "[pack]\nid = \"x\"\nversion = 1\n\n[[enum]\nfield = \"a\"\nallowed = 1",
    ];
    for src in cases {
        assert!(RulePack::parse(src, "test").is_err(), "should reject: {src:?}");
    }
}

#[test]
fn allowed_forms() {
    let check = |allowed: &str| -> Vec<std::ops::RangeInclusive<u64>> {
        let src =
            format!("[pack]\nid = \"x\"\nversion = 1\n\n[[enum]]\nfield = \"header.pdu_type\"\nallowed = {allowed}");
        let merged = Merged::merge(vec![base(), RulePack::parse(&src, "test").unwrap()]);
        merged
            .enum_checks
            .iter()
            .find(|c| c.spec.name == "header.pdu_type")
            .unwrap()
            .allowed
            .clone()
    };
    assert_eq!(check("\"0-8\""), vec![0..=8]);
    assert_eq!(check("\"0-3, 7\""), vec![0..=3, 7..=7]);
    assert_eq!(check("[1, 2, 3]"), vec![1..=1, 2..=2, 3..=3]);
    assert_eq!(check("5"), vec![5..=5]);
}

struct Collect {
    start: SystemTime,
    out: Vec<Datagram>,
}

impl Sink for Collect {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        self.out.push(Datagram {
            received_at: self.start + Duration::from_secs_f64(t),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, s.site as u8, 10), 40_000)),
            destination: None,
            payload: d.to_vec(),
        });
        Ok(())
    }
}

/// Clean generator traffic must pass every base-pack enum check: false
/// positives here would erode trust in every other rule.
#[test]
fn generator_output_passes_all_enum_checks() {
    let cfg = Config {
        duration: 30.0,
        fire_every: Some(5.0),
        ..Default::default()
    };
    let mut sink = Collect {
        start: cfg.start_time,
        out: Vec::new(),
    };
    run(&cfg, &mut sink).unwrap();
    assert!(!sink.out.is_empty());

    let mut m = Monitor::new(RuleConfig::default());
    let mut violations = 0;
    for d in &sink.out {
        violations += m
            .ingest(d)
            .1
            .iter()
            .filter(|e| e.alert.rule == Rule::EnumViolation)
            .count();
    }
    assert_eq!(violations, 0);
}
