//! Every finding the generator's fault presets provoke has a plain-language
//! explanation (`nn_rules::explain`), so no alert reaches the dashboard as
//! bare standard-speak.

use nn_capture::Datagram;
use nn_generator::presets::{schedule, Presets};
use nn_generator::{profile, run, Config, Sender, Sink};
use nn_rules::pack::Merged;
use nn_rules::siso::Siso;
use nn_rules::{explain, AlertState, Monitor};
use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime};

struct Collect {
    start: SystemTime,
    out: Vec<Datagram>,
}

impl Sink for Collect {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        let source = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, s.site as u8, s.host()),
            40_000 + s.generation,
        ));
        self.out.push(Datagram {
            received_at: self.start + Duration::from_secs_f64(t),
            source,
            destination: None,
            payload: d.to_vec(),
            monotonic: None,
            listener: None,
        });
        Ok(())
    }
}

/// (rule, finding type) of every alert a run of all presets raises.
fn findings(profile_name: &str) -> BTreeSet<(&'static str, &'static str)> {
    let mut cfg = Config {
        duration: 600.0,
        sites: 4,
        entities_per_site: 10,
        fire_every: Some(10.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    profile(profile_name).unwrap().apply(&mut cfg);
    schedule(&mut cfg, &Presets::all(), Vec::new(), Vec::new()).unwrap();
    let mut sink = Collect {
        start: cfg.start_time,
        out: Vec::new(),
    };
    run(&cfg, &mut sink).unwrap();
    let xml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/siso-mini.xml")).unwrap();
    let siso = Siso::parse(&xml).unwrap();
    let mut m = Monitor::with_packs(&Merged::load_with(Some(&siso), &[] as &[&str]).unwrap());
    let mut out = BTreeSet::new();
    for d in &sink.out {
        for e in m.ingest(d).1 {
            if e.state == AlertState::Firing {
                out.insert((e.alert.rule.name(), e.alert.kind));
            }
        }
    }
    out
}

#[test]
fn every_finding_the_presets_raise_is_explained() {
    let mut all = BTreeSet::new();
    for p in ["standard", "legacy", "body-axis", "gateway"] {
        all.extend(findings(p));
    }
    let missing: Vec<_> = all.iter().filter(|(r, k)| explain::explain(r, k).is_none()).collect();
    assert!(
        missing.is_empty(),
        "{} of {} findings unexplained: {missing:?}",
        missing.len(),
        all.len()
    );
}

#[test]
fn the_catalog_has_one_entry_per_finding_and_every_field_filled() {
    let mut seen = BTreeSet::new();
    for e in explain::catalog() {
        assert!(seen.insert((e.rule, e.kind)), "{}/{} twice", e.rule, e.kind);
        for (name, text) in [
            ("title", e.title),
            ("impact", e.impact),
            ("causes", e.causes),
            ("fix", e.fix),
        ] {
            assert!(!text.trim().is_empty(), "{}/{}: empty {name}", e.rule, e.kind);
        }
        let real = nn_rules::Rule::from_name(e.rule).is_some() || ["enum-violation", "decode-error"].contains(&e.rule);
        assert!(real, "{}: no such rule", e.rule);
    }
}
