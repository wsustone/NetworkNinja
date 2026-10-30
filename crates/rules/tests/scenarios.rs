//! Milestone 2–3 checks against the synthetic generator:
//! every injected fault fires the right alert on the right entity in time,
//! control scenarios stay silent, a long clean run stays silent, and entity
//! counts and rates match ground truth.

use nn_capture::Datagram;
use nn_decode::{decode_datagram, EntityId, PduBody};
use nn_generator::{profile, run, Config, Event, EventKind, Sender, Sink, Target};
use nn_rules::{AlertEvent, AlertState, Monitor, Rule, RuleConfig};
use nn_state::query::evaluate;
use nn_state::{secs, EntityKey, Query};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

struct Collect {
    start: std::time::SystemTime,
    out: Vec<Datagram>,
}

impl Sink for Collect {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        let host = s.host();
        let source = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(10, 0, s.site as u8, host),
            40_000 + s.generation,
        ));
        self.out.push(Datagram {
            received_at: self.start + Duration::from_secs_f64(t),
            source,
            destination: None,
            payload: d.to_vec(),
            monotonic: None,
        });
        Ok(())
    }
}

fn generate(cfg: &Config) -> Vec<Datagram> {
    let mut sink = Collect {
        start: cfg.start_time,
        out: Vec::new(),
    };
    run(cfg, &mut sink).unwrap();
    sink.out
}

/// Feed every datagram through a monitor; return all alert events.
fn monitor(datagrams: &[Datagram]) -> (Monitor, Vec<AlertEvent>) {
    let mut m = Monitor::new(RuleConfig::default());
    let mut events = Vec::new();
    for d in datagrams {
        events.extend(m.ingest(d).1);
    }
    (m, events)
}

fn t0(cfg: &Config) -> f64 {
    secs(cfg.start_time)
}

fn key(site: u16, entity: u16) -> EntityKey {
    EntityKey {
        exercise: 1,
        id: EntityId::new(site, 1, entity),
    }
}

fn firing(events: &[AlertEvent]) -> Vec<&AlertEvent> {
    events.iter().filter(|e| e.state == AlertState::Firing).collect()
}

fn describe(events: &[AlertEvent]) -> String {
    events
        .iter()
        .map(|e| {
            format!(
                "{:?} {} {} at {:.2}: {}",
                e.state,
                e.alert.rule.name(),
                e.alert.key,
                e.at,
                e.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Time of the last Entity State for `id` from a non-rogue sender before `before`.
fn last_report_before(cfg: &Config, datagrams: &[Datagram], id: EntityId, before: f64) -> f64 {
    let mut last = f64::NEG_INFINITY;
    for d in datagrams {
        let t = secs(d.received_at) - t0(cfg);
        if t >= before || d.source.to_string().contains(".250:") {
            continue;
        }
        for p in decode_datagram(&d.payload).into_iter().flatten() {
            if matches!(p.body, PduBody::EntityState(ref e) if e.entity_id == id) {
                last = last.max(t);
            }
        }
    }
    last
}

fn faults(version: u8, bundle: bool) -> Config {
    let id = |s, e| Target::Entity(EntityId::new(s, 1, e));
    Config {
        version,
        bundle,
        duration: 60.0,
        sites: 3,
        entities_per_site: 20,
        fire_every: Some(5.0),
        events: vec![
            Event {
                kind: EventKind::DropHeartbeat,
                target: id(1, 1),
                at: 10.0,
            },
            Event {
                kind: EventKind::CloneId,
                target: id(1, 2),
                at: 15.0,
            },
            Event {
                kind: EventKind::Teleport,
                target: id(1, 3),
                at: 20.0,
            },
        ],
        ..Default::default()
    }
}

#[test]
fn each_fault_fires_the_right_alert_in_time() {
    for version in [6, 7] {
        for bundle in [false, true] {
            let cfg = faults(version, bundle);
            let datagrams = generate(&cfg);
            let (_, events) = monitor(&datagrams);
            let fired = firing(&events);
            let ctx = format!("v{version} bundle={bundle}\n{}", describe(&events));

            // Exactly one alert per fault, nothing else.
            assert_eq!(fired.len(), 3, "{ctx}");
            let find = |rule: Rule, k: EntityKey| {
                fired
                    .iter()
                    .find(|e| e.alert.rule == rule && e.alert.key == k)
                    .unwrap_or_else(|| panic!("missing {} on {k}\n{ctx}", rule.name()))
            };
            let base = t0(&cfg);

            // Timeout: 12 s after the last report, plus at most one tick and one packet gap.
            let last = last_report_before(&cfg, &datagrams, EntityId::new(1, 1, 1), 10.0);
            let fired_at = find(Rule::EntityTimeout, key(1, 1)).at - base;
            let latency = fired_at - last;
            assert!(
                (12.0..=12.0 + 0.6).contains(&latency),
                "timeout latency {latency:.2} s\n{ctx}"
            );

            // Conflict: by the original sender's next report after the clone appears.
            let at = find(Rule::IdConflict, key(1, 2)).at - base;
            assert!(
                (15.0..=15.0 + cfg.heartbeat + 0.1).contains(&at),
                "conflict at {at:.2} s\n{ctx}"
            );

            // Jump: the very next report, in the same tick as the teleport.
            let at = find(Rule::PositionJump, key(1, 3)).at - base;
            assert!((20.0..=20.0 + 0.1).contains(&at), "jump at {at:.2} s\n{ctx}");
        }
    }
}

/// Each alert is pinned on the sender that caused it (ADR 0008 conformance
/// view): the silent simulator for a timeout, the cloning intruder (not the
/// original owner) for an ID conflict, the reporter for a jump.
#[test]
fn alerts_are_attributed_to_the_responsible_sender() {
    let cfg = faults(7, false);
    let (_, events) = monitor(&generate(&cfg));
    let sender_of = |rule: Rule, k: EntityKey| {
        firing(&events)
            .iter()
            .find(|e| e.alert.rule == rule && e.alert.key == k)
            .and_then(|e| e.alert.sender)
            .map(|s| s.ip().to_string())
            .unwrap_or_else(|| panic!("no attributed {} on {k}\n{}", rule.name(), describe(&events)))
    };
    // The generator's site-1 simulator is 10.0.1.10; its rogue clone 10.0.1.250.
    assert_eq!(sender_of(Rule::EntityTimeout, key(1, 1)), "10.0.1.10");
    assert_eq!(sender_of(Rule::IdConflict, key(1, 2)), "10.0.1.250");
    assert_eq!(sender_of(Rule::PositionJump, key(1, 3)), "10.0.1.10");
}

#[test]
fn faults_mixed_with_controls_fire_once_each() {
    // The generator's --all-faults --all-controls mix, including a freeze
    // while the clone is still running.
    for silent_when_frozen in [false, true] {
        let id = |s, e| Target::Entity(EntityId::new(s, 1, e));
        let d = 60.0;
        let cfg = Config {
            duration: d,
            fire_every: Some(7.0),
            silent_when_frozen,
            events: vec![
                Event {
                    kind: EventKind::DropHeartbeat,
                    target: id(1, 1),
                    at: d * 0.25,
                },
                Event {
                    kind: EventKind::CloneId,
                    target: id(1, 2),
                    at: d * 0.35,
                },
                Event {
                    kind: EventKind::Teleport,
                    target: id(1, 3),
                    at: d * 0.45,
                },
                Event {
                    kind: EventKind::Remove,
                    target: id(2, 1),
                    at: d * 0.25,
                },
                Event {
                    kind: EventKind::RestartPort,
                    target: Target::Site(2),
                    at: d * 0.35,
                },
                Event {
                    kind: EventKind::Freeze,
                    target: Target::Exercise,
                    at: d * 0.55,
                },
                Event {
                    kind: EventKind::Resume,
                    target: Target::Exercise,
                    at: d * 0.70,
                },
            ],
            ..Default::default()
        };
        let (_, events) = monitor(&generate(&cfg));
        let mut fired: Vec<(Rule, EntityKey)> = firing(&events).iter().map(|e| (e.alert.rule, e.alert.key)).collect();
        fired.sort();
        assert_eq!(
            fired,
            vec![
                (Rule::EntityTimeout, key(1, 1)),
                (Rule::IdConflict, key(1, 2)),
                (Rule::PositionJump, key(1, 3))
            ],
            "silent_when_frozen={silent_when_frozen}\n{}",
            describe(&events)
        );
    }
}

#[test]
fn timeout_counts_only_running_time_across_a_freeze() {
    // Entity goes silent at 10 s; exercise frozen 15–40 s.
    for silent_when_frozen in [false, true] {
        let cfg = Config {
            duration: 70.0,
            silent_when_frozen,
            events: vec![
                Event {
                    kind: EventKind::DropHeartbeat,
                    target: Target::Entity(EntityId::new(1, 1, 1)),
                    at: 10.0,
                },
                Event {
                    kind: EventKind::Freeze,
                    target: Target::Exercise,
                    at: 15.0,
                },
                Event {
                    kind: EventKind::Resume,
                    target: Target::Exercise,
                    at: 40.0,
                },
            ],
            ..Default::default()
        };
        let datagrams = generate(&cfg);
        let (_, events) = monitor(&datagrams);
        let fired = firing(&events);
        assert_eq!(fired.len(), 1, "{}", describe(&events));
        assert_eq!(
            (fired[0].alert.rule, fired[0].alert.key),
            (Rule::EntityTimeout, key(1, 1))
        );

        let last = last_report_before(&cfg, &datagrams, EntityId::new(1, 1, 1), 10.0);
        let running_before_freeze = 15.0 - last;
        // Remaining running time after resume, but at least one heartbeat of grace.
        let expected = 40.0 + (12.0 - running_before_freeze).max(cfg.heartbeat);
        let at = fired[0].at - t0(&cfg);
        assert!(
            (expected..=expected + 0.6).contains(&at),
            "fired at {at:.2}, expected ~{expected:.2}\n{}",
            describe(&events)
        );
    }
}

#[test]
fn alerts_resolve_when_the_cause_goes_away() {
    // Teleport resolves on the next consistent report.
    let cfg = faults(7, false);
    let (_, events) = monitor(&generate(&cfg));
    let resolved: Vec<_> = events.iter().filter(|e| e.state == AlertState::Resolved).collect();
    assert!(
        resolved
            .iter()
            .any(|e| e.alert.rule == Rule::PositionJump && e.alert.key == key(1, 3)),
        "{}",
        describe(&events)
    );
    // The dropped entity and the clone keep their alerts to the end.
    assert!(!resolved
        .iter()
        .any(|e| e.alert.key == key(1, 1) || e.alert.key == key(1, 2)));
}

#[test]
fn control_scenarios_stay_silent() {
    for silent_when_frozen in [false, true] {
        for version in [6, 7] {
            let cfg = Config {
                version,
                duration: 90.0,
                sites: 3,
                entities_per_site: 20,
                fire_every: Some(5.0),
                silent_when_frozen,
                events: vec![
                    Event {
                        kind: EventKind::Remove,
                        target: Target::Entity(EntityId::new(2, 1, 1)),
                        at: 10.0,
                    },
                    Event {
                        kind: EventKind::RestartPort,
                        target: Target::Site(2),
                        at: 20.0,
                    },
                    Event {
                        kind: EventKind::RestartPort,
                        target: Target::Site(3),
                        at: 22.5,
                    },
                    // Frozen for 20 s: longer than the 12 s timeout.
                    Event {
                        kind: EventKind::Freeze,
                        target: Target::Exercise,
                        at: 40.0,
                    },
                    Event {
                        kind: EventKind::Resume,
                        target: Target::Exercise,
                        at: 60.0,
                    },
                ],
                ..Default::default()
            };
            let (_, events) = monitor(&generate(&cfg));
            assert!(
                events.is_empty(),
                "silent_when_frozen={silent_when_frozen} v{version}\n{}",
                describe(&events)
            );
        }
    }
}

#[test]
fn thirty_minute_clean_run_is_silent() {
    let cfg = Config {
        duration: 1800.0,
        sites: 3,
        entities_per_site: 25,
        fire_every: Some(10.0),
        bundle: true,
        seed: 7,
        ..Default::default()
    };
    let (m, events) = monitor(&generate(&cfg));
    assert!(events.is_empty(), "{}", describe(&events));
    assert_eq!(m.decode_errors, 0);
    assert_eq!(m.active_entities(), 75);
}

#[test]
fn entity_counts_and_rates_match_ground_truth() {
    let cfg = Config {
        duration: 120.0,
        sites: 4,
        entities_per_site: 30,
        fire_every: Some(3.0),
        events: vec![
            Event {
                kind: EventKind::Remove,
                target: Target::Entity(EntityId::new(2, 1, 5)),
                at: 30.0,
            },
            Event {
                kind: EventKind::DropHeartbeat,
                target: Target::Entity(EntityId::new(3, 1, 7)),
                at: 30.0,
            },
        ],
        ..Default::default()
    };
    let datagrams = generate(&cfg);
    let (m, _) = monitor(&datagrams);

    // 120 entities seen; one removed and one silent leave 118 active.
    assert_eq!(m.table.entities.len(), 120);
    assert_eq!(m.active_entities(), 118);

    // PDUs and bytes in the last 60 s window match the generator exactly.
    let end = m.now;
    let window_start = end.floor() - 59.0;
    let (mut pdus, mut bytes) = (0u64, 0u64);
    for d in &datagrams {
        let t = secs(d.received_at);
        if t >= window_start && t <= end {
            pdus += decode_datagram(&d.payload).len() as u64;
            bytes += d.payload.len() as u64;
        }
    }
    let w = m.metrics.window(end, 60);
    assert_eq!(w.pdus, pdus);
    assert_eq!(w.bytes, bytes);
    assert_eq!(w.errors, 0);

    // The query API agrees, split by sender (ADR 0008): one toplist value
    // per source address over the same 60 s.
    let mut per_sender: std::collections::BTreeMap<String, u64> = Default::default();
    for d in &datagrams {
        let t = secs(d.received_at);
        if t >= window_start && t <= end {
            *per_sender.entry(d.source.to_string()).or_default() += decode_datagram(&d.payload).len() as u64;
        }
    }
    let from = window_start as i64;
    let q = Query::parse(
        &[
            ("name".into(), "pdu.count".into()),
            ("by".into(), "sender".into()),
            ("agg".into(), "sum".into()),
            ("from".into(), from.to_string()),
            ("to".into(), (from + 60).to_string()),
            ("window".into(), "60".into()),
        ],
        end,
    )
    .unwrap();
    let got: std::collections::BTreeMap<String, u64> =
        evaluate(&q, m.metrics.cells(q.metric, q.from, q.to, |t| q.matches(t)))
            .into_iter()
            .map(|s| (s.tags[0].1.clone(), s.points[0].1 as u64))
            .collect();
    assert_eq!(got, per_sender);

    // entity.active summed over every tag is the active count at the end.
    let q = Query::parse(
        &[
            ("name".into(), "entity.active".into()),
            ("agg".into(), "sum".into()),
            ("window".into(), "1".into()),
            ("from".into(), (end.floor() as i64 - 1).to_string()),
            ("to".into(), (end.floor() as i64 + 1).to_string()),
        ],
        end,
    )
    .unwrap();
    let s = evaluate(&q, m.metrics.cells(q.metric, q.from, q.to, |_| true));
    assert_eq!(s[0].points.last().unwrap().1, 118.0, "{s:?}");

    // Heartbeat interval stats per entity are close to the configured 5 s or less.
    for rec in m.table.entities.values() {
        let track = &rec.sources[&rec.last_source];
        assert!(
            track.intervals.mean <= cfg.heartbeat + 0.06,
            "{} mean {}",
            rec.key,
            track.intervals.mean
        );
    }
}

/// Datagrams from one generator *process*: its own sockets, so its own
/// source ports (process `p` sends from 41000 + 100·p + generation).
fn generate_process(cfg: &Config, p: u16) -> Vec<Datagram> {
    struct Proc(std::time::SystemTime, u16, Vec<Datagram>);
    impl Sink for Proc {
        fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
            let host = s.host();
            self.2.push(Datagram {
                received_at: self.0 + Duration::from_secs_f64(t),
                source: SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(10, 0, s.site as u8, host),
                    41_000 + 100 * self.1 + s.generation,
                )),
                destination: None,
                payload: d.to_vec(),
                monotonic: None,
            });
            Ok(())
        }
    }
    let mut sink = Proc(cfg.start_time, p, Vec::new());
    run(cfg, &mut sink).unwrap();
    sink.2
}

/// Two generators side by side (ADR 0010): with separate site ranges and
/// application numbers a clean run raises nothing; overlapping ranges are
/// two simulators claiming the same IDs, which the monitor must catch.
#[test]
fn generators_side_by_side_need_separate_site_ranges() {
    let base = Config {
        duration: 40.0,
        sites: 2,
        entities_per_site: 10,
        fire_every: Some(4.0),
        ..Default::default()
    };
    let merged = |a: &Config, b: &Config| {
        let mut all = generate_process(a, 0);
        all.extend(generate_process(b, 1));
        all.sort_by_key(|d| d.received_at); // stable: per-process order kept
        all
    };

    let a = Config { ..base.clone() };
    let b = Config {
        site_base: 3,
        application: 7,
        seed: 2,
        ..base.clone()
    };
    let (m, events) = monitor(&merged(&a, &b));
    assert!(firing(&events).is_empty(), "{}", describe(&events));
    assert_eq!(m.table.entities.len(), 40);
    assert!(m.table.entities.keys().any(|k| k.id == EntityId::new(4, 7, 10)));

    // Same site range twice: every entity is claimed by two simulators.
    let clash = Config {
        seed: 2,
        ..base.clone()
    };
    let (_, events) = monitor(&merged(&a, &clash));
    let conflicts = firing(&events)
        .iter()
        .filter(|e| e.alert.rule == Rule::IdConflict)
        .count();
    assert!(conflicts >= 15, "only {conflicts} conflicts\n{}", describe(&events));
}

// ------------------------------------------------- tier S (ADR 0010)

#[test]
fn every_pdu_type_sent_clean_is_silent() {
    for version in [6, 7] {
        for bundle in [false, true] {
            let cfg = Config {
                version,
                bundle,
                duration: 30.0,
                all_types: Some(5.0),
                fire_every: Some(5.0),
                ..Default::default()
            };
            let datagrams = generate(&cfg);
            let (m, events) = monitor(&datagrams);
            assert!(events.is_empty(), "v{version} bundle={bundle}\n{}", describe(&events));
            assert_eq!(m.decode_errors, 0);
            // Every type went out, except Remove Entity and Stop/Freeze,
            // which only the controls send.
            let types: std::collections::BTreeSet<u8> = datagrams
                .iter()
                .flat_map(|d| decode_datagram(&d.payload))
                .map(|p| p.unwrap().header.pdu_type)
                .collect();
            assert_eq!(types.len(), 70, "v{version}");
            assert!(!types.contains(&12) && !types.contains(&14));
        }
    }
}

#[test]
fn each_structural_fault_fires_its_rule_on_its_sender() {
    let cases = [
        (EventKind::ShortPdu, 4, "pdu-structure"),
        (EventKind::CountOverrun, 25, "pdu-structure"),
        (EventKind::PaddedPdu, 24, "pdu-padding"),
        (EventKind::WrongFamily, 26, "pdu-family"),
        (EventKind::TruncatedPdu, 23, "pdu-structure"),
    ];
    for version in [6, 7] {
        let cfg = Config {
            version,
            duration: 30.0,
            sites: 3,
            all_types: Some(5.0),
            events: cases
                .iter()
                .enumerate()
                .map(|(i, &(kind, pdu_type, _))| Event {
                    kind,
                    target: Target::Pdu { site: 2, pdu_type },
                    at: 5.0 + 2.0 * i as f64,
                })
                .collect(),
            ..Default::default()
        };
        let (_, events) = monitor(&generate(&cfg));
        let got: Vec<(&str, String, String)> = firing(&events)
            .iter()
            .map(|e| {
                (
                    e.alert.rule.name(),
                    e.alert.sender.unwrap().to_string(),
                    e.alert.key.id.to_string(),
                )
            })
            .collect();
        let want: Vec<(&str, String, String)> = cases
            .iter()
            .map(|&(_, _, rule)| (rule, "10.0.2.10:40000".to_string(), "2:1:0".to_string()))
            .collect();
        assert_eq!(got, want, "v{version}\n{}", describe(&events));
        // Each cites the layout clause it checks.
        assert!(events[0].reason.contains("Collision") && events[0].reason.contains("7.2.3"));
    }
}

// ------------------------------------------- vendor profiles (ADR 0010)

/// Four vendors side by side, each a separate generator process with its
/// own profile, sites and application, all following one exercise freeze.
/// Vendor `p` (0-3) runs sites 2p+1 and 2p+2 as application p+1.
fn multi_vendor(faults: &[(usize, Event)]) -> Vec<Datagram> {
    let mut all = Vec::new();
    for (p, name) in ["standard", "legacy", "body-axis", "gateway"].into_iter().enumerate() {
        let mut cfg = Config {
            duration: 60.0,
            site_base: 2 * p as u16 + 1,
            application: p as u16 + 1,
            sites: 2,
            entities_per_site: 8,
            fire_every: Some(6.0),
            all_types: (p % 2 == 0).then_some(10.0),
            seed: 11 + p as u64,
            events: vec![
                Event {
                    kind: EventKind::Freeze,
                    target: Target::Exercise,
                    at: 20.0,
                },
                Event {
                    kind: EventKind::Resume,
                    target: Target::Exercise,
                    at: 35.0,
                },
            ],
            ..Default::default()
        };
        profile(name).unwrap().apply(&mut cfg);
        if p == 0 {
            cfg.events.push(Event {
                kind: EventKind::Remove,
                target: Target::Entity(EntityId::new(1, 1, 1)),
                at: 10.0,
            });
            cfg.events.push(Event {
                kind: EventKind::RestartPort,
                target: Target::Site(2),
                at: 15.0,
            });
        }
        cfg.events
            .extend(faults.iter().filter(|(v, _)| *v == p).map(|(_, e)| *e));
        all.extend(generate_process(&cfg, p as u16));
    }
    all.sort_by_key(|d| d.received_at); // stable: each process keeps its order
    all
}

#[test]
fn multi_vendor_run_without_defects_is_silent() {
    let (m, events) = monitor(&multi_vendor(&[]));
    assert!(events.is_empty(), "{}", describe(&events));
    assert_eq!(m.decode_errors, 0);
    assert_eq!(m.table.entities.len(), 64);
    // The gateway's copies were recognised as copies, not a second simulator.
    assert!(m.duplicates > 100, "{} duplicates", m.duplicates);
}

#[test]
fn multi_vendor_run_raises_exactly_the_injected_defects() {
    let ev = |kind, target, at| Event { kind, target, at };
    let faults = [
        (
            0,
            ev(EventKind::DropHeartbeat, Target::Entity(EntityId::new(1, 1, 2)), 12.0),
        ),
        (1, ev(EventKind::Teleport, Target::Entity(EntityId::new(3, 2, 3)), 14.0)),
        (
            1,
            ev(EventKind::WrongFamily, Target::Pdu { site: 3, pdu_type: 26 }, 15.0),
        ),
        (2, ev(EventKind::CloneId, Target::Entity(EntityId::new(5, 3, 2)), 16.0)),
        (3, ev(EventKind::ShortPdu, Target::Pdu { site: 7, pdu_type: 4 }, 18.0)),
    ];
    let (_, events) = monitor(&multi_vendor(&faults));
    let mut got: Vec<(String, String, String)> = firing(&events)
        .iter()
        .map(|e| {
            (
                e.alert.rule.name().to_string(),
                e.alert.key.id.to_string(),
                e.alert.sender.unwrap().to_string(),
            )
        })
        .collect();
    got.sort();
    let mut want: Vec<(String, String, String)> = [
        ("entity-timeout", "1:1:2", "10.0.1.10:41000"),
        ("id-conflict", "5:3:2", "10.0.5.250:41200"),
        ("pdu-family", "3:2:0", "10.0.3.10:41100"),
        ("pdu-structure", "7:4:0", "10.0.7.10:41300"),
        ("position-jump", "3:2:3", "10.0.3.10:41100"),
    ]
    .iter()
    .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
    .collect();
    want.sort();
    assert_eq!(got, want, "{}", describe(&events));
}
