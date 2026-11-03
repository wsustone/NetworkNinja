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
            listener: None,
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

/// Time of the last Entity State (or Update) for `id` from a non-rogue
/// sender before `before`.
fn last_report_before(cfg: &Config, datagrams: &[Datagram], id: EntityId, before: f64) -> f64 {
    let mut last = f64::NEG_INFINITY;
    for d in datagrams {
        let t = secs(d.received_at) - t0(cfg);
        if t >= before || d.source.to_string().contains(".250:") {
            continue;
        }
        for p in decode_datagram(&d.payload).into_iter().flatten() {
            let reported = match &p.body {
                PduBody::EntityState(e) => e.entity_id == id,
                PduBody::EntityStateUpdate(u) => u.entity_id == id,
                _ => false,
            };
            if reported {
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
                listener: None,
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
            // which only the controls send, and Entity State Update, which
            // only follows a full Entity State (`entity_state_update`).
            let types: std::collections::BTreeSet<u8> = datagrams
                .iter()
                .flat_map(|d| decode_datagram(&d.payload))
                .map(|p| p.unwrap().header.pdu_type)
                .collect();
            assert_eq!(types.len(), 69, "v{version}");
            assert!(!types.contains(&12) && !types.contains(&14) && !types.contains(&67));
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

/// Five vendors side by side, each a separate generator process with its
/// own profile, sites and application, all following one exercise freeze.
/// Vendor `p` (0-4) runs sites 2p+1 and 2p+2 as application p+1.
fn multi_vendor(faults: &[(usize, Event)]) -> Vec<Datagram> {
    let mut all = Vec::new();
    for (p, name) in ["standard", "legacy", "body-axis", "gateway", "economical"]
        .into_iter()
        .enumerate()
    {
        let mut cfg = Config {
            duration: 60.0,
            site_base: 2 * p as u16 + 1,
            application: p as u16 + 1,
            sites: 2,
            entities_per_site: 8,
            fire_every: Some(6.0),
            all_types: (p % 2 == 0).then_some(10.0),
            siman_every: Some(3.0),
            radio_every: Some(4.0),
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
    // 5 vendors x 2 sites x 8 entities, plus the economical vendor's
    // 3 parked entities per site.
    assert_eq!(m.table.entities.len(), 86);
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

// ------------------------------------------ SIMAN handshakes (ADR 0010)

fn handshakes(version: u8, events: Vec<Event>) -> Config {
    Config {
        version,
        duration: 60.0,
        sites: 3,
        siman_every: Some(2.0),
        all_types: Some(10.0),
        fire_every: Some(6.0),
        events,
        ..Default::default()
    }
}

#[test]
fn answered_handshakes_are_silent() {
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&handshakes(version, vec![])));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
}

#[test]
fn each_handshake_fault_fires_once_on_the_answering_site() {
    let site2 = |kind, at| Event {
        kind,
        target: Target::Site(2),
        at,
    };
    let cfg = handshakes(
        7,
        vec![
            site2(EventKind::WrongAck, 9.0),
            site2(EventKind::OrphanResponse, 18.0),
            site2(EventKind::NoResponse, 36.0),
        ],
    );
    let (_, events) = monitor(&generate(&cfg));
    let got: Vec<(String, String, String)> = firing(&events)
        .iter()
        .map(|e| {
            (
                e.alert.key.id.to_string(),
                e.alert.sender.unwrap().to_string(),
                // The finding, without the request header or the citation.
                e.reason
                    .split(": ")
                    .nth(1)
                    .unwrap_or("")
                    .split(" (IEEE")
                    .next()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    assert!(
        firing(&events).iter().all(|e| e.alert.rule == Rule::SimanHandshake),
        "{}",
        describe(&events)
    );
    assert_eq!(
        got,
        [
            (
                "2:1:65535",
                "10.0.2.10:40000",
                "Acknowledge Flag 2, but it answers a CreateEntity (flag 1)"
            ),
            ("2:1:1", "10.0.2.10:40000", "answers no request seen from 1:1"),
            // The first request after the site goes quiet (36 s) is a Data Query.
            ("2:1:65535", "10.0.2.10:40000", "no Data within 12 s"),
        ]
        .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string())),
        "{}",
        describe(&events)
    );
}

// --------------------------------------------- radio (ADR 0010 step 5)

fn radio_run(events: Vec<Event>) -> Config {
    Config {
        duration: 200.0,
        sites: 4,
        entities_per_site: 4,
        radio_every: Some(5.0),
        all_types: Some(20.0),
        events,
        ..Default::default()
    }
}

#[test]
fn radio_traffic_is_silent() {
    let freeze = vec![
        Event {
            kind: EventKind::Freeze,
            target: Target::Exercise,
            at: 60.0,
        },
        Event {
            kind: EventKind::Resume,
            target: Target::Exercise,
            at: 90.0,
        },
    ];
    for (version, bundle, silent_when_frozen) in [(7, false, false), (6, true, true), (7, true, true)] {
        let cfg = Config {
            version,
            bundle,
            silent_when_frozen,
            ..radio_run(freeze.clone())
        };
        let datagrams = generate(&cfg);
        let (m, events) = monitor(&datagrams);
        assert!(
            events.is_empty(),
            "v{version} bundle={bundle} silent={silent_when_frozen}\n{}",
            describe(&events)
        );
        assert_eq!(m.decode_errors, 0);
        let signals = datagrams
            .iter()
            .flat_map(|d| decode_datagram(&d.payload))
            .filter(|p| p.as_ref().unwrap().header.pdu_type == 26)
            .count();
        assert!(signals > 1000, "{signals} Signal PDUs");
    }
}

#[test]
fn each_radio_fault_fires_once_on_its_site() {
    let at = |kind, site, at| Event {
        kind,
        target: Target::Site(site),
        at,
    };
    let cfg = radio_run(vec![
        at(EventKind::BadSignal, 1, 20.0),
        at(EventKind::HotMic, 2, 30.0),
        at(EventKind::DropTransmitter, 3, 40.0),
        at(EventKind::OrphanSignal, 4, 180.0),
    ]);
    let (_, events) = monitor(&generate(&cfg));
    let mut got: Vec<(String, String, String)> = firing(&events)
        .iter()
        .map(|e| {
            (
                e.alert.rule.name().to_string(),
                e.alert.sender.unwrap().to_string(),
                e.reason
                    .split(": ")
                    .nth(1)
                    .unwrap_or("")
                    .split(" (IEEE")
                    .next()
                    .unwrap()
                    .to_string(),
            )
        })
        .collect();
    got.sort();
    assert_eq!(got.len(), 4, "{}", describe(&events));
    let expect = [
        (
            "10.0.1.10:40000",
            "Signal Data Length 6392 bits, but 400 samples of encoding type 4 (16 bits each) are 6400",
        ),
        ("10.0.2.10:40000", "transmitting for"),
        ("10.0.3.10:40000", "transmitting, but no Transmitter PDU for"),
        ("10.0.4.10:40000", "Signal with no Transmitter PDU for this radio"),
    ];
    for ((rule, sender, msg), (want_sender, want_msg)) in got.iter().zip(expect) {
        assert_eq!(rule, "radio");
        assert_eq!(sender, want_sender);
        assert!(msg.starts_with(want_msg), "{msg} / {want_msg}\n{}", describe(&events));
    }
}

// ------------------------------------------------ duplicate delivery

fn copy_of(d: &Datagram, listener: &str, after: f64) -> Datagram {
    Datagram {
        received_at: d.received_at + Duration::from_secs_f64(after),
        listener: Some(std::sync::Arc::from(listener)),
        ..d.clone()
    }
}

#[test]
fn the_same_send_delivered_twice_is_counted_once_and_reported() {
    let cfg = Config {
        duration: 20.0,
        sites: 1,
        entities_per_site: 3,
        ..Default::default()
    };
    let base = generate(&cfg);
    let dup = |listener_b: &str, gap: f64| -> (Monitor, Vec<AlertEvent>) {
        let mut all = Vec::new();
        for d in &base {
            all.push(copy_of(d, "lab", 0.0));
            all.push(copy_of(d, listener_b, gap));
        }
        all.sort_by_key(|d| d.received_at);
        monitor(&all)
    };
    // Through two listeners: the listeners overlap.
    let (m, events) = dup("site-b", 0.002);
    let f = firing(&events);
    assert_eq!(f.len(), 1, "{}", describe(&events));
    assert_eq!(f[0].alert.rule, Rule::DuplicateDelivery);
    assert!(
        f[0].reason.contains("two listeners") && f[0].reason.contains("'site-b'"),
        "{}",
        f[0].reason
    );
    assert_eq!(m.echoes as usize, base.len());
    // Twice through one listener: the network duplicates it.
    let (_, events) = dup("lab", 0.002);
    let f = firing(&events);
    assert_eq!(f.len(), 1, "{}", describe(&events));
    assert!(
        f[0].reason.contains("arrive twice on listener 'lab'"),
        "{}",
        f[0].reason
    );
    // The same bytes again after the echo window aren't an echo.
    let (m, _) = dup("lab", 0.5);
    assert_eq!(m.echoes, 0);
}

// ------------------------------- stationary heartbeat and ESU (Wave 0)

fn economical(events: Vec<Event>) -> Config {
    let mut cfg = Config {
        duration: 400.0,
        sites: 2,
        entities_per_site: 4,
        events,
        ..Default::default()
    };
    profile("economical").unwrap().apply(&mut cfg);
    cfg
}

#[test]
fn updates_and_parked_entities_on_a_60_s_heartbeat_are_healthy() {
    let freeze = vec![
        Event {
            kind: EventKind::Freeze,
            target: Target::Exercise,
            at: 100.0,
        },
        Event {
            kind: EventKind::Resume,
            target: Target::Exercise,
            at: 130.0,
        },
    ];
    let datagrams = generate(&economical(freeze));
    let (m, events) = monitor(&datagrams);
    assert!(events.is_empty(), "{}", describe(&events));
    assert_eq!(m.active_entities(), 14);
    let updates = datagrams
        .iter()
        .flat_map(|d| decode_datagram(&d.payload))
        .filter(|p| matches!(p.as_ref().unwrap().body, PduBody::EntityStateUpdate(_)))
        .count();
    assert!(updates > 200, "{updates} Entity State Updates");
    // Updates move the entity on the map like full reports.
    let k = m.table.get(&key(1, 1)).unwrap();
    assert!(m.now - k.last_seen < 6.0);
}

#[test]
fn a_parked_entity_that_goes_silent_still_times_out() {
    // 1:1:5 is the first parked entity on site 1; silent from 100 s.
    let cfg = economical(vec![Event {
        kind: EventKind::DropHeartbeat,
        target: Target::Entity(EntityId::new(1, 1, 5)),
        at: 100.0,
    }]);
    let datagrams = generate(&cfg);
    let last = last_report_before(&cfg, &datagrams, EntityId::new(1, 1, 5), 100.0);
    let (_, events) = monitor(&datagrams);
    let f = firing(&events);
    assert_eq!(f.len(), 1, "{}", describe(&events));
    assert_eq!((f[0].alert.rule, f[0].alert.key), (Rule::EntityTimeout, key(1, 5)));
    let after = f[0].at - t0(&cfg) - last;
    assert!(
        (144.0..=145.0).contains(&after),
        "fired {after:.1} s after the last report"
    );
}

// ------------------------------------------- heartbeats (4.2.7, Table 4)

#[test]
fn a_type_that_stops_its_heartbeat_is_reported_once() {
    // IsGroupOf (5 s), IFF (10 s) and Aggregate State (30 s) stop at 60 s; every
    // other type keeps its heartbeat, so nothing else fires.
    let stop = |pdu_type, at| Event {
        kind: EventKind::StopHeartbeat,
        target: Target::Pdu { site: 1, pdu_type },
        at,
    };
    let cfg = Config {
        duration: 200.0,
        sites: 2,
        entities_per_site: 3,
        all_types: Some(20.0),
        events: vec![stop(34, 60.0), stop(28, 60.0), stop(33, 60.0)],
        ..Default::default()
    };
    let (_, events) = monitor(&generate(&cfg));
    let mut got: Vec<(String, f64)> = firing(&events)
        .iter()
        .map(|e| (e.reason.split(": none").next().unwrap().to_string(), e.at - t0(&cfg)))
        .collect();
    got.sort_by(|a, b| a.1.total_cmp(&b.1));
    assert!(
        firing(&events).iter().all(|e| e.alert.rule == Rule::Heartbeat),
        "{}",
        describe(&events)
    );
    let names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "1:1:0 stopped sending IsGroupOf",
            "1:1:0 stopped sending IFF",
            "1:1:0 stopped sending AggregateState"
        ],
        "{}",
        describe(&events)
    );
    // Last reports were at most one heartbeat before 60 s; timeouts 12, 24
    // and 72 s after them.
    for ((_, at), (hb, timeout)) in got.iter().zip([(5.0, 12.0), (10.0, 24.0), (30.0, 72.0)]) {
        assert!(
            *at > 60.0 - hb + timeout && *at <= 60.0 + timeout + 0.5,
            "fired at {at}"
        );
    }
}

// ------------------------------------------ entity lifecycle (Wave 1)

#[test]
fn removals_with_their_final_report_are_silent() {
    let remove = |e, at| Event {
        kind: EventKind::Remove,
        target: Target::Entity(EntityId::new(1, 1, e)),
        at,
    };
    let cfg = Config {
        duration: 60.0,
        sites: 2,
        entities_per_site: 6,
        events: vec![remove(1, 10.0), remove(2, 12.0), remove(3, 30.0)],
        ..Default::default()
    };
    let (m, events) = monitor(&generate(&cfg));
    assert!(events.is_empty(), "{}", describe(&events));
    let rec = m.table.get(&key(1, 1)).unwrap();
    assert!(rec.deactivated(), "the final report marks it deactivated");
}

#[test]
fn each_lifecycle_fault_fires_on_its_entity() {
    let ev = |kind, e, at| Event {
        kind,
        target: Target::Entity(EntityId::new(1, 1, e)),
        at,
    };
    let cfg = Config {
        duration: 220.0,
        sites: 2,
        entities_per_site: 8,
        events: vec![
            ev(EventKind::NoFinalReport, 4, 20.0),
            ev(EventKind::Zombie, 5, 25.0),
            ev(EventKind::StaticMoving, 6, 30.0),
            ev(EventKind::TypeChange, 7, 35.0),
            // Only reported once the monitor has watched 144 s.
            ev(EventKind::OrphanUpdate, 8, 150.0),
        ],
        ..Default::default()
    };
    let (_, events) = monitor(&generate(&cfg));
    let mut got: Vec<(String, String)> = firing(&events)
        .iter()
        .map(|e| {
            let what = e
                .reason
                .split(": ")
                .nth(1)
                .unwrap_or("")
                .split(' ')
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            (e.alert.key.id.to_string(), what)
        })
        .collect();
    // An ongoing fault (Static while moving, orphan updates) is reported
    // again each repeat window, like an enumeration violation.
    got.sort();
    got.dedup();
    assert!(
        firing(&events).iter().all(|e| e.alert.rule == Rule::EntityLifecycle),
        "{}",
        describe(&events)
    );
    assert!(firing(&events)
        .iter()
        .all(|e| e.alert.sender.unwrap().to_string() == "10.0.1.10:40000"));
    assert_eq!(
        got,
        [
            ("1:1:1008", "Entity State Update"),
            ("1:1:4", "removed, but sent"),
            ("1:1:5", "reports active again"),
            ("1:1:6", "DR algorithm Static"),
            ("1:1:7", "type changed from"),
        ]
        .map(|(a, b)| (a.to_string(), b.to_string())),
        "{}",
        describe(&events)
    );
}

// ------------------------------------------ Fire and Detonation (Wave 1)

#[test]
fn each_warfare_fault_fires_once() {
    let at = |kind, at| Event {
        kind,
        target: Target::Exercise,
        at,
    };
    let cfg = Config {
        duration: 420.0,
        sites: 2,
        entities_per_site: 4,
        fire_every: Some(10.0),
        events: vec![
            at(EventKind::NoDetonation, 15.0),
            at(EventKind::DetonationMismatch, 35.0),
            at(EventKind::WrongFireType, 55.0),
            // Judged only once the monitor has watched max_flight (180 s).
            at(EventKind::OrphanDetonation, 200.0),
        ],
        ..Default::default()
    };
    let (_, events) = monitor(&generate(&cfg));
    let mut got: Vec<String> = firing(&events)
        .iter()
        .map(|e| {
            e.reason
                .split(": ")
                .nth(1)
                .unwrap_or("")
                .split(' ')
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .collect();
    got.sort();
    assert!(
        firing(&events).iter().all(|e| e.alert.rule == Rule::FireDetonation),
        "{}",
        describe(&events)
    );
    assert_eq!(
        got,
        [
            "PDU Status says",
            "munition type 2.1.225.3.1.0.0,",
            "no Detonation within",
            "no Fire with"
        ],
        "{}",
        describe(&events)
    );
}

// ------------------------- collisions, damage, directed energy (Wave 1)

fn interactions(events: Vec<Event>) -> Config {
    Config {
        duration: 240.0,
        sites: 2,
        entities_per_site: 5,
        collision_every: Some(10.0),
        damage_every: Some(40.0),
        de_every: Some(20.0),
        events,
        ..Default::default()
    }
}

#[test]
fn collisions_damage_and_de_shots_told_right_are_silent() {
    for version in [6, 7] {
        let cfg = Config {
            version,
            ..interactions(vec![])
        };
        let datagrams = generate(&cfg);
        let (_, events) = monitor(&datagrams);
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
        let types: std::collections::BTreeSet<u8> = datagrams
            .iter()
            .flat_map(|d| decode_datagram(&d.payload))
            .map(|p| p.unwrap().header.pdu_type)
            .collect();
        for t in [4, 68, 69] {
            assert!(types.contains(&t), "type {t} sent");
        }
    }
}

#[test]
fn each_interaction_fault_fires_on_its_own() {
    let at = |kind, at| Event {
        kind,
        target: Target::Exercise,
        at,
    };
    let cfg = interactions(vec![
        at(EventKind::OneSidedCollision, 15.0),
        at(EventKind::DuplicateCollision, 35.0),
        at(EventKind::StaleAppearance, 45.0),
        at(EventKind::DeDropout, 65.0),
        // Its Detonation then has no Fire: fire-detonation judges that after
        // max_flight (180 s) of watching, so the shot comes later.
        at(EventKind::DeNoFire, 185.0),
        Event {
            kind: EventKind::Remove,
            target: Target::Entity(EntityId::new(2, 1, 5)),
            at: 100.0,
        },
        Event {
            kind: EventKind::EdsAfterRemove,
            target: Target::Entity(EntityId::new(2, 1, 5)),
            at: 120.0,
        },
    ]);
    let (_, events) = monitor(&generate(&cfg));
    let mut got: Vec<(&str, String)> = firing(&events)
        .iter()
        .map(|e| {
            // The first words after the entity, minus IDs (the RNG picks the pair).
            let what = e
                .reason
                .split(": ")
                .nth(1)
                .unwrap_or("")
                .split(' ')
                .filter(|w| !w.contains(':'))
                .take(3)
                .collect::<Vec<_>>()
                .join(" ");
            (e.alert.rule.name(), what)
        })
        .collect();
    got.sort();
    got.dedup();
    assert_eq!(
        got,
        [
            ("collision", "a second Collision"),
            ("collision", "reported a Collision"),
            ("directed-energy", "no Fire PDU"),
            ("directed-energy", "weapon on, but"),
            ("entity-damage", "Entity Damage Status"),
            ("entity-damage", "repaired per Entity"),
            // DeNoFire's Detonation has no Fire either.
            ("fire-detonation", "no Fire with"),
        ]
        .iter()
        .map(|(a, b)| (*a, b.to_string()))
        .collect::<Vec<_>>(),
        "{}",
        describe(&events)
    );
}

#[test]
fn wave1_wrapup_faults_fire_on_their_own() {
    let at = |kind, at| Event {
        kind,
        target: Target::Exercise,
        at,
    };
    let base = Config {
        fire_every: Some(10.0),
        parked_per_site: 1,
        all_types: Some(10.0),
        ..interactions(vec![])
    };
    // Told right, with every type, fires, parked entities: silent.
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    let cfg = Config {
        events: vec![
            at(EventKind::MineFired, 15.0),
            at(EventKind::ImpactMiss, 45.0),
            at(EventKind::StillCollision, 75.0),
            at(EventKind::BadDeRecord, 105.0),
            at(EventKind::BadAttribute, 135.0),
            at(EventKind::MissingExtension, 165.0),
        ],
        ..base
    };
    let (_, events) = monitor(&generate(&cfg));
    // Each finding, by its rule and a phrase of its message.
    let phrases = [
        ("attribute", "a record has type"),
        ("attribute", "no Attribute PDU follows"),
        ("collision", "COLLISION_THRSH"),
        ("directed-energy", "a DE record of type 4500"),
        ("fire-detonation", "category Fixed"),
        ("fire-detonation", "from the target's dead-reckoned position"),
    ];
    let mut got: Vec<(&str, &str)> = firing(&events)
        .iter()
        .map(|e| {
            let phrase = phrases
                .iter()
                .find(|(rule, p)| *rule == e.alert.rule.name() && e.reason.contains(p))
                .map_or("?", |(_, p)| *p);
            (e.alert.rule.name(), phrase)
        })
        .collect();
    got.sort();
    got.dedup();
    assert_eq!(got, phrases, "{}", describe(&events));
}

#[test]
fn emitters_told_right_are_silent_and_each_fault_fires_on_its_own() {
    let base = Config {
        duration: 600.0,
        sites: 2,
        entities_per_site: 4,
        emission_every: Some(40.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    let at = |kind, at| Event {
        kind,
        target: Target::Exercise,
        at,
    };
    let faults = [
        (EventKind::EmitterDropout, "no EE PDU for"),
        (EventKind::EmitterRename, "stay fixed for the exercise"),
        (EventKind::ReservedBeam, "NO_BEAM (0)"),
        (EventKind::DenseTargets, "High Density Track/Jam is Selected"),
        (EventKind::HalfPulsed, "continuous wave is both 0.0"),
        (EventKind::NoSiteTarget, "uses NO_SITE"),
        (EventKind::RepeatDeactivated, "reported Deactivated again"),
        (EventKind::DestroyedEmitting, "the entity is Destroyed"),
    ];
    for (kind, phrase) in faults {
        let cfg = Config {
            events: vec![at(kind, 30.0)],
            ..base.clone()
        };
        let (_, events) = monitor(&generate(&cfg));
        let fired = firing(&events);
        assert!(
            !fired.is_empty()
                && fired
                    .iter()
                    .all(|e| e.alert.rule == Rule::Emission && e.reason.contains(phrase)),
            "{}: {}",
            kind.name(),
            describe(&events)
        );
    }
}

#[test]
fn alerts_carry_the_pdu_that_raised_them() {
    // A wrong Protocol Family on site 1's IFF at 30 s, and entity 1:1:1
    // falling silent: the first is raised by a PDU, the second by silence.
    let cfg = Config {
        duration: 90.0,
        all_types: Some(10.0),
        events: vec![
            Event {
                kind: EventKind::WrongFamily,
                target: Target::Pdu { site: 1, pdu_type: 28 },
                at: 30.0,
            },
            Event {
                kind: EventKind::DropHeartbeat,
                target: Target::Entity(EntityId::new(1, 1, 1)),
                at: 30.0,
            },
        ],
        ..Default::default()
    };
    let datagrams = generate(&cfg);
    let (_, events) = monitor(&datagrams);
    let family = firing(&events)
        .into_iter()
        .find(|e| e.alert.rule == Rule::PduFamily)
        .expect("wrong family raised");
    let pdu = family.pdu.as_ref().expect("the family alert carries its PDU");
    assert_eq!(pdu[2], 28, "the IFF PDU itself");
    assert!(
        datagrams
            .iter()
            .any(|d| d.payload.windows(pdu.len()).any(|w| w == &pdu[..])),
        "byte for byte as it was received"
    );
    let timeout = firing(&events)
        .into_iter()
        .find(|e| e.alert.rule == Rule::EntityTimeout)
        .expect("timeout raised");
    assert!(timeout.pdu.is_none(), "silence has no PDU");
}

#[test]
fn designations_told_right_are_silent_and_each_fault_fires_on_its_own() {
    let base = Config {
        duration: 400.0,
        sites: 2,
        entities_per_site: 4,
        designator_every: Some(40.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    let faults = [
        (EventKind::SpotOffset, 30.0, "D-SPOT_NO_ENTITY"),
        // After the monitor's stationary-timeout grace (144 s).
        (EventKind::UnknownDesignated, 200.0, "isn't an entity in the exercise"),
        (EventKind::TargetGone, 30.0, "after it ceased to exist"),
        (EventKind::DesignatorGone, 30.0, "with its designator on"),
    ];
    for (kind, at, phrase) in faults {
        let cfg = Config {
            events: vec![Event {
                kind,
                target: Target::Exercise,
                at,
            }],
            ..base.clone()
        };
        let (_, events) = monitor(&generate(&cfg));
        let fired = firing(&events);
        assert!(
            !fired.is_empty()
                && fired
                    .iter()
                    .all(|e| e.alert.rule == Rule::Designator && e.reason.contains(phrase)),
            "{}: {}",
            kind.name(),
            describe(&events)
        );
    }
}

#[test]
fn iff_told_right_is_silent_and_each_fault_fires_on_its_own() {
    let base = Config {
        duration: 300.0,
        sites: 2,
        iff_every: Some(40.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    let faults = [
        (EventKind::IffMissingLayer, "mode5-missing"),
        (EventKind::IffLayerBits, "layer-bits"),
        (EventKind::IffLayerOrder, "layer-order"),
        (EventKind::IffEmptyLayer2, "layer2-no-parameters"),
        (EventKind::IffUnflaggedChange, "change-unflagged"),
        (EventKind::IffHeartbeatUnflagged, "heartbeat-unflagged"),
        (EventKind::IffModeMismatch, "mode-mismatch"),
        (EventKind::IffDestroyedOn, "destroyed-on"),
    ];
    for (kind, finding) in faults {
        let cfg = Config {
            events: vec![Event {
                kind,
                target: Target::Exercise,
                at: 65.0,
            }],
            ..base.clone()
        };
        let (_, events) = monitor(&generate(&cfg));
        let fired = firing(&events);
        assert!(
            !fired.is_empty()
                && fired
                    .iter()
                    .all(|e| e.alert.rule == Rule::Iff && e.alert.kind == finding),
            "{}: {}",
            kind.name(),
            describe(&events)
        );
    }
}

#[test]
fn logistics_told_right_is_silent_and_each_fault_fires_on_its_own() {
    let base = Config {
        duration: 400.0,
        sites: 2,
        logistics_every: Some(20.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    // The answers to nothing after the monitor's startup grace (144 s).
    let faults = [
        (EventKind::LogisticsNoOffer, 30.0, "no-offer"),
        (EventKind::LogisticsNoReceipt, 30.0, "no-receipt"),
        (EventKind::ReceivedMore, 30.0, "received-more"),
        (EventKind::NoRepairResponse, 30.0, "no-repair-response"),
        (EventKind::RepairCancelResult, 30.0, "cancel-result"),
        (EventKind::SuppliesOnRepair, 30.0, "supplies-on-repair"),
        (EventKind::UnsolicitedOffer, 200.0, "unsolicited-offer"),
        (EventKind::OrphanReceived, 200.0, "orphan-received"),
        (EventKind::UnrequestedRepair, 200.0, "unrequested-repair"),
        (EventKind::OrphanRepairResponse, 200.0, "orphan-repair-response"),
        (EventKind::UnknownSupplier, 200.0, "unknown-supplier"),
    ];
    for (kind, at, finding) in faults {
        let cfg = Config {
            events: vec![Event {
                kind,
                target: Target::Exercise,
                at,
            }],
            ..base.clone()
        };
        let (_, events) = monitor(&generate(&cfg));
        let fired = firing(&events);
        assert!(
            !fired.is_empty()
                && fired
                    .iter()
                    .all(|e| e.alert.rule == Rule::Logistics && e.alert.kind == finding),
            "{}: {}",
            kind.name(),
            describe(&events)
        );
    }
}

#[test]
fn transfers_told_right_are_silent_and_each_fault_fires_on_its_own() {
    let base = Config {
        duration: 400.0,
        sites: 3,
        transfer_every: Some(25.0),
        all_types: Some(10.0),
        ..Default::default()
    };
    for version in [6, 7] {
        let (_, events) = monitor(&generate(&Config {
            version,
            ..base.clone()
        }));
        assert!(events.is_empty(), "v{version}\n{}", describe(&events));
    }
    let faults = [
        (EventKind::TransferLingering, "lingering-owner"),
        (EventKind::TransferReliability, "reliability"),
        (EventKind::TransferIndicator, "transferred-indicator"),
        (EventKind::TransferAttributes, "attributes-changed"),
        (EventKind::TransferNoReport, "no-event-report"),
        (EventKind::TransferConcurrent, "concurrent"),
        (EventKind::TransferInactive, "inactive-entity"),
        (EventKind::TransferStalled, "stalled"),
    ];
    for (kind, finding) in faults {
        let cfg = Config {
            events: vec![Event {
                kind,
                target: Target::Exercise,
                at: 60.0,
            }],
            ..base.clone()
        };
        let (_, events) = monitor(&generate(&cfg));
        let fired = firing(&events);
        assert!(
            !fired.is_empty()
                && fired
                    .iter()
                    .all(|e| e.alert.rule == Rule::TransferOwnership && e.alert.kind == finding),
            "{}: {}",
            kind.name(),
            describe(&events)
        );
    }
}

#[test]
fn user_monitors_open_alerts_through_the_normal_path() {
    use nn_rules::monitors::MonitorDef;
    // Site 2's simulator restarts on a new port at 60 s: its old address
    // goes quiet (an absence by sender), and site 1 clones an entity ID at
    // 90 s (an event-count on id-conflict).
    let cfg = Config {
        duration: 150.0,
        events: vec![
            Event {
                kind: EventKind::RestartPort,
                target: Target::Site(2),
                at: 60.0,
            },
            Event {
                kind: EventKind::CloneId,
                target: Target::Entity(EntityId::new(1, 1, 2)),
                at: 90.0,
            },
        ],
        ..Default::default()
    };
    let defs = MonitorDef::parse_all(
        r#"
[[monitor]]
id = "quiet-sender"
name = "Sender went quiet"
type = "absence"
metric = "pdu.count"
by = ["sender"]
for = 15
severity = "critical"

[[monitor]]
id = "conflicts"
type = "event-count"
event = "id-conflict"
window = 60
"#,
    )
    .unwrap();
    let mut m = Monitor::new(RuleConfig::default());
    assert!(m.set_monitors(defs).is_empty());
    let mut events = Vec::new();
    for d in generate(&cfg) {
        events.extend(m.ingest(&d).1);
    }
    let mine: Vec<&AlertEvent> = firing(&events)
        .into_iter()
        .filter(|e| e.alert.rule == Rule::UserMonitor)
        .collect();
    let ids: Vec<&str> = mine.iter().map(|e| e.alert.rule_id.as_str()).collect();
    assert_eq!(mine.len(), 2, "{ids:?}\n{}", describe(&events));
    let quiet = mine
        .iter()
        .find(|e| e.alert.rule_id.starts_with("quiet-sender@sender="))
        .expect("absence");
    assert_eq!(quiet.alert.severity, nn_rules::Severity::Critical);
    assert!(
        quiet.reason.starts_with("Sender went quiet (sender="),
        "{}",
        quiet.reason
    );
    assert!(quiet.alert.sender.is_some(), "pinned on the quiet sender");
    assert!(mine.iter().any(|e| e.alert.rule_id == "conflicts"), "{ids:?}");
    // Open, like any alert: in the engine's active list, ackable.
    assert_eq!(m.engine.active().filter(|a| a.rule == Rule::UserMonitor).count(), 2);
    let id = quiet.alert.rule_id.clone();
    assert!(m.engine.ack(&id, quiet.alert.key, "op", "seen", 200.0));
    // Removing the monitors resolves their alerts.
    let gone = m.set_monitors(Vec::new());
    assert_eq!(gone.iter().filter(|e| e.state == AlertState::Resolved).count(), 2);
}
