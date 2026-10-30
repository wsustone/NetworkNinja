//! Milestone 2–3 checks against the synthetic generator:
//! every injected fault fires the right alert on the right entity in time,
//! control scenarios stay silent, a long clean run stays silent, and entity
//! counts and rates match ground truth.

use nn_capture::Datagram;
use nn_decode::{decode_datagram, EntityId, PduBody};
use nn_generator::{run, Config, Event, EventKind, Sender, Sink, Target};
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
        let host = if s.rogue { 250 } else { 10 };
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
