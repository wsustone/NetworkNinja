//! Traffic patterns from real exercises that the synthetic generator does not
//! produce yet: body-axis dead reckoning, clock steps, long outages, targeted
//! freezes, gateway duplicates, tracked munitions and wildcard IDs.
//!
//! Each test asserts the behaviour the spec asks for. Tests for known issues
//! from the October 2026 code review are `#[ignore]`d with the finding number;
//! remove the attribute when the fix lands. Run them all with
//! `cargo test -p nn-rules --test field_scenarios -- --include-ignored`.

use nn_capture::Datagram;
use nn_decode::*;
use nn_rules::{AlertEvent, AlertState, Monitor, Rule, RuleConfig};
use nn_state::geo;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LAT: f64 = 36.6;
const LON: f64 = -121.9;

fn start() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_798_761_600)
}

fn host(last: u8, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, last), port))
}

fn id(site: u16, entity: u16) -> EntityId {
    EntityId::new(site, 1, entity)
}

fn datagram(t: f64, source: SocketAddr, payload: Vec<u8>) -> Datagram {
    Datagram {
        received_at: start() + Duration::from_secs_f64(t),
        source,
        destination: None,
        payload,
    }
}

fn encode(pdu_type: u8, body: PduBody) -> Vec<u8> {
    encode_pdu(&Pdu {
        header: PduHeader::new(7, 1, pdu_type, DisTimestamp(0)),
        body,
    })
}

/// A stationary land vehicle (DR algorithm 1).
fn parked(entity: EntityId) -> Vec<u8> {
    entity_state(
        entity,
        (1, 1),
        geo::lla_to_ecef(LAT, LON, 10.0),
        Vec3f::default(),
        1,
        EulerAngles::default(),
    )
}

fn entity_state(
    entity_id: EntityId,
    (kind, domain): (u8, u8),
    location: WorldCoord,
    linear_velocity: Vec3f,
    algorithm: u8,
    orientation: EulerAngles,
) -> Vec<u8> {
    let entity_type = EntityType {
        kind,
        domain,
        country: 225,
        category: 1,
        subcategory: 1,
        specific: 0,
        extra: 0,
    };
    encode(
        pdu_type::ENTITY_STATE,
        PduBody::EntityState(EntityState {
            entity_id,
            force_id: 1,
            entity_type,
            alternative_entity_type: entity_type,
            linear_velocity,
            location,
            orientation,
            appearance: 0,
            dead_reckoning: DeadReckoning {
                algorithm,
                ..Default::default()
            },
            marking: Marking::ascii("FIELD"),
            capabilities: 0,
            variable_parameters: Vec::new(),
        }),
    )
}

/// Feeds datagrams through one monitor and collects every alert event.
struct Run {
    monitor: Monitor,
    events: Vec<AlertEvent>,
}

impl Run {
    fn new() -> Self {
        Run {
            monitor: Monitor::new(RuleConfig::default()),
            events: Vec::new(),
        }
    }

    fn feed(&mut self, t: f64, source: SocketAddr, payload: Vec<u8>) {
        let (_, events) = self.monitor.ingest(&datagram(t, source, payload));
        self.events.extend(events);
    }

    fn fired(&self) -> Vec<(Rule, EntityId)> {
        self.events
            .iter()
            .filter(|e| e.state == AlertState::Firing)
            .map(|e| (e.alert.rule, e.alert.key.id))
            .collect()
    }

    fn log(&self) -> String {
        self.events
            .iter()
            .map(|e| format!("{:?} {} {}: {}", e.state, e.alert.rule.name(), e.alert.key, e.reason))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// IEEE 1278.1: for DR algorithms 6–9 the Entity State linear velocity is in
/// body axes. A straight, level aircraft only needs heartbeats, and the
/// monitor's extrapolation must agree with the sender's.
#[test]
#[ignore = "known issue: body-axis velocity treated as world frame (review finding 1)"]
fn body_axis_aircraft_in_straight_flight_does_not_jump() {
    // DIS Euler angles of a level aircraft heading north, relative to ECEF.
    let north = geo::enu_to_ecef(LAT, LON, 0.0, 1.0, 0.0);
    let orientation = EulerAngles {
        psi: (north.y as f64).atan2(north.x as f64) as f32,
        theta: (-(north.z as f64)).asin() as f32,
        phi: 0.0,
    };
    let (m_per_deg_lat, _) = geo::metres_per_degree(LAT);
    let forward = Vec3f {
        x: 200.0,
        y: 0.0,
        z: 0.0,
    };
    for algorithm in [6, 8] {
        let mut run = Run::new();
        for i in 0..6 {
            let t = i as f64 * 5.0;
            let location = geo::lla_to_ecef(LAT + 200.0 * t / m_per_deg_lat, LON, 3000.0);
            let pdu = entity_state(id(1, 1), (1, 2), location, forward, algorithm, orientation);
            run.feed(t, host(1, 4000), pdu);
        }
        assert!(run.fired().is_empty(), "DR algorithm {algorithm}:\n{}", run.log());
    }
}

/// An NTP or PTP step on the monitor host must not look like every entity
/// going silent at once.
///
/// Note: this models the step by shifting receive stamps. If `Datagram` gains
/// a separate monotonic stamp as part of the fix, feed that here instead.
#[test]
#[ignore = "known issue: wall-clock time drives timeouts (review finding 2)"]
fn host_clock_step_does_not_time_out_healthy_entities() {
    let mut run = Run::new();
    for step in 0..200 {
        let t = step as f64 * 0.5;
        let clock_step = if t >= 60.0 { 30.0 } else { 0.0 };
        for e in 0..50u16 {
            if (step + e as usize).is_multiple_of(10) {
                run.feed(t + clock_step, host(1, 4000), parked(id(1, e + 1)));
            }
        }
    }
    assert!(run.fired().is_empty(), "{}", run.log());
}

/// A simulator that drops out stays alerted until it returns or is removed;
/// expiring its record from the table must not quietly resolve the alert.
#[test]
#[ignore = "known issue: pruning resolves open timeout alerts (review finding 3)"]
fn timeout_alert_stays_open_after_the_entity_expires() {
    let mut run = Run::new();
    let mut t = 0.0;
    while t < 900.0 {
        if t < 10.0 {
            run.feed(t, host(1, 4000), parked(id(1, 1)));
        }
        run.feed(t, host(1, 4000), parked(id(1, 2)));
        t += 1.0;
    }
    assert_eq!(run.fired(), vec![(Rule::EntityTimeout, id(1, 1))], "{}", run.log());
    let resolved = run
        .events
        .iter()
        .any(|e| e.state == AlertState::Resolved && e.alert.rule == Rule::EntityTimeout);
    assert!(!resolved, "{}", run.log());
}

/// A Stop/Freeze addressed to one simulation application freezes that
/// application, not the whole exercise.
#[test]
#[ignore = "known issue: Stop/Freeze receiving ID ignored (review finding 4)"]
fn freeze_for_one_application_does_not_mute_the_others() {
    let freeze_site_2 = encode(
        pdu_type::STOP_FREEZE,
        PduBody::StopFreeze(StopFreeze {
            originating: EntityId::new(9, 9, 0xffff),
            receiving: EntityId::new(2, 1, 0xffff),
            real_world_time: ClockTime::default(),
            reason: 6, // stop for reset
            frozen_behavior: 0,
            request_id: 1,
        }),
    );
    let mut run = Run::new();
    for step in 0..120 {
        let t = step as f64;
        if t < 20.0 {
            run.feed(t, host(1, 4000), parked(id(1, 1)));
        }
        if step == 10 {
            run.feed(t, host(9, 4000), freeze_site_2.clone());
        }
        run.feed(t, host(2, 4000), parked(id(2, 1)));
    }
    assert_eq!(run.fired(), vec![(Rule::EntityTimeout, id(1, 1))], "{}", run.log());
}

/// The same PDUs seen again from a gateway (or a second NIC, or both legs of
/// a SPAN port) are duplicates, not two simulators claiming one Entity ID.
#[test]
#[ignore = "known issue: relayed duplicates raise ID conflicts (review finding 5)"]
fn relayed_duplicates_are_not_id_conflicts() {
    let mut run = Run::new();
    for i in 0..10 {
        let t = i as f64 * 5.0;
        for e in 1..=3 {
            let pdu = parked(id(1, e));
            run.feed(t, host(1, 4000), pdu.clone());
            run.feed(t + 0.003, host(200, 3000), pdu);
        }
    }
    assert!(run.fired().is_empty(), "{}", run.log());
}

/// A tracked munition reports while in flight, detonates, and goes quiet
/// without a Remove Entity. That is the end of its life, not a dropout.
#[test]
#[ignore = "known issue: Detonation does not end the munition entity (review finding 6)"]
fn detonated_munition_does_not_time_out() {
    let munition = id(1, 500);
    let mut run = Run::new();
    for i in 0..10 {
        let pdu = entity_state(
            munition,
            (2, 2),
            geo::lla_to_ecef(LAT, LON, 10.0),
            Vec3f::default(),
            1,
            EulerAngles::default(),
        );
        run.feed(i as f64 * 0.2, host(1, 4000), pdu);
    }
    let detonation = encode(
        pdu_type::DETONATION,
        PduBody::Detonation(Detonation {
            firing_entity: id(1, 1),
            target_entity: id(2, 1),
            munition_id: munition,
            event_id: EventId::default(),
            velocity: Vec3f::default(),
            location: geo::lla_to_ecef(LAT, LON, 10.0),
            descriptor: BurstDescriptor::default(),
            location_in_entity: Vec3f::default(),
            result: 1,
            variable_parameters: Vec::new(),
        }),
    );
    run.feed(2.0, host(1, 4000), detonation);
    // Something else keeps reporting, so time moves on past the timeout.
    for i in 0..15 {
        run.feed(2.0 + i as f64 * 2.0, host(1, 4000), parked(id(1, 1)));
    }
    assert!(run.fired().is_empty(), "{}", run.log());
}

/// Entity number 65535 means "all entities" of that site and application.
#[test]
#[ignore = "known issue: wildcard Entity IDs not expanded (review finding 7)"]
fn wildcard_remove_entity_removes_every_entity_of_the_application() {
    let remove_all = encode(
        pdu_type::REMOVE_ENTITY,
        PduBody::RemoveEntity(RemoveEntity {
            originating: EntityId::new(9, 9, 0xffff),
            receiving: EntityId::new(1, 1, 0xffff),
            request_id: 1,
        }),
    );
    let mut run = Run::new();
    for e in 1..=3 {
        run.feed(0.0, host(1, 4000), parked(id(1, e)));
    }
    run.feed(1.0, host(9, 4000), remove_all);
    for i in 0..15 {
        run.feed(1.0 + i as f64 * 2.0, host(2, 4000), parked(id(2, 1)));
    }
    assert!(run.fired().is_empty(), "{}", run.log());
}
