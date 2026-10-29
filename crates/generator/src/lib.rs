//! Synthetic DIS traffic with fault injection.
//!
//! Simulates entities from several sites driving in circles, sending Entity
//! State PDUs the way a real simulator does: whenever the dead-reckoning error
//! passes a threshold, and otherwise on a heartbeat. Faults and control
//! scenarios are scheduled at fixed times so every alert rule has something
//! to catch, and so do the "must stay quiet" cases.
//!
//! The run is deterministic for a given [`Config`] (seeded RNG, fixed time
//! step), and returns a [`Truth`] summary that later milestones compare
//! against what the monitor reports.

pub use nn_state::geo;

use nn_decode::*;
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Simulation time step, seconds.
pub const TICK: f64 = 0.05;
/// Largest datagram built when bundling PDUs.
pub const BUNDLE_LIMIT: usize = 1400;
/// Origin of the synthetic exercise area.
const ORIGIN_LAT: f64 = 36.60;
const ORIGIN_LON: f64 = -121.90;
/// Fixed application number for every synthetic site.
const APPLICATION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Fault: the entity goes silent without a Remove Entity PDU.
    DropHeartbeat,
    /// Fault: a second sender starts sending the same Entity ID.
    CloneId,
    /// Fault: the entity jumps 20 km beyond its dead-reckoned path.
    Teleport,
    /// Control: a clean Remove Entity, then silence.
    Remove,
    /// Control: the site's simulator restarts on a new source port.
    RestartPort,
    /// Control: Stop/Freeze for the whole exercise.
    Freeze,
    /// Control: Start/Resume after a freeze.
    Resume,
}

impl EventKind {
    pub fn name(self) -> &'static str {
        match self {
            EventKind::DropHeartbeat => "drop-heartbeat",
            EventKind::CloneId => "clone-id",
            EventKind::Teleport => "teleport",
            EventKind::Remove => "remove",
            EventKind::RestartPort => "restart-port",
            EventKind::Freeze => "freeze",
            EventKind::Resume => "resume",
        }
    }
    /// True for faults that an alert rule should catch.
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            EventKind::DropHeartbeat | EventKind::CloneId | EventKind::Teleport
        )
    }
}

/// What an event applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Entity(EntityId),
    Site(u16),
    Exercise,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Entity(e) => write!(f, "{e}"),
            Target::Site(s) => write!(f, "site {s}"),
            Target::Exercise => write!(f, "exercise"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub target: Target,
    pub at: f64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub version: u8,
    pub exercise: u8,
    pub sites: u16,
    pub entities_per_site: u16,
    pub duration: f64,
    pub heartbeat: f64,
    pub dr_threshold: f64,
    pub seed: u64,
    /// Seconds between Fire events (each followed by a Detonation 2 s later).
    pub fire_every: Option<f64>,
    /// Pack each sender's PDUs from one tick into shared datagrams.
    pub bundle: bool,
    /// Simulators stop sending while the exercise is frozen (some do; the
    /// default keeps heartbeating with the frozen appearance bit set).
    pub silent_when_frozen: bool,
    pub events: Vec<Event>,
    /// Wall-clock time of simulation time zero (for DIS timestamps).
    pub start_time: SystemTime,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            version: 7,
            exercise: 1,
            sites: 2,
            entities_per_site: 10,
            duration: 60.0,
            heartbeat: 5.0,
            dr_threshold: 1.0,
            seed: 1,
            fire_every: None,
            bundle: false,
            silent_when_frozen: false,
            events: Vec::new(),
            start_time: UNIX_EPOCH + Duration::from_secs(1_798_761_600), // 2027-01-01T00:00:00Z
        }
    }
}

/// Who sends a datagram. Sinks map this to a source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sender {
    pub site: u16,
    /// Incremented when the site's simulator restarts on a new port.
    pub generation: u16,
    /// The rogue simulator that clones an Entity ID.
    pub rogue: bool,
}

/// Where generated datagrams go.
pub trait Sink {
    /// Called in non-decreasing order of `t` (simulation seconds).
    fn emit(&mut self, t: f64, sender: Sender, datagram: &[u8]) -> io::Result<()>;
}

/// Ground truth for one run.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Truth {
    pub version: u8,
    pub exercise: u8,
    pub duration: f64,
    pub entities: Vec<EntityId>,
    pub datagrams: u64,
    pub bytes: u64,
    pub pdus_by_type: BTreeMap<&'static str, u64>,
    pub entity_states_by_entity: BTreeMap<EntityId, u64>,
    /// Events as they happened, in time order.
    pub events: Vec<Event>,
}

impl Truth {
    pub fn total_pdus(&self) -> u64 {
        self.pdus_by_type.values().sum()
    }

    pub fn to_json(&self) -> String {
        let mut s = String::from("{\n");
        s += &format!("  \"version\": {},\n  \"exercise\": {},\n", self.version, self.exercise);
        s += &format!("  \"duration_s\": {},\n", self.duration);
        s += &format!("  \"entities\": {},\n", self.entities.len());
        s += &format!("  \"datagrams\": {},\n  \"bytes\": {},\n", self.datagrams, self.bytes);
        s += &format!("  \"pdus_total\": {},\n  \"pdus_by_type\": {{", self.total_pdus());
        let types: Vec<String> = self.pdus_by_type.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        s += &types.join(", ");
        s += "},\n  \"events\": [";
        let evs: Vec<String> = self
            .events
            .iter()
            .map(|e| {
                format!(
                    "\n    {{\"kind\": \"{}\", \"fault\": {}, \"target\": \"{}\", \"at_s\": {:.2}}}",
                    e.kind.name(),
                    e.kind.is_fault(),
                    e.target,
                    e.at
                )
            })
            .collect();
        s += &evs.join(",");
        if !evs.is_empty() {
            s += "\n  ";
        }
        s += "]\n}\n";
        s
    }
}

// ---------------------------------------------------------------- simulation

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in [lo, hi).
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * (hi - lo)
    }
}

struct SimEntity {
    id: EntityId,
    entity_type: EntityType,
    marking: Marking,
    force: u8,
    /// Circle centre, metres east/north of the origin.
    centre_e: f64,
    centre_n: f64,
    radius: f64,
    speed: f64,
    phase: f64,
    sending: bool,
    last_sent: f64,
    last_pos: WorldCoord,
    last_vel: Vec3f,
}

impl SimEntity {
    /// Location, velocity and heading at motion time `m`.
    fn kinematics(&self, m: f64) -> (WorldCoord, Vec3f, f32) {
        let w = self.speed / self.radius;
        let a = self.phase + w * m;
        let (e, n) = (
            self.centre_e + self.radius * a.cos(),
            self.centre_n + self.radius * a.sin(),
        );
        let (ve, vn) = (-self.radius * w * a.sin(), self.radius * w * a.cos());
        let (mlat, mlon) = geo::metres_per_degree(ORIGIN_LAT);
        let lat = ORIGIN_LAT + n / mlat;
        let lon = ORIGIN_LON + e / mlon;
        let pos = geo::lla_to_ecef(lat, lon, 10.0);
        let vel = geo::enu_to_ecef(lat, lon, ve, vn, 0.0);
        let heading = ve.atan2(vn) as f32;
        (pos, vel, heading)
    }

    fn dr_error(&self, t: f64, pos: &WorldCoord) -> f64 {
        let dt = t - self.last_sent;
        let predicted = WorldCoord {
            x: self.last_pos.x + self.last_vel.x as f64 * dt,
            y: self.last_pos.y + self.last_vel.y as f64 * dt,
            z: self.last_pos.z + self.last_vel.z as f64 * dt,
        };
        geo::distance(&predicted, pos)
    }
}

fn find(entities: &[SimEntity], id: &EntityId) -> Option<usize> {
    entities.iter().position(|e| e.id == *id)
}

/// Run the scenario, sending every datagram to `sink`.
pub fn run(cfg: &Config, sink: &mut dyn Sink) -> io::Result<Truth> {
    let mut rng = Rng::new(cfg.seed);
    let mut entities: Vec<SimEntity> = Vec::new();
    for s in 0..cfg.sites {
        let site = s + 1;
        let (base_e, base_n) = (s as f64 * 8000.0, 0.0);
        for i in 0..cfg.entities_per_site {
            let id = EntityId::new(site, APPLICATION, i + 1);
            entities.push(SimEntity {
                id,
                entity_type: EntityType {
                    kind: 1,
                    domain: 1,
                    country: 225,
                    category: 1 + (s % 3) as u8,
                    subcategory: 1,
                    specific: 1,
                    extra: 0,
                },
                marking: Marking::ascii(&format!("S{site}V{:02}", i + 1)),
                force: 1 + (s % 2) as u8,
                centre_e: base_e + rng.range(0.0, 4000.0),
                centre_n: base_n + rng.range(0.0, 4000.0),
                radius: rng.range(500.0, 3000.0),
                speed: rng.range(5.0, 25.0),
                phase: rng.range(0.0, std::f64::consts::TAU),
                sending: true,
                // Stagger first reports across one heartbeat.
                last_sent: -rng.range(0.0, cfg.heartbeat),
                last_pos: WorldCoord::default(),
                last_vel: Vec3f::default(),
            });
        }
    }

    let mut truth = Truth {
        version: cfg.version,
        exercise: cfg.exercise,
        duration: cfg.duration,
        entities: entities.iter().map(|e| e.id).collect(),
        ..Default::default()
    };

    let mut pending: Vec<Event> = cfg.events.clone();
    pending.sort_by(|a, b| a.at.total_cmp(&b.at));
    let mut next_event = 0;

    let mut generation: BTreeMap<u16, u16> = BTreeMap::new();
    let mut frozen = false;
    let mut motion_time = 0.0;
    let mut clone_of: Option<(usize, f64)> = None; // (entity index, last sent)
    let mut fire_count: u16 = 0;
    let mut next_fire = cfg.fire_every.unwrap_or(f64::INFINITY);
    let mut detonations: Vec<(f64, Detonation)> = Vec::new();
    let sim_address = |site: u16| EntityId::new(site, APPLICATION, 0xffff);
    let everyone = EntityId::new(0xffff, 0xffff, 0xffff);

    let steps = (cfg.duration / TICK).round() as u64;
    for step in 0..=steps {
        let t = step as f64 * TICK;
        let wall = cfg.start_time + Duration::from_secs_f64(t);
        let since_epoch = wall.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let stamp = DisTimestamp::from_seconds_past_hour(since_epoch, true);
        let clock = ClockTime {
            hour: (since_epoch / 3600.0) as i32,
            time_past_hour: stamp.0 >> 1,
        };
        let header = |pdu_type: u8| PduHeader::new(cfg.version, cfg.exercise, pdu_type, stamp);
        let gen_of = |g: &BTreeMap<u16, u16>, site: u16| Sender {
            site,
            generation: *g.get(&site).unwrap_or(&0),
            rogue: false,
        };

        // Each sender's PDUs for this tick, in order.
        let mut out: Vec<(Sender, Pdu)> = Vec::new();

        if step == 0 {
            out.push((
                gen_of(&generation, 1),
                Pdu {
                    header: header(pdu_type::START_RESUME),
                    body: PduBody::StartResume(StartResume {
                        originating: sim_address(1),
                        receiving: everyone,
                        real_world_time: clock,
                        simulation_time: ClockTime::default(),
                        request_id: 1,
                    }),
                },
            ));
        }

        while next_event < pending.len() && pending[next_event].at <= t + 1e-9 {
            let ev = pending[next_event];
            next_event += 1;
            let applied = match (ev.kind, ev.target) {
                (EventKind::DropHeartbeat, Target::Entity(id)) => {
                    find(&entities, &id).map(|i| entities[i].sending = false)
                }
                (EventKind::Teleport, Target::Entity(id)) => {
                    find(&entities, &id).map(|i| entities[i].centre_e += 20_000.0)
                }
                (EventKind::CloneId, Target::Entity(id)) => {
                    find(&entities, &id).map(|i| clone_of = Some((i, f64::NEG_INFINITY)))
                }
                (EventKind::Remove, Target::Entity(id)) => find(&entities, &id).map(|i| {
                    entities[i].sending = false;
                    out.push((
                        gen_of(&generation, id.site),
                        Pdu {
                            header: header(pdu_type::REMOVE_ENTITY),
                            body: PduBody::RemoveEntity(RemoveEntity {
                                originating: sim_address(id.site),
                                receiving: id,
                                request_id: 100 + i as u32,
                            }),
                        },
                    ));
                }),
                (EventKind::RestartPort, Target::Site(site)) => {
                    *generation.entry(site).or_insert(0) += 1;
                    Some(())
                }
                (EventKind::Freeze, _) => {
                    frozen = true;
                    out.push((
                        gen_of(&generation, 1),
                        Pdu {
                            header: header(pdu_type::STOP_FREEZE),
                            body: PduBody::StopFreeze(StopFreeze {
                                originating: sim_address(1),
                                receiving: everyone,
                                real_world_time: clock,
                                reason: 2, // recess
                                frozen_behavior: 1,
                                request_id: 2,
                            }),
                        },
                    ));
                    Some(())
                }
                (EventKind::Resume, _) => {
                    frozen = false;
                    out.push((
                        gen_of(&generation, 1),
                        Pdu {
                            header: header(pdu_type::START_RESUME),
                            body: PduBody::StartResume(StartResume {
                                originating: sim_address(1),
                                receiving: everyone,
                                real_world_time: clock,
                                simulation_time: ClockTime::default(),
                                request_id: 3,
                            }),
                        },
                    ));
                    Some(())
                }
                _ => None,
            };
            if applied.is_some() {
                truth.events.push(Event { at: t, ..ev });
            }
        }

        if !frozen && step > 0 {
            motion_time += TICK;
        }

        let appearance_bits = if frozen { appearance::FROZEN } else { 0 };
        let make_state = |e: &SimEntity, pos: WorldCoord, vel: Vec3f, heading: f32, marking: Marking| Pdu {
            header: header(pdu_type::ENTITY_STATE),
            body: PduBody::EntityState(EntityState {
                entity_id: e.id,
                force_id: e.force,
                entity_type: e.entity_type,
                alternative_entity_type: e.entity_type,
                linear_velocity: if frozen { Vec3f::default() } else { vel },
                location: pos,
                orientation: EulerAngles {
                    psi: heading,
                    theta: 0.0,
                    phi: 0.0,
                },
                appearance: appearance_bits,
                dead_reckoning: DeadReckoning {
                    algorithm: 2,
                    ..Default::default()
                },
                marking,
                capabilities: 0,
                variable_parameters: Vec::new(),
            }),
        };

        for e in entities.iter_mut() {
            if !e.sending || (frozen && cfg.silent_when_frozen) {
                continue;
            }
            let (pos, vel, heading) = e.kinematics(motion_time);
            let heartbeat_due = t - e.last_sent >= cfg.heartbeat;
            let dr_due = !frozen && e.last_sent >= 0.0 && e.dr_error(t, &pos) > cfg.dr_threshold;
            if heartbeat_due || dr_due {
                let pdu = make_state(e, pos, vel, heading, e.marking);
                e.last_sent = t;
                e.last_pos = pos;
                e.last_vel = if frozen { Vec3f::default() } else { vel };
                out.push((gen_of(&generation, e.id.site), pdu));
            }
        }

        if let Some((i, last)) = clone_of {
            if t - last >= cfg.heartbeat && !(frozen && cfg.silent_when_frozen) {
                let e = &entities[i];
                let (mut pos, vel, heading) = e.kinematics(motion_time);
                pos.z += 500.0; // a different simulator's idea of the same entity
                let pdu = make_state(e, pos, vel, heading, Marking::ascii("CLONE"));
                out.push((
                    Sender {
                        site: e.id.site,
                        generation: 0,
                        rogue: true,
                    },
                    pdu,
                ));
                clone_of = Some((i, t));
            }
        }

        if !frozen && t >= next_fire {
            next_fire += cfg.fire_every.unwrap_or(f64::INFINITY);
            let live: Vec<usize> = (0..entities.len()).filter(|&i| entities[i].sending).collect();
            if live.len() >= 2 {
                let a = live[(rng.next_u64() as usize) % live.len()];
                let others: Vec<usize> = live
                    .iter()
                    .copied()
                    .filter(|&i| entities[i].id.site != entities[a].id.site)
                    .collect();
                let pool = if others.is_empty() {
                    live.iter().copied().filter(|&i| i != a).collect()
                } else {
                    others
                };
                let b = pool[(rng.next_u64() as usize) % pool.len()];
                fire_count = fire_count.wrapping_add(1);
                let (from, _, _) = entities[a].kinematics(motion_time);
                let (to, _, _) = entities[b].kinematics(motion_time);
                let firer = entities[a].id;
                let event_id = EventId {
                    site: firer.site,
                    application: firer.application,
                    event_number: fire_count,
                };
                let munition_id = EntityId::new(firer.site, firer.application, 1000 + fire_count);
                let descriptor = BurstDescriptor {
                    munition_type: EntityType {
                        kind: 2,
                        domain: 1,
                        country: 225,
                        category: 2,
                        subcategory: 1,
                        specific: 0,
                        extra: 0,
                    },
                    warhead: 1000,
                    fuse: 1000,
                    quantity: 1,
                    rate: 0,
                };
                let range = geo::distance(&from, &to) as f32;
                out.push((
                    gen_of(&generation, firer.site),
                    Pdu {
                        header: header(pdu_type::FIRE),
                        body: PduBody::Fire(Fire {
                            firing_entity: firer,
                            target_entity: entities[b].id,
                            munition_id,
                            event_id,
                            fire_mission_index: 0,
                            location: from,
                            descriptor,
                            velocity: Vec3f {
                                x: 0.0,
                                y: 0.0,
                                z: 300.0,
                            },
                            range,
                        }),
                    },
                ));
                detonations.push((
                    t + 2.0,
                    Detonation {
                        firing_entity: firer,
                        target_entity: entities[b].id,
                        munition_id,
                        event_id,
                        velocity: Vec3f {
                            x: 0.0,
                            y: 0.0,
                            z: -250.0,
                        },
                        location: to,
                        descriptor,
                        location_in_entity: Vec3f::default(),
                        result: 1, // entity impact
                        variable_parameters: Vec::new(),
                    },
                ));
            }
        }

        detonations.retain(|(at, d)| {
            if *at <= t + 1e-9 {
                out.push((
                    gen_of(&generation, d.firing_entity.site),
                    Pdu {
                        header: header(pdu_type::DETONATION),
                        body: PduBody::Detonation(d.clone()),
                    },
                ));
                false
            } else {
                true
            }
        });

        // Count and send.
        for (_, pdu) in &out {
            *truth.pdus_by_type.entry(pdu.type_name()).or_insert(0) += 1;
            if let PduBody::EntityState(es) = &pdu.body {
                *truth.entity_states_by_entity.entry(es.entity_id).or_insert(0) += 1;
            }
        }
        let mut by_sender: BTreeMap<Sender, Vec<Vec<u8>>> = BTreeMap::new();
        for (sender, pdu) in &out {
            by_sender.entry(*sender).or_default().push(encode_pdu(pdu));
        }
        for (sender, pdus) in by_sender {
            let datagrams: Vec<Vec<u8>> = if cfg.bundle {
                let mut v: Vec<Vec<u8>> = vec![Vec::new()];
                for p in pdus {
                    if !v.last().unwrap().is_empty() && v.last().unwrap().len() + p.len() > BUNDLE_LIMIT {
                        v.push(Vec::new());
                    }
                    v.last_mut().unwrap().extend(p);
                }
                v
            } else {
                pdus
            };
            for d in datagrams {
                truth.datagrams += 1;
                truth.bytes += d.len() as u64;
                sink.emit(t, sender, &d)?;
            }
        }
    }
    Ok(truth)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Collect(Vec<(f64, Sender, Vec<u8>)>);
    impl Sink for Collect {
        fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
            self.0.push((t, s, d.to_vec()));
            Ok(())
        }
    }

    fn entity_state_times(c: &Collect, id: EntityId, rogue: bool) -> Vec<f64> {
        c.0.iter()
            .filter(|(_, s, _)| s.rogue == rogue)
            .flat_map(|(t, _, d)| decode_datagram(d).into_iter().map(move |p| (*t, p.unwrap())))
            .filter_map(|(t, p)| match p.body {
                PduBody::EntityState(e) if e.entity_id == id => Some(t),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn clean_run_has_heartbeats_and_dr_updates() {
        let cfg = Config {
            duration: 30.0,
            ..Default::default()
        };
        let mut sink = Collect(Vec::new());
        let truth = run(&cfg, &mut sink).unwrap();
        assert_eq!(truth.entities.len(), 20);
        for id in &truth.entities {
            let times = entity_state_times(&sink, *id, false);
            assert!(times.len() >= 6, "{id} sent only {}", times.len());
            for w in times.windows(2) {
                assert!(w[1] - w[0] <= cfg.heartbeat + TICK + 1e-9, "{id} gap {}", w[1] - w[0]);
            }
        }
        // Every datagram decodes cleanly.
        let decoded: u64 = sink
            .0
            .iter()
            .map(|(_, _, d)| decode_datagram(d).iter().filter(|r| r.is_ok()).count() as u64)
            .sum();
        assert_eq!(decoded, truth.total_pdus());
    }

    #[test]
    fn faults_and_controls_take_effect() {
        let id = |e| EntityId::new(1, 1, e);
        let cfg = Config {
            duration: 40.0,
            events: vec![
                Event {
                    kind: EventKind::DropHeartbeat,
                    target: Target::Entity(id(1)),
                    at: 10.0,
                },
                Event {
                    kind: EventKind::Remove,
                    target: Target::Entity(id(2)),
                    at: 10.0,
                },
                Event {
                    kind: EventKind::CloneId,
                    target: Target::Entity(id(3)),
                    at: 15.0,
                },
                Event {
                    kind: EventKind::Teleport,
                    target: Target::Entity(id(4)),
                    at: 20.0,
                },
                Event {
                    kind: EventKind::RestartPort,
                    target: Target::Site(2),
                    at: 20.0,
                },
                Event {
                    kind: EventKind::Freeze,
                    target: Target::Exercise,
                    at: 25.0,
                },
                Event {
                    kind: EventKind::Resume,
                    target: Target::Exercise,
                    at: 30.0,
                },
            ],
            ..Default::default()
        };
        let mut sink = Collect(Vec::new());
        let truth = run(&cfg, &mut sink).unwrap();
        assert_eq!(truth.events.len(), 7);

        assert!(entity_state_times(&sink, id(1), false).iter().all(|&t| t < 10.0));
        assert!(entity_state_times(&sink, id(2), false).iter().all(|&t| t < 10.0));
        assert_eq!(truth.pdus_by_type["RemoveEntity"], 1);

        let clones = entity_state_times(&sink, id(3), true);
        assert!(!clones.is_empty() && clones[0] >= 15.0);

        assert_eq!(truth.pdus_by_type["StopFreeze"], 1);
        assert_eq!(truth.pdus_by_type["StartResume"], 2);

        let gens: std::collections::BTreeSet<u16> = sink
            .0
            .iter()
            .filter(|(_, s, _)| s.site == 2 && !s.rogue)
            .map(|(_, s, _)| s.generation)
            .collect();
        assert_eq!(gens.into_iter().collect::<Vec<_>>(), vec![0, 1]);

        // Teleport: the first report after 20 s is ~20 km from the last one before it.
        let mut before = None;
        let mut after = None;
        for (t, _, d) in &sink.0 {
            for p in decode_datagram(d) {
                if let PduBody::EntityState(e) = p.unwrap().body {
                    if e.entity_id == id(4) && e.marking.text() != "CLONE" {
                        if *t < 20.0 {
                            before = Some(e.location);
                        } else if after.is_none() {
                            after = Some(e.location);
                        }
                    }
                }
            }
        }
        let jump = geo::distance(&before.unwrap(), &after.unwrap());
        assert!(jump > 15_000.0, "jump was {jump}");
    }

    #[test]
    fn frozen_entities_still_heartbeat_with_frozen_bit() {
        let cfg = Config {
            duration: 20.0,
            events: vec![
                Event {
                    kind: EventKind::Freeze,
                    target: Target::Exercise,
                    at: 5.0,
                },
                Event {
                    kind: EventKind::Resume,
                    target: Target::Exercise,
                    at: 15.0,
                },
            ],
            ..Default::default()
        };
        let mut sink = Collect(Vec::new());
        run(&cfg, &mut sink).unwrap();
        let mut frozen_reports = 0;
        for (t, _, d) in &sink.0 {
            for p in decode_datagram(d) {
                if let PduBody::EntityState(e) = p.unwrap().body {
                    if *t > 5.0 && *t < 15.0 {
                        assert!(e.is_frozen());
                        frozen_reports += 1;
                    }
                }
            }
        }
        assert!(frozen_reports >= 20); // every entity heartbeats at least once
    }

    #[test]
    fn bundling_packs_pdus_and_is_deterministic() {
        let cfg = Config {
            duration: 10.0,
            bundle: true,
            fire_every: Some(3.0),
            entities_per_site: 200,
            ..Default::default()
        };
        let mut a = Collect(Vec::new());
        let ta = run(&cfg, &mut a).unwrap();
        let mut b = Collect(Vec::new());
        let tb = run(&cfg, &mut b).unwrap();
        assert_eq!(ta, tb);
        assert!(ta.datagrams < ta.total_pdus());
        assert!(a.0.iter().all(|(_, _, d)| d.len() <= BUNDLE_LIMIT));
        assert!(ta.pdus_by_type["Fire"] >= 2 && ta.pdus_by_type["Detonation"] >= 2);
    }
}
