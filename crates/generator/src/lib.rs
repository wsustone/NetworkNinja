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
//!
//! Layout (ADR 0010): [`world`] is the shared simulation (clock, entities and
//! their motion, senders, freeze state, truth); [`families`] holds one module
//! per DIS protocol family, each owning its PDU types and the faults and
//! controls that change them; [`wire`] sits between the simulation and the
//! sink. `tests/golden.rs` pins the output byte for byte.

pub use nn_state::geo;

mod families;
mod wire;
mod world;

use nn_decode::*;
use std::collections::BTreeMap;
use std::io;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Simulation time step, seconds.
pub const TICK: f64 = 0.05;
/// Largest datagram built when bundling PDUs.
pub const BUNDLE_LIMIT: usize = 1400;

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
    /// Structural fault (ADR 0010 tier S): a PDU missing its last 4 bytes,
    /// with a length field that agrees.
    ShortPdu,
    /// Structural fault: a count claims one record that isn't there.
    CountOverrun,
    /// Structural fault: 8 bytes the layout doesn't account for.
    PaddedPdu,
    /// Structural fault: a Protocol Family that doesn't match the type.
    WrongFamily,
    /// Structural fault: the datagram ends 4 bytes before the length field
    /// says the PDU does.
    TruncatedPdu,
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
            EventKind::ShortPdu => "short-pdu",
            EventKind::CountOverrun => "count-overrun",
            EventKind::PaddedPdu => "padded-pdu",
            EventKind::WrongFamily => "wrong-family",
            EventKind::TruncatedPdu => "truncated-pdu",
        }
    }
    /// The structural faults, in preset order.
    pub const STRUCTURAL: [EventKind; 5] = [
        EventKind::ShortPdu,
        EventKind::CountOverrun,
        EventKind::PaddedPdu,
        EventKind::WrongFamily,
        EventKind::TruncatedPdu,
    ];
    /// The structural fault called `name`.
    pub fn structural(name: &str) -> Option<EventKind> {
        EventKind::STRUCTURAL.into_iter().find(|k| k.name() == name)
    }
    /// True for faults that an alert rule should catch.
    pub fn is_fault(self) -> bool {
        matches!(
            self,
            EventKind::DropHeartbeat
                | EventKind::CloneId
                | EventKind::Teleport
                | EventKind::ShortPdu
                | EventKind::CountOverrun
                | EventKind::PaddedPdu
                | EventKind::WrongFamily
                | EventKind::TruncatedPdu
        )
    }
}

/// What an event applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Entity(EntityId),
    Site(u16),
    Exercise,
    /// A PDU of this type from this site's simulator.
    Pdu {
        site: u16,
        pdu_type: u8,
    },
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Entity(e) => write!(f, "{e}"),
            Target::Site(s) => write!(f, "site {s}"),
            Target::Exercise => write!(f, "exercise"),
            Target::Pdu { site, pdu_type } => write!(f, "site {site} {}", pdu_type_name(*pdu_type)),
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
    /// First site number; sites run `site_base..site_base + sites`. Give
    /// generators that run side by side different bases.
    pub site_base: u16,
    /// Simulation application number used by every site.
    pub application: u16,
    pub sites: u16,
    pub entities_per_site: u16,
    pub duration: f64,
    pub heartbeat: f64,
    pub dr_threshold: f64,
    pub seed: u64,
    /// Seconds between Fire events (each followed by a Detonation 2 s later).
    pub fire_every: Option<f64>,
    /// Seconds between rounds of every PDU type the other families don't
    /// send, each a minimal valid PDU from the first site (ADR 0010 tier S).
    pub all_types: Option<f64>,
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
            site_base: 1,
            application: 1,
            sites: 2,
            entities_per_site: 10,
            duration: 60.0,
            heartbeat: 5.0,
            dr_threshold: 1.0,
            seed: 1,
            fire_every: None,
            all_types: None,
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

// ---------------------------------------------------------------- run

/// Run the scenario, sending every datagram to `sink`.
///
/// Each tick: families' `begin`, then scheduled events (each to the family
/// that owns it), then motion, then families' `emit`, then the wire.
pub fn run(cfg: &Config, sink: &mut dyn Sink) -> io::Result<Truth> {
    let mut w = world::World::new(cfg);
    let mut families = families::all(&w);
    let wire = wire::Wire::new(cfg);

    let mut pending: Vec<Event> = cfg.events.clone();
    pending.sort_by(|a, b| a.at.total_cmp(&b.at));
    let mut next_event = 0;

    let steps = (cfg.duration / TICK).round() as u64;
    for step in 0..=steps {
        let tick = world::Tick::new(cfg, step);
        let mut out = families::Out::new();
        for f in families.iter_mut() {
            f.begin(&mut w, &tick, &mut out);
        }
        while next_event < pending.len() && pending[next_event].at <= tick.t + 1e-9 {
            let ev = pending[next_event];
            next_event += 1;
            // A simulator restart is the sender's, not any one family's.
            let applied = match (ev.kind, ev.target) {
                (EventKind::RestartPort, Target::Site(site)) => {
                    w.restart(site);
                    true
                }
                _ => families
                    .iter_mut()
                    .find_map(|f| f.on_event(&mut w, &tick, &ev, &mut out))
                    .unwrap_or(false),
            };
            if applied {
                w.truth.events.push(Event { at: tick.t, ..ev });
            }
        }
        w.advance(&tick);
        for f in families.iter_mut() {
            f.emit(&mut w, &tick, &mut out);
        }
        wire.send(&mut w.truth, tick.t, out, sink)?;
    }
    Ok(w.truth)
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
