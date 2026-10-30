//! Byte-for-byte regression guard: three scenarios covering every fault and
//! control, v6/v7, bundling and both freeze behaviours, hashed datagram by
//! datagram (time, sender, bytes) together with the ground truth.
//!
//! Positions, velocities and angles come from `sin`/`cos`/`atan2`, whose
//! last bit differs between platform maths libraries, so those fields are
//! hashed rounded well above that noise (0.1 mm, 1 mm/s, 10 µrad). Every
//! other byte, and which PDUs are sent when and by whom, is hashed exactly.
//!
//! A refactor of the generator must reproduce these exactly. A change that
//! *means* to alter the traffic updates the hashes in the same commit and
//! says why.

use nn_decode::*;
use nn_generator::{run, Config, Event, EventKind, Sender, Sink, Target};
use std::io;

/// FNV-1a: stable across Rust versions, unlike `DefaultHasher`.
struct Fnv(u64);

impl Fnv {
    fn eat(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 ^= *b as u64;
            self.0 = self.0.wrapping_mul(0x0100_0000_01b3);
        }
    }
}

struct HashSink(Fnv, u64);

impl Sink for HashSink {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        self.0.eat(&t.to_bits().to_le_bytes());
        self.0
            .eat(&[s.site as u8, (s.site >> 8) as u8, s.generation as u8, s.rogue as u8]);
        self.0.eat(&(d.len() as u32).to_le_bytes());
        self.0.eat(&canonical(d));
        self.1 += 1;
        Ok(())
    }
}

fn r64(v: f64, step: f64) -> f64 {
    (v / step).round() * step
}

fn r32(v: f32, step: f64) -> f32 {
    r64(v as f64, step) as f32
}

fn rv(v: &mut Vec3f, step: f64) {
    (v.x, v.y, v.z) = (r32(v.x, step), r32(v.y, step), r32(v.z, step));
}

fn rw(c: &mut WorldCoord) {
    (c.x, c.y, c.z) = (r64(c.x, 1e-4), r64(c.y, 1e-4), r64(c.z, 1e-4));
}

/// The datagram with its trig-derived fields rounded (see the module docs).
fn canonical(d: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in decode_datagram(d) {
        let Ok(mut p) = p else { return d.to_vec() };
        match &mut p.body {
            PduBody::EntityState(e) => {
                rv(&mut e.linear_velocity, 1e-3);
                rw(&mut e.location);
                let o = &mut e.orientation;
                (o.psi, o.theta, o.phi) = (r32(o.psi, 1e-5), r32(o.theta, 1e-5), r32(o.phi, 1e-5));
                rv(&mut e.dead_reckoning.linear_acceleration, 1e-3);
                rv(&mut e.dead_reckoning.angular_velocity, 1e-5);
            }
            PduBody::Fire(f) => {
                rw(&mut f.location);
                rv(&mut f.velocity, 1e-3);
                f.range = r32(f.range, 1e-3);
            }
            PduBody::Detonation(x) => {
                rw(&mut x.location);
                rv(&mut x.velocity, 1e-3);
                rv(&mut x.location_in_entity, 1e-3);
            }
            _ => {}
        }
        out.extend(encode_pdu(&p));
    }
    out
}

fn digest(cfg: &Config) -> (u64, u64) {
    let mut sink = HashSink(Fnv(0xcbf2_9ce4_8422_2325), 0);
    let truth = run(cfg, &mut sink).unwrap();
    sink.0.eat(truth.to_json().as_bytes());
    (sink.1, sink.0 .0)
}

fn ev(kind: EventKind, target: Target, at: f64) -> Event {
    Event { kind, target, at }
}

fn ent(site: u16, n: u16) -> Target {
    Target::Entity(EntityId::new(site, 1, n))
}

#[test]
fn every_fault_and_control_v7() {
    let cfg = Config {
        duration: 120.0,
        fire_every: Some(5.0),
        events: vec![
            ev(EventKind::DropHeartbeat, ent(1, 1), 10.0),
            ev(EventKind::CloneId, ent(1, 2), 14.0),
            ev(EventKind::Teleport, ent(1, 3), 18.0),
            ev(EventKind::Remove, ent(2, 1), 10.0),
            ev(EventKind::RestartPort, Target::Site(2), 14.0),
            ev(EventKind::Freeze, Target::Exercise, 22.0),
            ev(EventKind::Resume, Target::Exercise, 28.0),
        ],
        ..Default::default()
    };
    assert_eq!(digest(&cfg), (GOLDEN_A_COUNT, GOLDEN_A));
}

#[test]
fn v6_bundled_silent_when_frozen() {
    let cfg = Config {
        version: 6,
        bundle: true,
        sites: 4,
        entities_per_site: 15,
        duration: 90.0,
        silent_when_frozen: true,
        seed: 7,
        events: vec![
            ev(EventKind::Freeze, Target::Exercise, 20.0),
            ev(EventKind::Resume, Target::Exercise, 40.0),
        ],
        ..Default::default()
    };
    assert_eq!(digest(&cfg), (GOLDEN_B_COUNT, GOLDEN_B));
}

#[test]
fn dense_faults_fast_heartbeat() {
    let cfg = Config {
        duration: 60.0,
        heartbeat: 2.0,
        dr_threshold: 0.5,
        fire_every: Some(3.0),
        events: vec![
            ev(EventKind::DropHeartbeat, ent(1, 1), 3.0),
            ev(EventKind::CloneId, ent(1, 3), 5.0),
            ev(EventKind::Teleport, ent(2, 2), 9.0),
            ev(EventKind::Remove, ent(1, 4), 12.0),
            ev(EventKind::RestartPort, Target::Site(2), 15.0),
        ],
        ..Default::default()
    };
    assert_eq!(digest(&cfg), (GOLDEN_C_COUNT, GOLDEN_C));
}

// Recorded from the single-loop generator (main 13b548f) before the ADR 0010
// restructure, which reproduces them; identical on macOS, Linux and Windows.
const GOLDEN_A_COUNT: u64 = 719;
const GOLDEN_A: u64 = 6257440943991091363;
const GOLDEN_B_COUNT: u64 = 994;
const GOLDEN_B: u64 = 2011724329581801927;
const GOLDEN_C_COUNT: u64 = 673;
const GOLDEN_C: u64 = 10657536439052893928;
