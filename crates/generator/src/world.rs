//! The shared simulation every protocol family reads (ADR 0010): the clock,
//! the seeded RNG, the entities and how they move, the senders (one per
//! site, renumbered when a simulator restarts), the exercise's frozen flag
//! and the ground truth.

use crate::{Config, Sender, Truth, TICK};
use nn_decode::*;
use nn_state::geo;
use std::collections::BTreeMap;
use std::time::{Duration, UNIX_EPOCH};

/// Origin of the synthetic exercise area.
const ORIGIN_LAT: f64 = 36.60;
const ORIGIN_LON: f64 = -121.90;
/// East-west spacing between sites' areas, metres.
const SITE_SPACING: f64 = 8000.0;

pub(crate) struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    /// Uniform in [lo, hi).
    pub fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64 * (hi - lo)
    }
}

/// One simulated entity: identity, a circular track, and its sender's
/// Entity State bookkeeping.
pub(crate) struct SimEntity {
    pub id: EntityId,
    pub entity_type: EntityType,
    pub marking: Marking,
    pub force: u8,
    /// Circle centre, metres east/north of the origin.
    pub centre_e: f64,
    pub centre_n: f64,
    pub radius: f64,
    pub speed: f64,
    pub phase: f64,
    pub sending: bool,
    /// Never moves; DR algorithm Static, stationary heartbeat.
    pub parked: bool,
    /// Entity State (or Update) reports sent so far.
    pub reports: u32,
    pub last_sent: f64,
    pub last_pos: WorldCoord,
    pub last_vel: Vec3f,
}

impl SimEntity {
    /// Location, world-frame velocity and DIS orientation at motion time `m`.
    pub fn kinematics(&self, m: f64) -> (WorldCoord, Vec3f, EulerAngles) {
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
        let orientation = geo::heading_to_euler(lat, lon, ve.atan2(vn));
        (pos, vel, orientation)
    }

    /// Distance between `pos` and where the last report dead-reckons to.
    pub fn dr_error(&self, t: f64, pos: &WorldCoord) -> f64 {
        let dt = t - self.last_sent;
        let predicted = WorldCoord {
            x: self.last_pos.x + self.last_vel.x as f64 * dt,
            y: self.last_pos.y + self.last_vel.y as f64 * dt,
            z: self.last_pos.z + self.last_vel.z as f64 * dt,
        };
        geo::distance(&predicted, pos)
    }
}

/// One simulation step's time: seconds since the start, and the matching DIS
/// timestamp and clock time.
pub(crate) struct Tick {
    pub step: u64,
    pub t: f64,
    pub clock: ClockTime,
    stamp: DisTimestamp,
    version: u8,
    exercise: u8,
}

impl Tick {
    pub fn new(cfg: &Config, step: u64) -> Tick {
        let t = step as f64 * TICK;
        let wall = cfg.start_time + Duration::from_secs_f64(t);
        let since_epoch = wall.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let stamp = DisTimestamp::from_seconds_past_hour(since_epoch, !cfg.relative_timestamps);
        Tick {
            step,
            t,
            clock: ClockTime {
                hour: (since_epoch / 3600.0) as i32,
                time_past_hour: stamp.0 >> 1,
            },
            stamp,
            version: cfg.version,
            exercise: cfg.exercise,
        }
    }

    /// A header for a PDU of `pdu_type` sent this tick.
    pub fn header(&self, pdu_type: u8) -> PduHeader {
        PduHeader::new(self.version, self.exercise, pdu_type, self.stamp)
    }
}

/// Each site's simulator as a sender; a restart renumbers it (new port).
#[derive(Default)]
pub(crate) struct Senders(BTreeMap<u16, u16>);

impl Senders {
    pub fn get(&self, site: u16) -> Sender {
        Sender {
            site,
            generation: *self.0.get(&site).unwrap_or(&0),
            rogue: false,
            relay: false,
        }
    }
}

pub(crate) struct World<'a> {
    pub cfg: &'a Config,
    pub rng: Rng,
    pub entities: Vec<SimEntity>,
    pub senders: Senders,
    pub frozen: bool,
    /// Seconds the exercise has been running (frozen time excluded).
    pub motion_time: f64,
    pub truth: Truth,
}

impl<'a> World<'a> {
    pub fn new(cfg: &'a Config) -> World<'a> {
        let mut rng = Rng::new(cfg.seed);
        let mut entities = Vec::new();
        for s in 0..cfg.sites {
            let site = cfg.site_base + s;
            // Placement and type follow the site number, so generators with
            // different `site_base`s lay out side by side, not on top.
            let n = site - 1;
            let (base_e, base_n) = (n as f64 * SITE_SPACING, 0.0);
            for i in 0..cfg.entities_per_site {
                entities.push(SimEntity {
                    id: EntityId::new(site, cfg.application, i + 1),
                    entity_type: EntityType {
                        kind: 1,
                        domain: 1,
                        country: 225,
                        category: 1 + (n % 3) as u8,
                        subcategory: 1,
                        specific: 1,
                        extra: 0,
                    },
                    marking: Marking::ascii(&format!("S{site}V{:02}", i + 1)),
                    force: 1 + (n % 2) as u8,
                    centre_e: base_e + rng.range(0.0, 4000.0),
                    centre_n: base_n + rng.range(0.0, 4000.0),
                    radius: rng.range(500.0, 3000.0),
                    speed: rng.range(5.0, 25.0),
                    phase: rng.range(0.0, std::f64::consts::TAU),
                    sending: true,
                    parked: false,
                    reports: 0,
                    // Stagger first reports across one heartbeat.
                    last_sent: -rng.range(0.0, cfg.heartbeat),
                    last_pos: WorldCoord::default(),
                    last_vel: Vec3f::default(),
                });
            }
        }
        // Parked entities come after every moving one, so adding them leaves
        // the moving entities (and the RNG draws for them) as they were.
        for s in 0..cfg.sites {
            let site = cfg.site_base + s;
            let n = site - 1;
            for p in 0..cfg.parked_per_site {
                let i = cfg.entities_per_site + p;
                entities.push(SimEntity {
                    id: EntityId::new(site, cfg.application, i + 1),
                    entity_type: EntityType {
                        kind: 1,
                        domain: 1,
                        country: 225,
                        category: 1 + (n % 3) as u8,
                        subcategory: 1,
                        specific: 1,
                        extra: 0,
                    },
                    marking: Marking::ascii(&format!("S{site}P{:02}", p + 1)),
                    force: 1 + (n % 2) as u8,
                    centre_e: n as f64 * SITE_SPACING + rng.range(0.0, 4000.0),
                    centre_n: rng.range(0.0, 4000.0),
                    radius: 1.0,
                    speed: 0.0,
                    phase: 0.0,
                    sending: true,
                    parked: true,
                    reports: 0,
                    last_sent: -rng.range(0.0, cfg.stationary_heartbeat),
                    last_pos: WorldCoord::default(),
                    last_vel: Vec3f::default(),
                });
            }
        }
        let truth = Truth {
            version: cfg.version,
            exercise: cfg.exercise,
            duration: cfg.duration,
            entities: entities.iter().map(|e| e.id).collect(),
            ..Default::default()
        };
        World {
            cfg,
            rng,
            entities,
            senders: Senders::default(),
            frozen: false,
            motion_time: 0.0,
            truth,
        }
    }

    /// The current sender for `site`'s simulator.
    pub fn sender(&self, site: u16) -> Sender {
        self.senders.get(site)
    }

    /// The site that speaks for the exercise (simulation management).
    pub fn manager_site(&self) -> u16 {
        self.cfg.site_base
    }

    /// The simulator of `site` restarts on a new source port.
    pub fn restart(&mut self, site: u16) {
        *self.senders.0.entry(site).or_insert(0) += 1;
    }

    pub fn find(&self, id: &EntityId) -> Option<usize> {
        self.entities.iter().position(|e| e.id == *id)
    }

    /// Move simulated time on, unless the exercise is frozen.
    pub fn advance(&mut self, tick: &Tick) {
        if !self.frozen && tick.step > 0 {
            self.motion_time += TICK;
        }
    }
}
