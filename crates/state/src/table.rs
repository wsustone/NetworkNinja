//! Per-entity state, keyed by exercise and Entity ID, with per-source tracks.

use crate::dr::Kinematics;
use nn_decode::*;
use std::collections::BTreeMap;
use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityKey {
    pub exercise: u8,
    pub id: EntityId,
}

impl std::fmt::Display for EntityKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ex{} {}", self.exercise, self.id)
    }
}

/// Running mean and variance (Welford) of the gap between reports.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct IntervalStats {
    pub count: u64,
    pub mean: f64,
    m2: f64,
}

impl IntervalStats {
    pub fn add(&mut self, x: f64) {
        self.count += 1;
        let d = x - self.mean;
        self.mean += d / self.count as f64;
        self.m2 += d * (x - self.mean);
    }
    pub fn variance(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }
}

/// What one sender has told us about an entity.
#[derive(Debug, Clone, PartialEq)]
pub struct SourceTrack {
    pub first_seen: f64,
    pub last_seen: f64,
    pub reports: u64,
    pub entity_type: EntityType,
    pub last: Kinematics,
    pub intervals: IntervalStats,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntityRecord {
    pub key: EntityKey,
    pub entity_type: EntityType,
    pub marking: String,
    pub force_id: u8,
    pub appearance: u32,
    pub first_seen: f64,
    pub last_seen: f64,
    pub last_source: SocketAddr,
    pub sources: BTreeMap<SocketAddr, SourceTrack>,
    /// Remove Entity received, or the deactivated appearance bit set.
    pub removed: bool,
}

impl EntityRecord {
    pub fn kinematics(&self) -> &Kinematics {
        &self.sources[&self.last_source].last
    }
    pub fn deactivated(&self) -> bool {
        self.appearance & appearance::DEACTIVATED != 0
    }
}

/// How many past freeze periods to remember.
const FREEZE_HISTORY: usize = 16;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExerciseState {
    pub frozen: bool,
    /// Time of the last Stop/Freeze or Start/Resume.
    pub last_change: f64,
    pub freezes: u32,
    /// Recent freeze periods as (start, end); `end` is infinite while frozen.
    pub freeze_periods: Vec<(f64, f64)>,
}

impl ExerciseState {
    /// Seconds the exercise was frozen between `from` and `to`.
    pub fn frozen_between(&self, from: f64, to: f64) -> f64 {
        self.freeze_periods
            .iter()
            .map(|&(s, e)| (e.min(to) - s.max(from)).max(0.0))
            .sum()
    }

    /// Seconds of running (unfrozen) time between `from` and `to`.
    pub fn running_between(&self, from: f64, to: f64) -> f64 {
        (to - from) - self.frozen_between(from, to)
    }
}

/// Everything known about every entity, across exercises.
#[derive(Debug, Default, Clone)]
pub struct EntityTable {
    pub entities: BTreeMap<EntityKey, EntityRecord>,
    pub exercises: BTreeMap<u8, ExerciseState>,
}

impl EntityTable {
    pub fn get(&self, key: &EntityKey) -> Option<&EntityRecord> {
        self.entities.get(key)
    }

    pub fn exercise(&self, exercise: u8) -> ExerciseState {
        self.exercises.get(&exercise).cloned().unwrap_or_default()
    }

    /// Apply one decoded PDU received from `source` at `now` (seconds).
    pub fn apply(&mut self, now: f64, source: SocketAddr, pdu: &Pdu) {
        let exercise = pdu.header.exercise_id;
        match &pdu.body {
            PduBody::EntityState(es) => self.apply_entity_state(now, source, exercise, es),
            PduBody::RemoveEntity(r) => {
                if let Some(rec) = self.entities.get_mut(&EntityKey {
                    exercise,
                    id: r.receiving,
                }) {
                    rec.removed = true;
                }
            }
            PduBody::StopFreeze(_) => {
                let ex = self.exercises.entry(exercise).or_default();
                if !ex.frozen {
                    ex.frozen = true;
                    ex.last_change = now;
                    ex.freezes += 1;
                    ex.freeze_periods.push((now, f64::INFINITY));
                    if ex.freeze_periods.len() > FREEZE_HISTORY {
                        ex.freeze_periods.remove(0);
                    }
                }
            }
            PduBody::StartResume(_) => {
                let ex = self.exercises.entry(exercise).or_default();
                if ex.frozen || ex.last_change == 0.0 {
                    ex.frozen = false;
                    ex.last_change = now;
                    if let Some(last) = ex.freeze_periods.last_mut() {
                        if last.1.is_infinite() {
                            last.1 = now;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_entity_state(&mut self, now: f64, source: SocketAddr, exercise: u8, es: &EntityState) {
        let key = EntityKey {
            exercise,
            id: es.entity_id,
        };
        let kin = Kinematics {
            location: es.location,
            velocity: es.linear_velocity,
            acceleration: es.dead_reckoning.linear_acceleration,
            orientation: es.orientation,
            algorithm: es.dead_reckoning.algorithm,
        };
        let rec = self.entities.entry(key).or_insert_with(|| EntityRecord {
            key,
            entity_type: es.entity_type,
            marking: String::new(),
            force_id: es.force_id,
            appearance: es.appearance,
            first_seen: now,
            last_seen: now,
            last_source: source,
            sources: BTreeMap::new(),
            removed: false,
        });
        let track = rec.sources.entry(source).or_insert_with(|| SourceTrack {
            first_seen: now,
            last_seen: now,
            reports: 0,
            entity_type: es.entity_type,
            last: kin,
            intervals: IntervalStats::default(),
        });
        if track.reports > 0 {
            track.intervals.add(now - track.last_seen);
        }
        track.reports += 1;
        track.last_seen = now;
        track.last = kin;
        track.entity_type = es.entity_type;

        rec.entity_type = es.entity_type;
        rec.marking = es.marking.text();
        rec.force_id = es.force_id;
        rec.appearance = es.appearance;
        rec.last_seen = now;
        rec.last_source = source;
        rec.removed = es.is_deactivated();
    }

    /// Drop entities not heard from for longer than `max_age` seconds.
    pub fn prune(&mut self, now: f64, max_age: f64) -> usize {
        let before = self.entities.len();
        self.entities.retain(|_, r| now - r.last_seen <= max_age);
        before - self.entities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_time_excludes_freezes() {
        let ex = ExerciseState {
            freeze_periods: vec![(10.0, 20.0), (30.0, f64::INFINITY)],
            ..Default::default()
        };
        assert_eq!(ex.frozen_between(0.0, 5.0), 0.0);
        assert_eq!(ex.frozen_between(5.0, 25.0), 10.0);
        assert_eq!(ex.frozen_between(15.0, 35.0), 10.0);
        assert_eq!(ex.running_between(0.0, 40.0), 20.0);
    }
}
