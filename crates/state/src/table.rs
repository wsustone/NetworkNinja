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

/// DIS wildcard for a site, application or entity number: "all of them".
pub const ALL: u16 = 0xFFFF;

/// Does `id` fall under `pattern`, where any [`ALL`] field matches anything?
pub fn id_matches(pattern: &EntityId, id: &EntityId) -> bool {
    let f = |p: u16, v: u16| p == ALL || p == v;
    f(pattern.site, id.site) && f(pattern.application, id.application) && f(pattern.entity, id.entity)
}

/// A Stop/Freeze or Start/Resume target: `None` for the whole exercise
/// (site wildcard, or the unassigned site 0), else (site, application).
fn scope_of(receiving: &EntityId) -> Option<(u16, u16)> {
    match receiving.site {
        ALL | 0 => None,
        site => Some((site, receiving.application)),
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

    fn freeze(&mut self, now: f64) {
        if !self.frozen {
            self.frozen = true;
            self.last_change = now;
            self.freezes += 1;
            self.freeze_periods.push((now, f64::INFINITY));
            if self.freeze_periods.len() > FREEZE_HISTORY {
                self.freeze_periods.remove(0);
            }
        }
    }

    fn resume(&mut self, now: f64) {
        if self.frozen || self.last_change == 0.0 {
            self.frozen = false;
            self.last_change = now;
            if let Some(last) = self.freeze_periods.last_mut() {
                if last.1.is_infinite() {
                    last.1 = now;
                }
            }
        }
    }

    /// Several scopes' states as one: frozen if any is, periods unioned.
    fn merge<'a>(states: impl Iterator<Item = &'a ExerciseState>) -> ExerciseState {
        let mut out = ExerciseState::default();
        let mut periods = Vec::new();
        for s in states {
            out.frozen |= s.frozen;
            out.last_change = out.last_change.max(s.last_change);
            out.freezes += s.freezes;
            periods.extend_from_slice(&s.freeze_periods);
        }
        periods.sort_by(|a, b| a.0.total_cmp(&b.0));
        for (s, e) in periods {
            match out.freeze_periods.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => out.freeze_periods.push((s, e)),
            }
        }
        out
    }
}

/// Everything known about every entity, across exercises.
#[derive(Debug, Default, Clone)]
pub struct EntityTable {
    pub entities: BTreeMap<EntityKey, EntityRecord>,
    /// Freeze state of each whole exercise.
    pub exercises: BTreeMap<u8, ExerciseState>,
    /// Freezes addressed to one site or application, keyed by (exercise,
    /// site, application); application [`ALL`] = the whole site.
    pub scoped: BTreeMap<(u8, u16, u16), ExerciseState>,
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
                for key in self.matching(exercise, &r.receiving) {
                    if let Some(rec) = self.entities.get_mut(&key) {
                        rec.removed = true;
                    }
                }
            }
            // A tracked munition's life ends at its detonation; it goes quiet
            // without a Remove Entity.
            PduBody::Detonation(d) => {
                if let Some(rec) = self.entities.get_mut(&EntityKey {
                    exercise,
                    id: d.munition_id,
                }) {
                    rec.removed = true;
                }
            }
            // The receiving ID says who is frozen: every application in
            // the exercise (site wildcard), one site, or one application.
            PduBody::StopFreeze(s) => match scope_of(&s.receiving) {
                None => self.exercises.entry(exercise).or_default().freeze(now),
                Some((site, app)) => self.scoped.entry((exercise, site, app)).or_default().freeze(now),
            },
            // A resume also resumes every narrower freeze it covers.
            PduBody::StartResume(s) => {
                let target = scope_of(&s.receiving);
                if target.is_none() {
                    self.exercises.entry(exercise).or_default().resume(now);
                } else if let Some((site, app)) = target {
                    self.scoped.entry((exercise, site, app)).or_default().resume(now);
                }
                for ((ex, site, app), st) in self.scoped.iter_mut() {
                    let covered = match target {
                        None => true,
                        Some((s, a)) => s == *site && (a == ALL || a == *app),
                    };
                    if *ex == exercise && covered {
                        st.resume(now);
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

    /// The freeze state that applies to one entity: its exercise's, merged
    /// with any freeze addressed to its site or application.
    pub fn state_for(&self, key: &EntityKey) -> std::borrow::Cow<'_, ExerciseState> {
        use std::borrow::Cow;
        let site = key.id.site;
        let states: Vec<&ExerciseState> = [
            self.exercises.get(&key.exercise),
            self.scoped.get(&(key.exercise, site, ALL)),
            self.scoped.get(&(key.exercise, site, key.id.application)),
        ]
        .into_iter()
        .flatten()
        .collect();
        match states.as_slice() {
            [] => Cow::Owned(ExerciseState::default()),
            [one] => Cow::Borrowed(*one),
            many => Cow::Owned(ExerciseState::merge(many.iter().copied())),
        }
    }

    /// Keys in `exercise` that `pattern` addresses, wildcards expanded.
    pub fn matching(&self, exercise: u8, pattern: &EntityId) -> Vec<EntityKey> {
        let lo = EntityKey {
            exercise,
            id: EntityId::new(0, 0, 0),
        };
        let hi = EntityKey {
            exercise,
            id: EntityId::new(ALL, ALL, ALL),
        };
        self.entities
            .range(lo..=hi)
            .map(|(k, _)| *k)
            .filter(|k| id_matches(pattern, &k.id))
            .collect()
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

    fn sim_mgmt(freeze: bool, receiving: EntityId) -> Pdu {
        let (originating, real_world_time) = (EntityId::new(9, 9, ALL), ClockTime::default());
        Pdu {
            header: PduHeader::new(7, 1, if freeze { 14 } else { 13 }, DisTimestamp(0)),
            body: if freeze {
                PduBody::StopFreeze(StopFreeze {
                    originating,
                    receiving,
                    real_world_time,
                    reason: 0,
                    frozen_behavior: 0,
                    request_id: 1,
                })
            } else {
                PduBody::StartResume(StartResume {
                    originating,
                    receiving,
                    real_world_time,
                    simulation_time: ClockTime::default(),
                    request_id: 1,
                })
            },
        }
    }

    #[test]
    fn freezes_apply_to_the_addressed_scope() {
        let src: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let key = |site, app| EntityKey {
            exercise: 1,
            id: EntityId::new(site, app, 1),
        };
        let mut t = EntityTable::default();
        // Freeze site 2 only: site 2's applications are frozen, site 1 runs.
        t.apply(10.0, src, &sim_mgmt(true, EntityId::new(2, ALL, ALL)));
        assert!(t.state_for(&key(2, 1)).frozen && t.state_for(&key(2, 7)).frozen);
        assert!(!t.state_for(&key(1, 1)).frozen);
        // Freeze one application of site 1 as well.
        t.apply(12.0, src, &sim_mgmt(true, EntityId::new(1, 3, ALL)));
        assert!(t.state_for(&key(1, 3)).frozen && !t.state_for(&key(1, 1)).frozen);
        // An exercise-wide freeze merges with the site's: periods union.
        t.apply(15.0, src, &sim_mgmt(true, EntityId::new(ALL, ALL, ALL)));
        let st = t.state_for(&key(2, 1));
        assert_eq!(st.frozen_between(0.0, 20.0), 10.0);
        // An exercise-wide resume resumes every narrower freeze it covers.
        t.apply(20.0, src, &sim_mgmt(false, EntityId::new(ALL, ALL, ALL)));
        for k in [key(1, 1), key(1, 3), key(2, 1)] {
            assert!(!t.state_for(&k).frozen, "{k}");
        }
        assert_eq!(t.state_for(&key(1, 3)).frozen_between(0.0, 30.0), 8.0);
    }

    #[test]
    fn wildcards_match_whole_sites_and_applications() {
        let id = EntityId::new(3, 4, 5);
        assert!(id_matches(&EntityId::new(3, 4, ALL), &id));
        assert!(id_matches(&EntityId::new(3, ALL, ALL), &id));
        assert!(id_matches(&EntityId::new(ALL, ALL, ALL), &id));
        assert!(id_matches(&id, &id));
        assert!(!id_matches(&EntityId::new(3, 9, ALL), &id));
        assert!(!id_matches(&EntityId::new(3, 4, 6), &id));
    }

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
