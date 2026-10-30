//! Per-entity state and rolling traffic metrics.
//!
//! - [`table`]: entities keyed by exercise and Entity ID, tracked per sender
//!   (so two simulators claiming one ID stay distinguishable), plus each
//!   exercise's running/frozen state.
//! - [`metrics`]: one-second buckets of tagged counters and gauges (ADR 0008).
//! - [`query`]: the one query object over those series, memory or disk.
//! - [`dr`]: dead-reckoning extrapolation.
//! - [`geo`]: WGS84 conversions.

pub mod dr;
pub mod geo;
pub mod metrics;
pub mod query;
pub mod table;

pub use dr::{extrapolate, Kinematics};
pub use metrics::{Agg, Cell, Dim, Metric, Metrics, Rollup, Tags, WindowStats};
pub use query::{Query, Series};
pub use table::{EntityKey, EntityRecord, EntityTable, ExerciseState, SourceTrack};

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch, the time base for state and rules.
pub fn secs(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}
