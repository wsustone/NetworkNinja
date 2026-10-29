//! Alert rules and the monitor that runs them.
//!
//! The MVP's three rules, as defined in the spec:
//!
//! | Rule | Fires when | Suppressed when |
//! | --- | --- | --- |
//! | Entity timeout | no Entity State for heartbeat × multiplier | Remove Entity; deactivated; frozen time does not count; one heartbeat of grace after resume |
//! | Entity ID conflict | one Entity ID reported by two senders whose reports interleave, or with different entity types | a sender that restarts on a new port (no interleaving after a grace period) |
//! | Position jump | a report lands further from the dead-reckoned prediction than the tolerance | first report from a sender; reappearing after a timeout; exercise frozen; first report after a freeze or resume |
//!
//! Thresholds live in [`RuleConfig`] for now; they move into rule packs in
//! milestone 3 proper.

mod engine;
mod monitor;

pub use engine::{Alert, AlertEvent, AlertState, Engine, Rule, RuleConfig, Severity};
pub use monitor::Monitor;
