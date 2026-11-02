//! Alert rules, the rule packs that configure them, and the monitor that
//! runs everything.
//!
//! The MVP's three behavioural rules, as defined in the spec:
//!
//! | Rule | Fires when | Suppressed when |
//! | --- | --- | --- |
//! | Entity timeout | no Entity State for heartbeat × multiplier | Remove Entity; deactivated; frozen time does not count; one heartbeat of grace after resume |
//! | Entity ID conflict | one Entity ID reported by two senders whose reports interleave, or with different entity types | a sender that restarts on a new port (no interleaving after a grace period) |
//! | Position jump | a report lands further from the dead-reckoned prediction than the tolerance | first report from a sender; reappearing after a timeout; exercise frozen; first report after a freeze or resume |
//!
//! Thresholds, per-rule enable switches and the enumeration checks that run
//! on every PDU all come from layered rule packs ([`pack`], ADR 0003): the
//! base DIS pack ships in the binary and site packs layer on top.

mod attribute;
pub mod capture;
mod designator;
mod emission;
mod engine;
pub mod explain;
mod heartbeats;
mod interactions;
mod lifecycle;
pub mod minitoml;
mod monitor;
pub mod monitors;
pub mod pack;
pub mod radio;
pub mod siman;
pub mod siso;
mod warfare;

pub use capture::{Capture, Captured};
pub use engine::{Ack, Alert, AlertEvent, AlertState, Engine, Mute, MuteScope, Rule, RuleConfig, Severity};
pub use monitor::Monitor;
pub use pack::{builtin as builtin_packs, CaptureRule, EnumCheck, FieldSpec, Merged, PackError, RulePack};
pub use siso::Siso;
