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
pub mod presets;
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
    /// Lifecycle fault: Remove Entity, then silence with no final
    /// Deactivated report.
    NoFinalReport,
    /// Lifecycle fault: Remove Entity and the final report, then the entity
    /// keeps reporting active.
    Zombie,
    /// Lifecycle fault: the entity reports DR algorithm Static while moving.
    StaticMoving,
    /// Lifecycle fault: the entity's type changes mid-life.
    TypeChange,
    /// Lifecycle fault: Entity State Updates for an ID (entity number +
    /// 1000) no full Entity State describes.
    OrphanUpdate,
    /// Warfare fault: the next Fire's Detonation never comes.
    NoDetonation,
    /// Warfare fault: the next Detonation names another munition type than
    /// its Fire.
    DetonationMismatch,
    /// Warfare fault: the next Fire's PDU Status calls its munition an
    /// expendable (v7).
    WrongFireType,
    /// Warfare fault: a Detonation for an Event ID never fired.
    OrphanDetonation,
    /// Warfare fault: the next Fire fires a mine (munition category Fixed).
    MineFired,
    /// Warfare fault: the next Detonation claims an entity impact 2 km from
    /// its target.
    ImpactMiss,
    /// Collision fault: the next collision's parties are both stationary.
    StillCollision,
    /// DE fault: the next shot's DE Fire carries a Damage Description record.
    BadDeRecord,
    /// Attribute fault: an Attribute PDU whose records don't match its
    /// Master Attribute Record Type.
    BadAttribute,
    /// Attribute fault: a PDU says it is coupled (PDU Status CEI) and no
    /// Attribute PDU follows it.
    MissingExtension,
    /// Emission fault: the next emitter's EE PDUs stop with its beam on.
    EmitterDropout,
    /// Emission fault: the next emitter's Emitter Name changes.
    EmitterRename,
    /// Emission fault: the next emitter's Emitter Name and Beam Function are
    /// values SISO-REF-010 doesn't define.
    BadEmitterEnums,
    /// Emission fault: the next emitter's beam is numbered NO_BEAM.
    ReservedBeam,
    /// Emission fault: the next emitter selects High Density Track/Jam and
    /// still lists its target.
    DenseTargets,
    /// Emission fault: the next emitter gives a PRF with no pulse width.
    HalfPulsed,
    /// Emission fault: the next emitter's Track/Jam target has site 0.
    NoSiteTarget,
    /// Emission fault: the next emitter reports its beam Deactivated twice.
    RepeatDeactivated,
    /// Emission fault: the next emitter's entity is destroyed and keeps
    /// emitting.
    DestroyedEmitting,
    /// Designator fault: the next spot is on no entity but has an offset.
    SpotOffset,
    /// Designator fault: the next designation names an entity that doesn't
    /// exist.
    UnknownDesignated,
    /// Designator fault: the next target is deactivated and the designator
    /// stays on.
    TargetGone,
    /// Designator fault: the next designating entity is deactivated and its
    /// designator stops with no Power 0 report.
    DesignatorGone,
    /// IFF fault: the next PDU leaves out Layer 3 (Mode 5).
    IffMissingLayer,
    /// IFF fault: the next PDU's Information Layers also claim Layer 5.
    IffLayerBits,
    /// IFF fault: the next PDU sends Layer 4 before Layer 3.
    IffLayerOrder,
    /// IFF fault: the next PDU's Layer 2 has no Fundamental Parameter record.
    IffEmptyLayer2,
    /// IFF fault: the Mode 3/A code changes now with the Change Indicator clear.
    IffUnflaggedChange,
    /// IFF fault: the code changes now, and the next heartbeat clears the Change Indicator.
    IffHeartbeatUnflagged,
    /// IFF fault: the next PDU says System On with System Mode Off.
    IffModeMismatch,
    /// IFF fault: the transponder's entity is destroyed and the transponder stays on.
    IffDestroyedOn,
    /// Logistics fault: the next resupply request gets no offer (or cancel) from its supplier.
    LogisticsNoOffer,
    /// Logistics fault: the next resupply offer is never taken or cancelled.
    LogisticsNoReceipt,
    /// Logistics fault: the next resupply receipt takes more than was offered.
    ReceivedMore,
    /// Logistics fault: the next completed repair gets no Repair Response.
    NoRepairResponse,
    /// Logistics fault: the next repair is cancelled by its supplier, answered as finished.
    RepairCancelResult,
    /// Logistics fault: the next repair request lists supplies.
    SuppliesOnRepair,
    /// Logistics fault: supplies offered to an entity that didn't ask.
    UnsolicitedOffer,
    /// Logistics fault: supplies received with no offer.
    OrphanReceived,
    /// Logistics fault: a repair reported that nobody requested.
    UnrequestedRepair,
    /// Logistics fault: a Repair Response to no Repair Complete.
    OrphanRepairResponse,
    /// Logistics fault: a service request to an entity that doesn't exist.
    UnknownSupplier,
    /// Transfer fault: the old owner keeps reporting the next transferred entity.
    TransferLingering,
    /// Transfer fault: the next TO PDU asks for Acknowledged service.
    TransferReliability,
    /// Transfer fault: the next new owner leaves the Transferred Entity Indicator clear.
    TransferIndicator,
    /// Transfer fault: the next new owner changes the entity's marking.
    TransferAttributes,
    /// Transfer fault: the next new owner sends no ownership Event Report.
    TransferNoReport,
    /// Transfer fault: a second TO for the next entity, to another simulation, while the first is open.
    TransferConcurrent,
    /// Transfer fault: the next transfer is of an entity just deactivated.
    TransferInactive,
    /// Transfer fault: the next transfer gets no answer and nobody cancels it.
    TransferStalled,
    /// Collision fault: only one party reports the next collision.
    OneSidedCollision,
    /// Collision fault: one party reports the next collision twice.
    DuplicateCollision,
    /// Damage fault: the next repair leaves the appearance damaged.
    StaleAppearance,
    /// Damage fault: an Entity Damage Status for this (removed) entity.
    EdsAfterRemove,
    /// DE fault: the next shot's DE Fires stop after the first.
    DeDropout,
    /// DE fault: the next shot has no Fire PDU.
    DeNoFire,
    /// Heartbeat fault: the first site stops sending this PDU type (with
    /// `all_types`), as if the object it reports on had died.
    StopHeartbeat,
    /// Handshake fault: the site stops answering Simulation Management
    /// requests.
    NoResponse,
    /// Handshake fault: the site's next Acknowledge carries the wrong
    /// Acknowledge Flag.
    WrongAck,
    /// Handshake fault: the site sends an Action Response nobody asked for.
    OrphanResponse,
    /// Radio fault: the site's radio keys up and never sends a Signal.
    HotMic,
    /// Radio fault: the site sends a Signal for a radio with no Transmitter.
    OrphanSignal,
    /// Radio fault: the site's next Signal has the wrong Data Length.
    BadSignal,
    /// Radio fault: the site's radio stops sending Transmitter PDUs while it
    /// keeps transmitting.
    DropTransmitter,
    /// Enumeration fault (tier E): the type's first enumerated field set to
    /// its largest value, which SISO-REF-010 leaves undefined. Caught with
    /// `serve --siso`.
    BadEnum,
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
            EventKind::BadEnum => "bad-enum",
            EventKind::StopHeartbeat => "stop-heartbeat",
            EventKind::NoFinalReport => "no-final-report",
            EventKind::Zombie => "zombie",
            EventKind::StaticMoving => "static-moving",
            EventKind::TypeChange => "type-change",
            EventKind::OrphanUpdate => "orphan-update",
            EventKind::NoDetonation => "no-detonation",
            EventKind::DetonationMismatch => "detonation-mismatch",
            EventKind::WrongFireType => "wrong-fire-type",
            EventKind::OrphanDetonation => "orphan-detonation",
            EventKind::MineFired => "mine-fired",
            EventKind::ImpactMiss => "impact-miss",
            EventKind::StillCollision => "still-collision",
            EventKind::BadDeRecord => "bad-de-record",
            EventKind::BadAttribute => "bad-attribute",
            EventKind::MissingExtension => "missing-extension",
            EventKind::EmitterDropout => "emitter-dropout",
            EventKind::EmitterRename => "emitter-rename",
            EventKind::BadEmitterEnums => "bad-emitter-enums",
            EventKind::ReservedBeam => "reserved-beam",
            EventKind::DenseTargets => "dense-targets",
            EventKind::HalfPulsed => "half-pulsed",
            EventKind::NoSiteTarget => "no-site-target",
            EventKind::RepeatDeactivated => "repeat-deactivated",
            EventKind::DestroyedEmitting => "destroyed-emitting",
            EventKind::SpotOffset => "spot-offset",
            EventKind::UnknownDesignated => "unknown-designated",
            EventKind::TargetGone => "target-gone",
            EventKind::DesignatorGone => "designator-gone",
            EventKind::IffMissingLayer => "iff-missing-layer",
            EventKind::IffLayerBits => "iff-layer-bits",
            EventKind::IffLayerOrder => "iff-layer-order",
            EventKind::IffEmptyLayer2 => "iff-empty-layer2",
            EventKind::IffUnflaggedChange => "iff-unflagged-change",
            EventKind::IffHeartbeatUnflagged => "iff-heartbeat-unflagged",
            EventKind::IffModeMismatch => "iff-mode-mismatch",
            EventKind::IffDestroyedOn => "iff-destroyed-on",
            EventKind::LogisticsNoOffer => "logistics-no-offer",
            EventKind::LogisticsNoReceipt => "logistics-no-receipt",
            EventKind::ReceivedMore => "received-more",
            EventKind::NoRepairResponse => "no-repair-response",
            EventKind::RepairCancelResult => "repair-cancel-result",
            EventKind::SuppliesOnRepair => "supplies-on-repair",
            EventKind::UnsolicitedOffer => "unsolicited-offer",
            EventKind::OrphanReceived => "orphan-received",
            EventKind::UnrequestedRepair => "unrequested-repair",
            EventKind::OrphanRepairResponse => "orphan-repair-response",
            EventKind::UnknownSupplier => "unknown-supplier",
            EventKind::TransferLingering => "transfer-lingering",
            EventKind::TransferReliability => "transfer-reliability",
            EventKind::TransferIndicator => "transfer-indicator",
            EventKind::TransferAttributes => "transfer-attributes",
            EventKind::TransferNoReport => "transfer-no-report",
            EventKind::TransferConcurrent => "transfer-concurrent",
            EventKind::TransferInactive => "transfer-inactive",
            EventKind::TransferStalled => "transfer-stalled",
            EventKind::OneSidedCollision => "one-sided-collision",
            EventKind::DuplicateCollision => "duplicate-collision",
            EventKind::StaleAppearance => "stale-appearance",
            EventKind::EdsAfterRemove => "eds-after-remove",
            EventKind::DeDropout => "de-dropout",
            EventKind::DeNoFire => "de-no-fire",
            EventKind::NoResponse => "no-response",
            EventKind::WrongAck => "wrong-ack",
            EventKind::OrphanResponse => "orphan-response",
            EventKind::HotMic => "hot-mic",
            EventKind::OrphanSignal => "orphan-signal",
            EventKind::BadSignal => "bad-signal",
            EventKind::DropTransmitter => "drop-transmitter",
        }
    }
    /// The PDU defects (structural and enumeration), in preset order.
    pub const DEFECTS: [EventKind; 7] = [
        EventKind::ShortPdu,
        EventKind::CountOverrun,
        EventKind::PaddedPdu,
        EventKind::WrongFamily,
        EventKind::TruncatedPdu,
        EventKind::BadEnum,
        EventKind::StopHeartbeat,
    ];
    /// The PDU defect called `name`.
    pub fn defect(name: &str) -> Option<EventKind> {
        EventKind::DEFECTS.into_iter().find(|k| k.name() == name)
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
                | EventKind::BadEnum
                | EventKind::StopHeartbeat
                | EventKind::NoFinalReport
                | EventKind::Zombie
                | EventKind::StaticMoving
                | EventKind::TypeChange
                | EventKind::OrphanUpdate
                | EventKind::NoDetonation
                | EventKind::DetonationMismatch
                | EventKind::WrongFireType
                | EventKind::OrphanDetonation
                | EventKind::MineFired
                | EventKind::ImpactMiss
                | EventKind::StillCollision
                | EventKind::BadDeRecord
                | EventKind::BadAttribute
                | EventKind::MissingExtension
                | EventKind::EmitterDropout
                | EventKind::EmitterRename
                | EventKind::BadEmitterEnums
                | EventKind::ReservedBeam
                | EventKind::DenseTargets
                | EventKind::HalfPulsed
                | EventKind::NoSiteTarget
                | EventKind::RepeatDeactivated
                | EventKind::DestroyedEmitting
                | EventKind::SpotOffset
                | EventKind::UnknownDesignated
                | EventKind::TargetGone
                | EventKind::DesignatorGone
                | EventKind::IffMissingLayer
                | EventKind::IffLayerBits
                | EventKind::IffLayerOrder
                | EventKind::IffEmptyLayer2
                | EventKind::IffUnflaggedChange
                | EventKind::IffHeartbeatUnflagged
                | EventKind::IffModeMismatch
                | EventKind::IffDestroyedOn
                | EventKind::LogisticsNoOffer
                | EventKind::LogisticsNoReceipt
                | EventKind::ReceivedMore
                | EventKind::NoRepairResponse
                | EventKind::RepairCancelResult
                | EventKind::SuppliesOnRepair
                | EventKind::UnsolicitedOffer
                | EventKind::OrphanReceived
                | EventKind::UnrequestedRepair
                | EventKind::OrphanRepairResponse
                | EventKind::UnknownSupplier
                | EventKind::TransferLingering
                | EventKind::TransferReliability
                | EventKind::TransferIndicator
                | EventKind::TransferAttributes
                | EventKind::TransferNoReport
                | EventKind::TransferConcurrent
                | EventKind::TransferInactive
                | EventKind::TransferStalled
                | EventKind::OneSidedCollision
                | EventKind::DuplicateCollision
                | EventKind::StaleAppearance
                | EventKind::EdsAfterRemove
                | EventKind::DeDropout
                | EventKind::DeNoFire
                | EventKind::NoResponse
                | EventKind::WrongAck
                | EventKind::OrphanResponse
                | EventKind::HotMic
                | EventKind::OrphanSignal
                | EventKind::BadSignal
                | EventKind::DropTransmitter
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
    /// Seconds between Simulation Management requests from the first site
    /// to the second, each answered (needs at least 2 sites).
    pub siman_every: Option<f64>,
    /// Seconds between 2 s radio transmissions, each site's first vehicle
    /// in turn; every such radio heartbeats Transmitter and Receiver PDUs.
    pub radio_every: Option<f64>,
    /// Seconds between collisions, damage-and-repair and DE shots
    /// (`families::interactions`).
    pub collision_every: Option<f64>,
    pub damage_every: Option<f64>,
    pub de_every: Option<f64>,
    /// Seconds between 30 s radar emissions (`families::emission`).
    pub emission_every: Option<f64>,
    /// Seconds between 30 s laser designations (`families::designator`).
    pub designator_every: Option<f64>,
    /// Seconds between Mode 3/A code changes of a Mark XIIA transponder on
    /// the first site (`families::iff`); `None` sends no IFF from it.
    pub iff_every: Option<f64>,
    /// Seconds between logistics conversations, alternating resupply and
    /// repair (`families::logistics`).
    pub logistics_every: Option<f64>,
    /// Seconds between Transfer Ownership pushes of an entity to another
    /// site's simulator (`families::transfer`).
    pub transfer_every: Option<f64>,
    /// Pack each sender's PDUs from one tick into shared datagrams.
    pub bundle: bool,
    /// Simulators stop sending while the exercise is frozen (some do; the
    /// default keeps heartbeating with the frozen appearance bit set).
    pub silent_when_frozen: bool,
    /// Dead-reckoning algorithm in Entity State: 2 (FPW, world-frame
    /// velocity) or 6 (FPB, velocity in the entity's body frame).
    pub dr_algorithm: u8,
    /// Relative DIS timestamps (time since the simulator's own reference)
    /// instead of absolute ones (time past the UTC hour).
    pub relative_timestamps: bool,
    /// Every datagram is also relayed by a gateway on another address, the
    /// way a site bridge or a second NIC repeats traffic.
    pub gateway: bool,
    /// Parked entities per site, besides `entities_per_site`: they never
    /// move, report DR algorithm Static, and heartbeat at
    /// `stationary_heartbeat` (HBT_STATIONARY, IEEE 1278.1 4.2.7).
    pub parked_per_site: u16,
    pub stationary_heartbeat: f64,
    /// Send Entity State Update PDUs between full Entity States (every
    /// sixth report is full), as 5.3.5 allows.
    pub entity_state_update: bool,
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
            siman_every: None,
            radio_every: None,
            collision_every: None,
            damage_every: None,
            de_every: None,
            emission_every: None,
            designator_every: None,
            iff_every: None,
            logistics_every: None,
            transfer_every: None,
            bundle: false,
            silent_when_frozen: false,
            dr_algorithm: 2,
            relative_timestamps: false,
            gateway: false,
            parked_per_site: 0,
            stationary_heartbeat: 60.0,
            entity_state_update: false,
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
    /// A gateway repeating this simulator's traffic.
    pub relay: bool,
}

impl Sender {
    /// Host part of the sender's address in the sinks' 10.0.<site>.<host>
    /// scheme: 10 for the simulator, 200 for its gateway, 250 for a rogue.
    pub fn host(&self) -> u8 {
        if self.rogue {
            250
        } else if self.relay {
            200
        } else {
            10
        }
    }
}

/// A named bundle of legitimate variation (ADR 0010): how one vendor's
/// simulator behaves. None of it is an error; a run mixing profiles must
/// raise no alerts.
pub struct Profile {
    pub name: &'static str,
    pub description: &'static str,
    apply: fn(&mut Config),
}

impl Profile {
    pub fn apply(&self, cfg: &mut Config) {
        (self.apply)(cfg)
    }
}

pub const PROFILES: [Profile; 5] = [
    Profile {
        name: "standard",
        description: "DIS v7, one PDU per datagram, world-frame DR, absolute timestamps",
        apply: |_| {},
    },
    Profile {
        name: "legacy",
        description: "DIS v6, bundled datagrams, relative timestamps, silent while frozen",
        apply: |c| {
            c.version = 6;
            c.bundle = true;
            c.relative_timestamps = true;
            c.silent_when_frozen = true;
        },
    },
    Profile {
        name: "body-axis",
        description: "DIS v7, body-frame dead reckoning (FPB), bundled",
        apply: |c| {
            c.dr_algorithm = 6;
            c.bundle = true;
        },
    },
    Profile {
        name: "gateway",
        description: "DIS v7 behind a gateway that repeats every datagram from another address",
        apply: |c| c.gateway = true,
    },
    Profile {
        name: "economical",
        description: "DIS v7, Entity State Updates between full reports, parked entities heartbeating every 60 s",
        apply: |c| {
            c.entity_state_update = true;
            c.parked_per_site = 3;
        },
    },
];

/// The profile called `name`.
pub fn profile(name: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.name == name)
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
        // Removed at 10 s: its last report, Deactivated, goes out then.
        assert!(entity_state_times(&sink, id(2), false).iter().all(|&t| t <= 10.0));
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
