//! PDU data types.

use crate::time::DisTimestamp;

/// Size of the PDU header in bytes (v6 and v7).
pub const HEADER_LEN: usize = 12;

/// Fixed (no variable records) lengths of the deep-decoded PDUs, in bytes.
pub const ENTITY_STATE_LEN: usize = 144;
pub const FIRE_LEN: usize = 96;
pub const DETONATION_LEN: usize = 104;
pub const START_RESUME_LEN: usize = 44;
pub const STOP_FREEZE_LEN: usize = 40;
pub const REMOVE_ENTITY_LEN: usize = 28;
/// Size of one articulation / variable parameter record.
pub const VARIABLE_PARAM_LEN: usize = 16;

/// DIS protocol version numbers that matter to the MVP.
pub const PROTOCOL_VERSION_6: u8 = 6;
pub const PROTOCOL_VERSION_7: u8 = 7;

/// PDU type numbers (SISO-REF-010) for the deep-decoded PDUs.
pub mod pdu_type {
    pub const ENTITY_STATE: u8 = 1;
    pub const FIRE: u8 = 2;
    pub const DETONATION: u8 = 3;
    pub const REMOVE_ENTITY: u8 = 12;
    pub const START_RESUME: u8 = 13;
    pub const STOP_FREEZE: u8 = 14;
}

/// Protocol family numbers (SISO-REF-010).
pub mod family {
    pub const ENTITY_INFORMATION: u8 = 1;
    pub const WARFARE: u8 = 2;
    pub const SIMULATION_MANAGEMENT: u8 = 5;
}

/// The 12-byte header common to every PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PduHeader {
    pub protocol_version: u8,
    pub exercise_id: u8,
    pub pdu_type: u8,
    pub protocol_family: u8,
    pub timestamp: DisTimestamp,
    /// Total PDU length in bytes, including the header.
    pub length: u16,
    /// PDU status byte (v7). Zero in v6, where these bits are padding.
    pub pdu_status: u8,
}

impl PduHeader {
    pub fn new(protocol_version: u8, exercise_id: u8, pdu_type: u8, timestamp: DisTimestamp) -> Self {
        PduHeader {
            protocol_version,
            exercise_id,
            pdu_type,
            protocol_family: default_family(pdu_type),
            timestamp,
            length: 0,
            pdu_status: 0,
        }
    }
}

/// The standard protocol family for a PDU type, for the types we encode.
pub fn default_family(pdu_type: u8) -> u8 {
    match pdu_type {
        pdu_type::ENTITY_STATE => family::ENTITY_INFORMATION,
        pdu_type::FIRE | pdu_type::DETONATION => family::WARFARE,
        pdu_type::REMOVE_ENTITY | pdu_type::START_RESUME | pdu_type::STOP_FREEZE => {
            family::SIMULATION_MANAGEMENT
        }
        _ => 0,
    }
}

/// Human-readable name for a PDU type number, for logs and the console.
pub fn pdu_type_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        1 => "EntityState",
        2 => "Fire",
        3 => "Detonation",
        4 => "Collision",
        11 => "CreateEntity",
        12 => "RemoveEntity",
        13 => "StartResume",
        14 => "StopFreeze",
        15 => "Acknowledge",
        20 => "Data",
        21 => "Comment",
        23 => "ElectromagneticEmission",
        24 => "Designator",
        25 => "Transmitter",
        26 => "Signal",
        27 => "Receiver",
        28 => "IFF",
        _ => "Other",
    }
}

/// Site / application / entity triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct EntityId {
    pub site: u16,
    pub application: u16,
    pub entity: u16,
}

impl EntityId {
    pub const fn new(site: u16, application: u16, entity: u16) -> Self {
        EntityId { site, application, entity }
    }
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}:{}", self.site, self.application, self.entity)
    }
}

impl std::str::FromStr for EntityId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(format!("expected site:application:entity, got '{s}'"));
        }
        let p = |i: usize| parts[i].parse::<u16>().map_err(|e| format!("'{s}': {e}"));
        Ok(EntityId::new(p(0)?, p(1)?, p(2)?))
    }
}

/// Event identifier: site / application / event number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EventId {
    pub site: u16,
    pub application: u16,
    pub event_number: u16,
}

/// Entity type record (kind, domain, country, category, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct EntityType {
    pub kind: u8,
    pub domain: u8,
    pub country: u16,
    pub category: u8,
    pub subcategory: u8,
    pub specific: u8,
    pub extra: u8,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}.{}.{}.{}",
            self.kind, self.domain, self.country, self.category, self.subcategory, self.specific, self.extra
        )
    }
}

/// Single-precision 3-vector (velocities, accelerations, entity coordinates).
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Vec3f {
    pub x: f32,
    pub y: f32,
    pub z: f32,
}

/// Double-precision world location, geocentric (ECEF) metres.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct WorldCoord {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

/// Orientation as Euler angles (psi, theta, phi) in radians.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct EulerAngles {
    pub psi: f32,
    pub theta: f32,
    pub phi: f32,
}

/// Dead-reckoning parameters carried in Entity State.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DeadReckoning {
    /// Algorithm number (1 = static, 2 = FPW, 3 = RPW, 4 = RVW, 5 = FVW, ...).
    pub algorithm: u8,
    pub other_parameters: [u8; 15],
    pub linear_acceleration: Vec3f,
    pub angular_velocity: Vec3f,
}

/// Entity marking: character set plus 11 bytes of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Marking {
    pub character_set: u8,
    pub chars: [u8; 11],
}

impl Marking {
    /// ASCII marking from a string, truncated or zero-padded to 11 bytes.
    pub fn ascii(text: &str) -> Self {
        let mut chars = [0u8; 11];
        for (dst, src) in chars.iter_mut().zip(text.bytes()) {
            *dst = src;
        }
        Marking { character_set: 1, chars }
    }

    /// The marking text, trimmed of trailing NULs and spaces.
    pub fn text(&self) -> String {
        let end = self.chars.iter().position(|&c| c == 0).unwrap_or(self.chars.len());
        String::from_utf8_lossy(&self.chars[..end]).trim_end().to_string()
    }
}

/// One 16-byte articulation / variable parameter record, kept raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VariableParameter(pub [u8; VARIABLE_PARAM_LEN]);

/// Appearance bits that matter to the alert rules (generic appearance record).
pub mod appearance {
    /// Bit 21: frozen status.
    pub const FROZEN: u32 = 1 << 21;
    /// Bit 23: state (0 = active, 1 = deactivated).
    pub const DEACTIVATED: u32 = 1 << 23;
}

#[derive(Debug, Clone, PartialEq)]
pub struct EntityState {
    pub entity_id: EntityId,
    pub force_id: u8,
    pub entity_type: EntityType,
    pub alternative_entity_type: EntityType,
    pub linear_velocity: Vec3f,
    pub location: WorldCoord,
    pub orientation: EulerAngles,
    pub appearance: u32,
    pub dead_reckoning: DeadReckoning,
    pub marking: Marking,
    pub capabilities: u32,
    pub variable_parameters: Vec<VariableParameter>,
}

impl EntityState {
    pub fn is_deactivated(&self) -> bool {
        self.appearance & appearance::DEACTIVATED != 0
    }
    pub fn is_frozen(&self) -> bool {
        self.appearance & appearance::FROZEN != 0
    }
}

/// Munition / burst descriptor (16 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BurstDescriptor {
    pub munition_type: EntityType,
    pub warhead: u16,
    pub fuse: u16,
    pub quantity: u16,
    pub rate: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fire {
    pub firing_entity: EntityId,
    pub target_entity: EntityId,
    pub munition_id: EntityId,
    pub event_id: EventId,
    pub fire_mission_index: u32,
    pub location: WorldCoord,
    pub descriptor: BurstDescriptor,
    pub velocity: Vec3f,
    pub range: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detonation {
    pub firing_entity: EntityId,
    pub target_entity: EntityId,
    pub munition_id: EntityId,
    pub event_id: EventId,
    pub velocity: Vec3f,
    pub location: WorldCoord,
    pub descriptor: BurstDescriptor,
    pub location_in_entity: Vec3f,
    pub result: u8,
    pub variable_parameters: Vec<VariableParameter>,
}

/// Real-world or simulation time as hour + time past the hour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockTime {
    pub hour: i32,
    pub time_past_hour: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StartResume {
    pub originating: EntityId,
    pub receiving: EntityId,
    pub real_world_time: ClockTime,
    pub simulation_time: ClockTime,
    pub request_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StopFreeze {
    pub originating: EntityId,
    pub receiving: EntityId,
    pub real_world_time: ClockTime,
    pub reason: u8,
    pub frozen_behavior: u8,
    pub request_id: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RemoveEntity {
    pub originating: EntityId,
    pub receiving: EntityId,
    pub request_id: u32,
}

/// A decoded PDU body.
#[derive(Debug, Clone, PartialEq)]
pub enum PduBody {
    EntityState(EntityState),
    Fire(Fire),
    Detonation(Detonation),
    StartResume(StartResume),
    StopFreeze(StopFreeze),
    RemoveEntity(RemoveEntity),
    /// Any other PDU type: header decoded, body kept raw.
    Other(Vec<u8>),
}

/// A decoded PDU: header plus body.
#[derive(Debug, Clone, PartialEq)]
pub struct Pdu {
    pub header: PduHeader,
    pub body: PduBody,
}

impl Pdu {
    pub fn type_name(&self) -> &'static str {
        pdu_type_name(self.header.pdu_type)
    }
}
