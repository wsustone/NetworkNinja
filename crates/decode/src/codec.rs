//! Binary encoding and decoding.

use crate::pdu::*;
use crate::time::DisTimestamp;

/// Why a PDU (or the rest of a datagram) could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// Fewer bytes than the header or body requires.
    Truncated { needed: usize, available: usize },
    /// The header's length field is smaller than a header.
    BadLength { length: u16 },
    /// The header's length field disagrees with the body it describes.
    LengthMismatch { pdu_type: u8, length: u16, expected: usize },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated { needed, available } => {
                write!(f, "truncated: needed {needed} bytes, had {available}")
            }
            DecodeError::BadLength { length } => write!(f, "bad length field {length}"),
            DecodeError::LengthMismatch {
                pdu_type,
                length,
                expected,
            } => write!(
                f,
                "{} length field {length} does not match expected {expected}",
                pdu_type_name(*pdu_type)
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

// ---------------------------------------------------------------- reading

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self.pos + n;
        if end > self.buf.len() {
            return Err(DecodeError::Truncated {
                needed: end,
                available: self.buf.len(),
            });
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.u32()? as i32)
    }
    fn f32(&mut self) -> Result<f32, DecodeError> {
        Ok(f32::from_bits(self.u32()?))
    }
    fn f64(&mut self) -> Result<f64, DecodeError> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(f64::from_be_bytes(a))
    }
    fn entity_id(&mut self) -> Result<EntityId, DecodeError> {
        Ok(EntityId {
            site: self.u16()?,
            application: self.u16()?,
            entity: self.u16()?,
        })
    }
    fn event_id(&mut self) -> Result<EventId, DecodeError> {
        Ok(EventId {
            site: self.u16()?,
            application: self.u16()?,
            event_number: self.u16()?,
        })
    }
    fn entity_type(&mut self) -> Result<EntityType, DecodeError> {
        Ok(EntityType {
            kind: self.u8()?,
            domain: self.u8()?,
            country: self.u16()?,
            category: self.u8()?,
            subcategory: self.u8()?,
            specific: self.u8()?,
            extra: self.u8()?,
        })
    }
    fn vec3f(&mut self) -> Result<Vec3f, DecodeError> {
        Ok(Vec3f {
            x: self.f32()?,
            y: self.f32()?,
            z: self.f32()?,
        })
    }
    fn world(&mut self) -> Result<WorldCoord, DecodeError> {
        Ok(WorldCoord {
            x: self.f64()?,
            y: self.f64()?,
            z: self.f64()?,
        })
    }
    fn euler(&mut self) -> Result<EulerAngles, DecodeError> {
        Ok(EulerAngles {
            psi: self.f32()?,
            theta: self.f32()?,
            phi: self.f32()?,
        })
    }
    fn clock(&mut self) -> Result<ClockTime, DecodeError> {
        Ok(ClockTime {
            hour: self.i32()?,
            time_past_hour: self.u32()?,
        })
    }
    fn burst(&mut self) -> Result<BurstDescriptor, DecodeError> {
        Ok(BurstDescriptor {
            munition_type: self.entity_type()?,
            warhead: self.u16()?,
            fuse: self.u16()?,
            quantity: self.u16()?,
            rate: self.u16()?,
        })
    }
    fn variable_params(&mut self, n: usize) -> Result<Vec<VariableParameter>, DecodeError> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            let mut rec = [0u8; VARIABLE_PARAM_LEN];
            rec.copy_from_slice(self.take(VARIABLE_PARAM_LEN)?);
            v.push(VariableParameter(rec));
        }
        Ok(v)
    }
}

fn decode_header(r: &mut Reader) -> Result<PduHeader, DecodeError> {
    let protocol_version = r.u8()?;
    let exercise_id = r.u8()?;
    let pdu_type = r.u8()?;
    let protocol_family = r.u8()?;
    let timestamp = DisTimestamp(r.u32()?);
    let length = r.u16()?;
    let status = r.u8()?;
    let _padding = r.u8()?;
    Ok(PduHeader {
        protocol_version,
        exercise_id,
        pdu_type,
        protocol_family,
        timestamp,
        length,
        pdu_status: if protocol_version >= PROTOCOL_VERSION_7 {
            status
        } else {
            0
        },
    })
}

fn check_len(h: &PduHeader, expected: usize) -> Result<(), DecodeError> {
    if h.length as usize != expected {
        return Err(DecodeError::LengthMismatch {
            pdu_type: h.pdu_type,
            length: h.length,
            expected,
        });
    }
    Ok(())
}

/// Decode a single PDU from the start of `buf`.
///
/// The header's length field decides how many bytes belong to the PDU; any
/// bytes after that are ignored. PDU types outside the deep-decoded set, and
/// protocol versions other than 6 and 7, come back as [`PduBody::Other`].
pub fn decode_pdu(buf: &[u8]) -> Result<Pdu, DecodeError> {
    let mut r = Reader::new(buf);
    let header = decode_header(&mut r)?;
    let len = header.length as usize;
    if len < HEADER_LEN {
        return Err(DecodeError::BadLength { length: header.length });
    }
    if len > buf.len() {
        return Err(DecodeError::Truncated {
            needed: len,
            available: buf.len(),
        });
    }
    let mut r = Reader::new(&buf[..len]);
    r.take(HEADER_LEN)?;

    let deep = matches!(header.protocol_version, PROTOCOL_VERSION_6 | PROTOCOL_VERSION_7);
    let body = match (deep, header.pdu_type) {
        (true, pdu_type::ENTITY_STATE) => {
            let entity_id = r.entity_id()?;
            let force_id = r.u8()?;
            let n_params = r.u8()? as usize;
            check_len(&header, ENTITY_STATE_LEN + n_params * VARIABLE_PARAM_LEN)?;
            let entity_type = r.entity_type()?;
            let alternative_entity_type = r.entity_type()?;
            let linear_velocity = r.vec3f()?;
            let location = r.world()?;
            let orientation = r.euler()?;
            let appearance = r.u32()?;
            let algorithm = r.u8()?;
            let mut other_parameters = [0u8; 15];
            other_parameters.copy_from_slice(r.take(15)?);
            let linear_acceleration = r.vec3f()?;
            let angular_velocity = r.vec3f()?;
            let character_set = r.u8()?;
            let mut chars = [0u8; 11];
            chars.copy_from_slice(r.take(11)?);
            let capabilities = r.u32()?;
            let variable_parameters = r.variable_params(n_params)?;
            PduBody::EntityState(EntityState {
                entity_id,
                force_id,
                entity_type,
                alternative_entity_type,
                linear_velocity,
                location,
                orientation,
                appearance,
                dead_reckoning: DeadReckoning {
                    algorithm,
                    other_parameters,
                    linear_acceleration,
                    angular_velocity,
                },
                marking: Marking { character_set, chars },
                capabilities,
                variable_parameters,
            })
        }
        (true, pdu_type::FIRE) => {
            check_len(&header, FIRE_LEN)?;
            PduBody::Fire(Fire {
                firing_entity: r.entity_id()?,
                target_entity: r.entity_id()?,
                munition_id: r.entity_id()?,
                event_id: r.event_id()?,
                fire_mission_index: r.u32()?,
                location: r.world()?,
                descriptor: r.burst()?,
                velocity: r.vec3f()?,
                range: r.f32()?,
            })
        }
        (true, pdu_type::DETONATION) => {
            let firing_entity = r.entity_id()?;
            let target_entity = r.entity_id()?;
            let munition_id = r.entity_id()?;
            let event_id = r.event_id()?;
            let velocity = r.vec3f()?;
            let location = r.world()?;
            let descriptor = r.burst()?;
            let location_in_entity = r.vec3f()?;
            let result = r.u8()?;
            let n_params = r.u8()? as usize;
            let _padding = r.u16()?;
            check_len(&header, DETONATION_LEN + n_params * VARIABLE_PARAM_LEN)?;
            PduBody::Detonation(Detonation {
                firing_entity,
                target_entity,
                munition_id,
                event_id,
                velocity,
                location,
                descriptor,
                location_in_entity,
                result,
                variable_parameters: r.variable_params(n_params)?,
            })
        }
        (true, pdu_type::START_RESUME) => {
            check_len(&header, START_RESUME_LEN)?;
            PduBody::StartResume(StartResume {
                originating: r.entity_id()?,
                receiving: r.entity_id()?,
                real_world_time: r.clock()?,
                simulation_time: r.clock()?,
                request_id: r.u32()?,
            })
        }
        (true, pdu_type::STOP_FREEZE) => {
            check_len(&header, STOP_FREEZE_LEN)?;
            let originating = r.entity_id()?;
            let receiving = r.entity_id()?;
            let real_world_time = r.clock()?;
            let reason = r.u8()?;
            let frozen_behavior = r.u8()?;
            let _padding = r.u16()?;
            PduBody::StopFreeze(StopFreeze {
                originating,
                receiving,
                real_world_time,
                reason,
                frozen_behavior,
                request_id: r.u32()?,
            })
        }
        (true, pdu_type::REMOVE_ENTITY) => {
            check_len(&header, REMOVE_ENTITY_LEN)?;
            PduBody::RemoveEntity(RemoveEntity {
                originating: r.entity_id()?,
                receiving: r.entity_id()?,
                request_id: r.u32()?,
            })
        }
        _ => PduBody::Other(r.take(len - HEADER_LEN)?.to_vec()),
    };
    Ok(Pdu { header, body })
}

/// Decode every PDU in a UDP datagram.
///
/// A datagram may carry several PDUs back to back; each header's length field
/// says where the next one starts. Decoding stops at the first error that
/// makes the rest of the datagram unreadable (a bad or overlong length field).
/// Trailing zero padding after the last PDU is ignored.
pub fn decode_datagram(buf: &[u8]) -> Vec<Result<Pdu, DecodeError>> {
    decode_datagram_spans(buf).into_iter().map(|(_, r)| r).collect()
}

/// [`decode_datagram`], with each PDU's byte range in `buf` — so a caller
/// can keep a PDU's exact wire bytes without decoding it twice. A framing
/// error's range is the unreadable rest of the datagram.
pub fn decode_datagram_spans(buf: &[u8]) -> Vec<(std::ops::Range<usize>, Result<Pdu, DecodeError>)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let rest = &buf[offset..];
        if rest.iter().all(|&b| b == 0) {
            break;
        }
        let tail = offset..buf.len();
        if rest.len() < HEADER_LEN {
            out.push((
                tail,
                Err(DecodeError::Truncated {
                    needed: HEADER_LEN,
                    available: rest.len(),
                }),
            ));
            break;
        }
        let length = u16::from_be_bytes([rest[8], rest[9]]);
        if (length as usize) < HEADER_LEN {
            out.push((tail, Err(DecodeError::BadLength { length })));
            break;
        }
        if length as usize > rest.len() {
            out.push((
                tail,
                Err(DecodeError::Truncated {
                    needed: length as usize,
                    available: rest.len(),
                }),
            ));
            break;
        }
        // The framing is sound, so a body error only affects this PDU.
        let end = offset + length as usize;
        out.push((offset..end, decode_pdu(&buf[offset..end])));
        offset = end;
    }
    out
}

// ---------------------------------------------------------------- writing

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn f32(&mut self, v: f32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn f64(&mut self, v: f64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    fn entity_id(&mut self, e: &EntityId) {
        self.u16(e.site);
        self.u16(e.application);
        self.u16(e.entity);
    }
    fn event_id(&mut self, e: &EventId) {
        self.u16(e.site);
        self.u16(e.application);
        self.u16(e.event_number);
    }
    fn entity_type(&mut self, t: &EntityType) {
        self.u8(t.kind);
        self.u8(t.domain);
        self.u16(t.country);
        self.u8(t.category);
        self.u8(t.subcategory);
        self.u8(t.specific);
        self.u8(t.extra);
    }
    fn vec3f(&mut self, v: &Vec3f) {
        self.f32(v.x);
        self.f32(v.y);
        self.f32(v.z);
    }
    fn world(&mut self, v: &WorldCoord) {
        self.f64(v.x);
        self.f64(v.y);
        self.f64(v.z);
    }
    fn euler(&mut self, e: &EulerAngles) {
        self.f32(e.psi);
        self.f32(e.theta);
        self.f32(e.phi);
    }
    fn clock(&mut self, c: &ClockTime) {
        self.i32(c.hour);
        self.u32(c.time_past_hour);
    }
    fn burst(&mut self, b: &BurstDescriptor) {
        self.entity_type(&b.munition_type);
        self.u16(b.warhead);
        self.u16(b.fuse);
        self.u16(b.quantity);
        self.u16(b.rate);
    }
    fn variable_params(&mut self, v: &[VariableParameter]) {
        for p in v {
            self.bytes(&p.0);
        }
    }
}

/// Encode a PDU. The header's length field (and protocol family, if zero)
/// is filled in from the body; everything else is written as given.
pub fn encode_pdu(pdu: &Pdu) -> Vec<u8> {
    let h = &pdu.header;
    let mut w = Writer {
        buf: Vec::with_capacity(ENTITY_STATE_LEN),
    };
    w.u8(h.protocol_version);
    w.u8(h.exercise_id);
    w.u8(h.pdu_type);
    w.u8(if h.protocol_family == 0 {
        default_family(h.pdu_type)
    } else {
        h.protocol_family
    });
    w.u32(h.timestamp.0);
    w.u16(0); // length, patched below
    w.u8(if h.protocol_version >= PROTOCOL_VERSION_7 {
        h.pdu_status
    } else {
        0
    });
    w.u8(0);

    match &pdu.body {
        PduBody::EntityState(e) => {
            w.entity_id(&e.entity_id);
            w.u8(e.force_id);
            w.u8(e.variable_parameters.len() as u8);
            w.entity_type(&e.entity_type);
            w.entity_type(&e.alternative_entity_type);
            w.vec3f(&e.linear_velocity);
            w.world(&e.location);
            w.euler(&e.orientation);
            w.u32(e.appearance);
            w.u8(e.dead_reckoning.algorithm);
            w.bytes(&e.dead_reckoning.other_parameters);
            w.vec3f(&e.dead_reckoning.linear_acceleration);
            w.vec3f(&e.dead_reckoning.angular_velocity);
            w.u8(e.marking.character_set);
            w.bytes(&e.marking.chars);
            w.u32(e.capabilities);
            w.variable_params(&e.variable_parameters);
        }
        PduBody::Fire(f) => {
            w.entity_id(&f.firing_entity);
            w.entity_id(&f.target_entity);
            w.entity_id(&f.munition_id);
            w.event_id(&f.event_id);
            w.u32(f.fire_mission_index);
            w.world(&f.location);
            w.burst(&f.descriptor);
            w.vec3f(&f.velocity);
            w.f32(f.range);
        }
        PduBody::Detonation(d) => {
            w.entity_id(&d.firing_entity);
            w.entity_id(&d.target_entity);
            w.entity_id(&d.munition_id);
            w.event_id(&d.event_id);
            w.vec3f(&d.velocity);
            w.world(&d.location);
            w.burst(&d.descriptor);
            w.vec3f(&d.location_in_entity);
            w.u8(d.result);
            w.u8(d.variable_parameters.len() as u8);
            w.u16(0);
            w.variable_params(&d.variable_parameters);
        }
        PduBody::StartResume(s) => {
            w.entity_id(&s.originating);
            w.entity_id(&s.receiving);
            w.clock(&s.real_world_time);
            w.clock(&s.simulation_time);
            w.u32(s.request_id);
        }
        PduBody::StopFreeze(s) => {
            w.entity_id(&s.originating);
            w.entity_id(&s.receiving);
            w.clock(&s.real_world_time);
            w.u8(s.reason);
            w.u8(s.frozen_behavior);
            w.u16(0);
            w.u32(s.request_id);
        }
        PduBody::RemoveEntity(r) => {
            w.entity_id(&r.originating);
            w.entity_id(&r.receiving);
            w.u32(r.request_id);
        }
        PduBody::Other(raw) => w.bytes(raw),
    }

    let len = w.buf.len() as u16;
    w.buf[8..10].copy_from_slice(&len.to_be_bytes());
    w.buf
}
