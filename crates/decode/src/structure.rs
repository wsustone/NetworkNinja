//! Tier S structure checks (ADR 0010): for every PDU type in IEEE 1278.1,
//! does the length field match the layout, including the records whose
//! counts the PDU declares?
//!
//! Each [`Layout`] holds a type's fixed size (every count zero, no optional
//! fields) and, for variable types, a walk that reads the counts and record
//! lengths and adds up the size they imply. [`check`] compares that size
//! with the length field and with the bytes the datagram actually holds.
//!
//! Clause numbers are from IEEE P1278.1/D16 Rev 18 (May 2012), the last
//! draft before IEEE 1278.1-2012. They must be verified against the
//! published standard before being quoted to a customer.

use crate::pdu::{EntityId, HEADER_LEN, PROTOCOL_VERSION_6, PROTOCOL_VERSION_7};

/// Adds a variable layout's records to the size it needs.
type WalkFn = fn(&mut Walk) -> Result<(), Stop>;

/// Where a PDU names the entity it is about (its first identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdField {
    /// A 48-bit Entity/Object/Simulation Identifier at this offset.
    Entity(usize),
    /// A 32-bit Simulation Address (site, application) at this offset.
    Simulation(usize),
    /// A 32-bit Live Entity Identifier (8-bit site and application,
    /// 16-bit entity) at this offset.
    Live(usize),
}

/// The structure of one PDU type.
pub struct Layout {
    pub pdu_type: u8,
    pub name: &'static str,
    pub family: u8,
    /// The layout clause (draft numbering, see the module docs).
    pub clause: &'static str,
    /// Size in bytes, header included, of the fields before any variable
    /// part: every count zero, every optional field absent, no trailing
    /// alignment padding. [`minimal_body`] adds the padding.
    pub fixed: usize,
    pub id: IdField,
    /// Top-level count fields as (offset, width in bytes), in PDU order.
    pub counts: &'static [(usize, u8)],
    /// Checked on DIS v6 too. The 1995-era types (1–27) kept their layouts
    /// in IEEE 1278.1-2012; later types get header checks only on v6 until
    /// the 1278.1a-1998 layouts are checked (ADR 0010, open questions).
    pub v6: bool,
    walk: Option<WalkFn>,
}

/// One structural problem in a PDU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Fewer than a header's bytes left in the datagram (and not just
    /// trailing zeros).
    HeaderTruncated { available: usize },
    /// The length field is smaller than a PDU header.
    BadLength { length: u16 },
    /// The datagram ends before the length field says the PDU does.
    Truncated { length: usize, available: usize },
    /// The layout and declared counts need more bytes than the length field
    /// gives: a count overruns the PDU, or a field is missing.
    Short { needed: usize, length: usize },
    /// The length field is larger than the layout and counts account for.
    Padded { needed: usize, length: usize },
    /// The PDU stops exactly where its last alignment padding should start:
    /// the data is all there but not padded to the boundary the layout asks.
    Unpadded { needed: usize, length: usize },
    /// A length field inside the PDU disagrees with what it describes.
    Inconsistent {
        field: &'static str,
        declared: u64,
        expected: u64,
    },
    /// The Protocol Family field doesn't match the PDU type.
    Family { family: u8, expected: u8 },
}

impl Finding {
    /// The rule a finding belongs to: `pdu-structure` (data is missing or
    /// misdescribed), `pdu-padding` (extra or missing padding only) or
    /// `pdu-family`.
    pub fn rule(&self) -> &'static str {
        match self {
            Finding::Padded { .. } | Finding::Unpadded { .. } => "pdu-padding",
            Finding::Family { .. } => "pdu-family",
            _ => "pdu-structure",
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Finding::HeaderTruncated { available } => {
                format!("only {available} bytes left in the datagram, too few for a PDU header")
            }
            Finding::BadLength { length } => format!("length field {length} is smaller than the 12-byte header"),
            Finding::Truncated { length, available } => {
                format!("length field {length} but the datagram holds only {available} bytes")
            }
            Finding::Short { needed, length } => {
                format!("length field {length} but the layout and its counts need {needed} bytes")
            }
            Finding::Padded { needed, length } => {
                format!("length field {length} but the layout and its counts account for {needed} bytes")
            }
            Finding::Unpadded { needed, length } => {
                format!("length field {length}: the data ends without its padding to {needed} bytes")
            }
            Finding::Inconsistent {
                field,
                declared,
                expected,
            } => format!("{field} is {declared}, but its data needs {expected}"),
            Finding::Family { family, expected } => {
                format!("protocol family {family}, but this PDU type belongs to family {expected}")
            }
        }
    }
}

/// What [`check`] found in the PDU at the start of a buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Header fields, when there were enough bytes for a header.
    pub version: Option<u8>,
    pub exercise: Option<u8>,
    pub pdu_type: Option<u8>,
    /// The PDU's first identifier, if the layout and bytes give one.
    pub entity: Option<EntityId>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// The layout behind the findings, for naming and citing.
    pub fn layout(&self) -> Option<&'static Layout> {
        self.pdu_type.and_then(layout)
    }
}

// ---------------------------------------------------------------- walking

/// Why a walk stopped early.
enum Stop {
    /// A field it had to read lies past the end of the PDU.
    Short(usize),
    Inconsistent {
        field: &'static str,
        declared: u64,
        expected: u64,
    },
}

/// A cursor over one PDU's bytes (as far as its length field reaches) that
/// adds up the size the layout needs. `pos` is that size so far.
struct Walk<'a> {
    b: &'a [u8],
    pos: usize,
    /// End position and size of the most recent alignment padding, to tell
    /// "unpadded" from "short".
    last_pad: (usize, usize),
}

fn round_up(n: usize, to: usize) -> usize {
    n.div_ceil(to).saturating_mul(to)
}

impl Walk<'_> {
    fn bytes(&self, at: usize, n: usize) -> Result<&[u8], Stop> {
        let end = at.saturating_add(n);
        if end > self.b.len() {
            return Err(Stop::Short(end));
        }
        Ok(&self.b[at..end])
    }
    fn u8(&self, at: usize) -> Result<usize, Stop> {
        Ok(self.bytes(at, 1)?[0] as usize)
    }
    fn u16(&self, at: usize) -> Result<usize, Stop> {
        let b = self.bytes(at, 2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]) as usize)
    }
    fn u32(&self, at: usize) -> Result<usize, Stop> {
        let b = self.bytes(at, 4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize)
    }
    fn skip(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }
    /// `count` records of `size` bytes each.
    fn records(&mut self, count: usize, size: usize) {
        self.skip(count.saturating_mul(size));
    }
    /// Padding up to a multiple of `align` bytes from the start of the PDU.
    fn pad_to(&mut self, align: usize) {
        let p = round_up(self.pos, align) - self.pos;
        self.skip(p);
        self.last_pad = (self.pos, p);
    }
    /// `count` records that state their own total length in octets as a
    /// 16-bit field at `len_at` (the standard Record Type / Record Length
    /// layout, 6.2.10 and kin).
    fn length_records(&mut self, count: usize, len_at: usize, min: usize, field: &'static str) -> Result<(), Stop> {
        for _ in 0..count {
            let len = self.u16(self.pos + len_at)?;
            if len < min {
                return Err(Stop::Inconsistent {
                    field,
                    declared: len as u64,
                    expected: min as u64,
                });
            }
            self.skip(len);
        }
        Ok(())
    }
    /// `n` Fixed Datum records, then `m` Variable Datum records (6.2.37,
    /// 6.2.93): ID, length in bits, value padded to 64 bits.
    fn datums(&mut self, n: usize, m: usize) -> Result<(), Stop> {
        self.records(n, 8);
        for _ in 0..m {
            let bits = self.u32(self.pos + 4)?;
            self.skip(8 + round_up(bits.div_ceil(8), 8));
        }
        Ok(())
    }
    /// `r` Record Sets (6.2.73): 16 bytes, then Record Count records of
    /// Record Length bits, padded to 64 bits.
    fn record_sets(&mut self, r: usize) -> Result<(), Stop> {
        for _ in 0..r {
            let bits = self.u16(self.pos + 12)?.saturating_mul(self.u16(self.pos + 14)?);
            self.skip(16 + round_up(bits.div_ceil(8), 8));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- walks

fn variable_parameters_at(at: usize) -> impl Fn(&mut Walk) -> Result<(), Stop> {
    move |w| {
        let n = w.u8(at)?;
        w.records(n, 16);
        Ok(())
    }
}

fn entity_state(w: &mut Walk) -> Result<(), Stop> {
    variable_parameters_at(19)(w)
}
fn detonation(w: &mut Walk) -> Result<(), Stop> {
    variable_parameters_at(101)(w)
}
fn service_request(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(25)?;
    w.records(n, 12);
    Ok(())
}
fn resupply(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(24)?;
    w.records(n, 12);
    Ok(())
}
/// Action Request/Response, Set Data, Data, Event Report and their -R
/// forms: two 32-bit counts, then the datums.
fn datums_at(n_at: usize) -> impl Fn(&mut Walk) -> Result<(), Stop> {
    move |w| {
        let (n, m) = (w.u32(n_at)?, w.u32(n_at + 4)?);
        w.datums(n, m)
    }
}
fn datums_32(w: &mut Walk) -> Result<(), Stop> {
    datums_at(32)(w)
}
fn datums_40(w: &mut Walk) -> Result<(), Stop> {
    datums_at(40)(w)
}
fn comment(w: &mut Walk) -> Result<(), Stop> {
    datums_at(24)(w)
}
/// Data Query (-R): datum IDs only, 32 bits each.
fn data_query_at(n_at: usize) -> impl Fn(&mut Walk) -> Result<(), Stop> {
    move |w| {
        let (n, m) = (w.u32(n_at)?, w.u32(n_at + 4)?);
        w.records(n.saturating_add(m), 4);
        Ok(())
    }
}
fn data_query(w: &mut Walk) -> Result<(), Stop> {
    data_query_at(32)(w)
}
fn data_query_r(w: &mut Walk) -> Result<(), Stop> {
    data_query_at(36)(w)
}
fn record_query_r(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u32(36)?;
    w.records(n, 4);
    Ok(())
}
fn record_sets_36(w: &mut Walk) -> Result<(), Stop> {
    let r = w.u32(36)?;
    w.record_sets(r)
}

/// EE PDU (7.6.2): systems of beams of track/jam targets. Each system and
/// beam also states its own length in 32-bit words (0 when over 1020
/// octets), which must agree with its contents.
fn electromagnetic_emission(w: &mut Walk) -> Result<(), Stop> {
    let systems = w.u8(25)?;
    for _ in 0..systems {
        let start = w.pos;
        let declared = w.u8(start)?;
        let beams = w.u8(start + 1)?;
        w.skip(20);
        for _ in 0..beams {
            let b = w.pos;
            let declared = w.u8(b)?;
            let targets = w.u8(b + 45)?;
            w.skip(52 + 8 * targets);
            words_agree("Beam Data Length", declared, w.pos - b)?;
        }
        words_agree("System Data Length", declared, w.pos - start)?;
    }
    Ok(())
}

fn words_agree(field: &'static str, declared: usize, size: usize) -> Result<(), Stop> {
    let expected = if size > 1020 { 0 } else { size / 4 };
    if declared != expected {
        return Err(Stop::Inconsistent {
            field,
            declared: declared as u64,
            expected: expected as u64,
        });
    }
    Ok(())
}

/// Transmitter PDU (7.7.2): Modulation Parameters (M octets), Antenna
/// Pattern (A octets), then Variable Transmitter Parameters records.
fn transmitter(w: &mut Walk) -> Result<(), Stop> {
    let vtp = w.u16(30)?;
    let antenna = w.u16(70)?;
    let modulation = w.u8(100)?;
    w.skip(modulation + antenna);
    w.length_records(vtp, 4, 6, "Variable Transmitter Parameters Record Length")
}

/// Signal and Intercom Signal (7.7.3, 7.7.5): Data Length bits of data,
/// padded to 32 bits.
fn signal(w: &mut Walk) -> Result<(), Stop> {
    let bits = w.u16(28)?;
    w.skip(bits.div_ceil(8));
    w.pad_to(4);
    Ok(())
}

/// IFF PDU (7.6.5): Layer 1 is fixed; each further layer starts with a
/// Layer Header whose length covers the whole layer.
fn iff(w: &mut Walk) -> Result<(), Stop> {
    while w.pos < w.b.len() {
        let len = w.u16(w.pos + 2)?;
        if len < 4 {
            return Err(Stop::Inconsistent {
                field: "Layer Header Length",
                declared: len as u64,
                expected: 4,
            });
        }
        w.skip(len);
    }
    Ok(())
}

/// UA PDU (7.6.4): shafts, APAs, then emitter systems of beams.
fn underwater_acoustic(w: &mut Walk) -> Result<(), Stop> {
    let (shafts, apas, systems) = (w.u8(29)?, w.u8(30)?, w.u8(31)?);
    w.records(shafts, 8);
    w.records(apas, 4);
    for _ in 0..systems {
        let beams = w.u8(w.pos + 1)?;
        w.skip(20);
        w.records(beams, 24);
    }
    Ok(())
}

fn sees(w: &mut Walk) -> Result<(), Stop> {
    let (n, m) = (w.u16(24)?, w.u16(26)?);
    w.records(n.saturating_add(m), 8);
    Ok(())
}

fn intercom_control(w: &mut Walk) -> Result<(), Stop> {
    let k = w.u32(36)?;
    w.skip(k);
    Ok(())
}

/// Aggregate State PDU (7.8.2).
fn aggregate_state(w: &mut Walk) -> Result<(), Stop> {
    let (aggs, ents, silent_aggs, silent_ents) = (w.u16(124)?, w.u16(126)?, w.u16(128)?, w.u16(130)?);
    // The fixed size includes the variable-datum count, which follows the
    // ID lists and silent systems; walk from the end of the counts.
    w.pos = 132;
    w.records(aggs.saturating_add(ents), 6);
    w.pad_to(4);
    w.records(silent_aggs, 12);
    for _ in 0..silent_ents {
        let appearances = w.u16(w.pos + 2)?;
        w.skip(12 + 4 * appearances);
    }
    let m = w.u32(w.pos)?;
    w.skip(4);
    w.datums(0, m)
}

/// IsGroupOf (7.8.3): the GED record size depends on the Grouped Entity
/// Category (SISO-REF-010), so for now the records only have to divide the
/// remaining length evenly.
fn is_group_of(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(19)?;
    let rest = w.b.len().saturating_sub(w.pos);
    if n > 0 && !rest.is_multiple_of(n) {
        return Err(Stop::Inconsistent {
            field: "Number of Grouped Entities",
            declared: n as u64,
            expected: 0,
        });
    }
    if n > 0 {
        w.skip(rest);
    }
    Ok(())
}

fn minefield_state(w: &mut Walk) -> Result<(), Stop> {
    let (n, m) = (w.u8(21)?, w.u16(30)?);
    w.records(n.saturating_add(m), 8);
    Ok(())
}

fn minefield_query(w: &mut Walk) -> Result<(), Stop> {
    let (n, m) = (w.u8(25)?, w.u8(27)?);
    w.records(n, 8);
    w.records(m, 2);
    w.pad_to(4);
    Ok(())
}

/// Minefield Data PDU (7.9.4): which per-mine arrays are present follows
/// the Data Filter bits.
fn minefield_data(w: &mut Walk) -> Result<(), Stop> {
    let (mines, sensors) = (w.u8(34)?, w.u8(35)?);
    let filter = w.u32(40)?;
    let f = |bit: u32| (filter >> bit) & 1 == 1;
    let burial = f(0) || f(1) || f(2);
    w.records(sensors, 2);
    w.pad_to(4);
    w.records(mines, 12); // location
    for (present, size) in [
        (burial, 4),          // ground burial depth offset
        (f(1), 4),            // water
        (f(2), 4),            // snow
        (f(3) || burial, 12), // orientation
        (f(4), 4),            // thermal contrast
        (f(5), 4),            // reflectance
        (f(6), 8),            // emplacement time
    ] {
        if present {
            w.records(mines, size);
        }
    }
    w.records(mines, 2); // mine entity numbers
    if f(8) {
        w.records(mines, 2); // fusing
    }
    if f(9) {
        w.records(mines.saturating_mul(sensors), 1); // scalar detection coefficients
    }
    if f(10) {
        w.records(mines, 1); // paint scheme
    }
    w.pad_to(4);
    if f(7) {
        let mut wires = 0usize;
        for i in 0..mines {
            wires = wires.saturating_add(w.u8(w.pos + i)?);
        }
        w.skip(mines);
        w.pad_to(4);
        let mut vertices = 0usize;
        for i in 0..wires {
            vertices = vertices.saturating_add(w.u8(w.pos + i)?);
        }
        w.skip(wires);
        w.pad_to(4);
        w.records(vertices, 12);
    }
    Ok(())
}

fn minefield_nack(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(25)?;
    w.records(n, 1);
    w.pad_to(4);
    Ok(())
}

/// Environmental Process (7.10.2): Environment records state their length
/// in bits.
fn environmental_process(w: &mut Walk) -> Result<(), Stop> {
    let m = w.u16(28)?;
    for _ in 0..m {
        let bits = w.u16(w.pos + 4)?;
        if bits < 64 || bits % 8 != 0 {
            return Err(Stop::Inconsistent {
                field: "Environment Record Length",
                declared: bits as u64,
                expected: round_up(bits.max(64), 64) as u64,
            });
        }
        w.skip(bits / 8);
    }
    Ok(())
}

/// Gridded Data (7.10.3): axis descriptors, then Grid Data records to the
/// end of the PDU. The record count follows from the axes, so the records
/// are walked until the length runs out; an unknown representation stops
/// the walk without a finding.
fn gridded_data(w: &mut Walk) -> Result<(), Stop> {
    let axes = w.u8(26)?;
    for _ in 0..axes {
        match w.u8(w.pos + 19)? {
            1 => {
                let points = w.u16(w.pos + 20)?;
                w.skip(round_up(40 + 2 * points, 8));
            }
            _ => w.skip(24),
        }
    }
    while w.pos < w.b.len() {
        let rep = w.u16(w.pos + 2)?;
        let size = match rep {
            0 => round_up(6 + w.u16(w.pos + 4)?, 2),
            1 => round_up(14 + 2 * w.u16(w.pos + 12)?, 4),
            2 => 8 + 4 * w.u16(w.pos + 4)?,
            _ => {
                w.pos = w.b.len();
                break;
            }
        };
        w.skip(size);
    }
    Ok(())
}

fn linear_object(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(31)?;
    w.records(n, 64);
    Ok(())
}

fn areal_object(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u16(38)?;
    w.records(n, 24);
    Ok(())
}

/// DE Fire, Entity Damage Status, IO Action and IO Report: a 16-bit count
/// of standard records.
fn standard_records_at(n_at: usize, field: &'static str) -> impl Fn(&mut Walk) -> Result<(), Stop> {
    move |w| {
        let n = w.u16(n_at)?;
        w.length_records(n, 4, 6, field)
    }
}
fn de_fire(w: &mut Walk) -> Result<(), Stop> {
    standard_records_at(86, "DE Record Length")(w)
}
fn entity_damage_status(w: &mut Walk) -> Result<(), Stop> {
    standard_records_at(22, "Damage Description Record Length")(w)
}
fn io_action(w: &mut Walk) -> Result<(), Stop> {
    standard_records_at(54, "IO Record Length")(w)
}
fn io_report(w: &mut Walk) -> Result<(), Stop> {
    standard_records_at(38, "IO Record Length")(w)
}

/// Attribute PDU (7.2.6): record sets, each an object ID and a count of
/// standard Attribute records.
fn attribute(w: &mut Walk) -> Result<(), Stop> {
    let sets = w.u16(30)?;
    for _ in 0..sets {
        let n = w.u16(w.pos + 6)?;
        w.skip(8);
        w.length_records(n, 4, 6, "Attribute Record Length")?;
    }
    Ok(())
}

fn entity_state_update(w: &mut Walk) -> Result<(), Stop> {
    variable_parameters_at(19)(w)
}

fn tspi(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(53)?;
    w.skip(n);
    Ok(())
}

fn bit(flags: usize, i: u32) -> usize {
    (flags >> i) & 1
}

/// Appearance PDU (9.4.3): optional fields by Appearance Flag-1/-2 bits.
fn appearance(w: &mut Walk) -> Result<(), Stop> {
    let f = w.u8(16)?;
    let g = if bit(f, 7) == 1 { w.u8(17)? } else { 0 };
    w.skip(
        bit(f, 7)
            + bit(f, 0)
            + 8 * bit(f, 1)
            + 8 * bit(f, 2)
            + 12 * bit(f, 3)
            + 4 * bit(f, 4)
            + 4 * (bit(f, 5) + bit(f, 6) + bit(g, 0) + bit(g, 1)),
    );
    Ok(())
}

fn articulated_parts(w: &mut Walk) -> Result<(), Stop> {
    let n = w.u8(16)?;
    w.records(n, 16);
    Ok(())
}

/// LE Fire PDU (9.4.5): optional fields by the Flags bits.
fn le_fire(w: &mut Walk) -> Result<(), Stop> {
    let f = w.u8(16)?;
    w.skip(
        4 * bit(f, 0) + (2 * bit(f, 1) + 2) * bit(f, 2) + 2 * bit(f, 3) + 8 * bit(f, 6) + 4 * bit(f, 4) + 4 * bit(f, 5),
    );
    Ok(())
}

/// LE Detonation PDU (9.4.6): optional fields by Detonation Flag-1/-2.
fn le_detonation(w: &mut Walk) -> Result<(), Stop> {
    let f = w.u8(16)?;
    let g = if bit(f, 7) == 1 { w.u8(17)? } else { 0 };
    w.skip(
        bit(f, 7)
            + 4 * bit(f, 0)
            + (2 * bit(f, 1) + 2) * bit(f, 2)
            + (2 * bit(f, 3) + 2) * bit(g, 1)
            + 8 * (1 - bit(f, 6))
            + 6 * bit(g, 0)
            + 4 * bit(f, 4)
            + 4 * bit(f, 5)
            + 6 * bit(f, 6),
    );
    Ok(())
}

// ---------------------------------------------------------------- table

const fn fixed(pdu_type: u8, name: &'static str, family: u8, clause: &'static str, size: usize, id: IdField) -> Layout {
    Layout {
        pdu_type,
        name,
        family,
        clause,
        fixed: size,
        id,
        counts: &[],
        v6: pdu_type <= 27,
        walk: None,
    }
}

impl Layout {
    /// A variable layout: its top-level count fields and its walk.
    const fn with(self, counts: &'static [(usize, u8)], walk: WalkFn) -> Layout {
        Layout {
            counts,
            walk: Some(walk),
            ..self
        }
    }
}

use IdField::{Entity as E, Live as L, Simulation as S};

/// Every PDU type in IEEE 1278.1, in PDU Type order. Sizes are bytes.
static LAYOUTS: [Layout; 72] = [
    fixed(1, "EntityState", 1, "7.2.2", 144, E(12)).with(&[(19, 1)], entity_state),
    fixed(2, "Fire", 2, "7.3.2", 96, E(12)),
    fixed(3, "Detonation", 2, "7.3.3", 104, E(12)).with(&[(101, 1)], detonation),
    fixed(4, "Collision", 1, "7.2.3", 60, E(12)),
    fixed(5, "ServiceRequest", 3, "7.4.2", 28, E(12)).with(&[(25, 1)], service_request),
    fixed(6, "ResupplyOffer", 3, "7.4.3", 28, E(12)).with(&[(24, 1)], resupply),
    fixed(7, "ResupplyReceived", 3, "7.4.4", 28, E(12)).with(&[(24, 1)], resupply),
    fixed(8, "ResupplyCancel", 3, "7.4.5", 24, E(12)),
    fixed(9, "RepairComplete", 3, "7.4.6", 28, E(12)),
    fixed(10, "RepairResponse", 3, "7.4.7", 28, E(12)),
    fixed(11, "CreateEntity", 5, "7.5.2", 28, E(12)),
    fixed(12, "RemoveEntity", 5, "7.5.3", 28, E(12)),
    fixed(13, "StartResume", 5, "7.5.4", 44, E(12)),
    fixed(14, "StopFreeze", 5, "7.5.5", 40, E(12)),
    fixed(15, "Acknowledge", 5, "7.5.6", 32, E(12)),
    fixed(16, "ActionRequest", 5, "7.5.7", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(17, "ActionResponse", 5, "7.5.8", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(18, "DataQuery", 5, "7.5.9", 40, E(12)).with(&[(32, 4), (36, 4)], data_query),
    fixed(19, "SetData", 5, "7.5.10", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(20, "Data", 5, "7.5.11", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(21, "EventReport", 5, "7.5.12", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(22, "Comment", 5, "7.5.13", 32, E(12)).with(&[(24, 4), (28, 4)], comment),
    fixed(23, "ElectromagneticEmission", 6, "7.6.2", 28, E(12)).with(&[(25, 1)], electromagnetic_emission),
    fixed(24, "Designator", 6, "7.6.3", 88, E(12)),
    fixed(25, "Transmitter", 4, "7.7.2", 104, E(12)).with(&[(30, 2), (70, 2), (100, 1)], transmitter),
    fixed(26, "Signal", 4, "7.7.3", 32, E(12)).with(&[(28, 2)], signal),
    fixed(27, "Receiver", 4, "7.7.4", 36, E(12)),
    fixed(28, "IFF", 6, "7.6.5", 60, E(12)).with(&[], iff),
    fixed(29, "UnderwaterAcoustic", 6, "7.6.4", 32, E(12)).with(&[(29, 1), (30, 1), (31, 1)], underwater_acoustic),
    fixed(30, "SupplementalEmission", 6, "7.6.6", 28, E(12)).with(&[(24, 2), (26, 2)], sees),
    fixed(31, "IntercomSignal", 4, "7.7.5", 32, E(12)).with(&[(28, 2)], signal),
    fixed(32, "IntercomControl", 4, "7.7.6", 40, E(14)).with(&[(36, 4)], intercom_control),
    fixed(33, "AggregateState", 7, "7.8.2", 136, E(12))
        .with(&[(124, 2), (126, 2), (128, 2), (130, 2)], aggregate_state),
    fixed(34, "IsGroupOf", 7, "7.8.3", 40, E(12)).with(&[(19, 1)], is_group_of),
    fixed(35, "TransferOwnership", 7, "7.8.4", 40, E(12)).with(&[(36, 4)], record_sets_36),
    fixed(36, "IsPartOf", 7, "7.8.5", 52, E(12)),
    fixed(37, "MinefieldState", 8, "7.9.2", 72, E(12)).with(&[(21, 1), (30, 2)], minefield_state),
    fixed(38, "MinefieldQuery", 8, "7.9.3", 40, E(12)).with(&[(25, 1), (27, 1)], minefield_query),
    fixed(39, "MinefieldData", 8, "7.9.4", 44, E(12)).with(&[(34, 1), (35, 1)], minefield_data),
    fixed(40, "MinefieldResponseNack", 8, "7.9.5", 26, E(12)).with(&[(25, 1)], minefield_nack),
    fixed(41, "EnvironmentalProcess", 9, "7.10.2", 32, E(12)).with(&[(28, 2)], environmental_process),
    fixed(42, "GriddedData", 9, "7.10.3", 64, E(12)).with(&[(26, 1)], gridded_data),
    fixed(43, "PointObjectState", 9, "7.10.4", 88, E(12)),
    fixed(44, "LinearObjectState", 9, "7.10.5", 40, E(12)).with(&[(31, 1)], linear_object),
    fixed(45, "ArealObjectState", 9, "7.10.6", 48, E(12)).with(&[(38, 2)], areal_object),
    fixed(46, "TSPI", 11, "9.4.2.5", 54, L(12)).with(&[(53, 1)], tspi),
    fixed(47, "Appearance", 11, "9.4.3.5", 17, L(12)).with(&[], appearance),
    fixed(48, "ArticulatedParts", 11, "9.4.4.5", 17, L(12)).with(&[(16, 1)], articulated_parts),
    fixed(49, "LEFire", 11, "9.4.5.6", 35, L(12)).with(&[], le_fire),
    fixed(50, "LEDetonation", 11, "9.4.6.8", 32, L(12)).with(&[], le_detonation),
    fixed(51, "CreateEntityR", 10, "7.11.2", 32, E(12)),
    fixed(52, "RemoveEntityR", 10, "7.11.3", 32, E(12)),
    fixed(53, "StartResumeR", 10, "7.11.4", 48, E(12)),
    fixed(54, "StopFreezeR", 10, "7.11.5", 40, E(12)),
    fixed(55, "AcknowledgeR", 10, "7.11.6", 32, E(12)),
    fixed(56, "ActionRequestR", 10, "7.11.7", 48, E(12)).with(&[(40, 4), (44, 4)], datums_40),
    fixed(57, "ActionResponseR", 10, "7.11.8", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(58, "DataQueryR", 10, "7.11.9", 44, E(12)).with(&[(36, 4), (40, 4)], data_query_r),
    fixed(59, "SetDataR", 10, "7.11.10", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(60, "DataR", 10, "7.11.11", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(61, "EventReportR", 10, "7.11.12", 40, E(12)).with(&[(32, 4), (36, 4)], datums_32),
    fixed(62, "CommentR", 10, "7.11.13", 32, E(12)).with(&[(24, 4), (28, 4)], comment),
    fixed(63, "RecordR", 10, "7.11.16", 40, E(12)).with(&[(36, 4)], record_sets_36),
    fixed(64, "SetRecordR", 10, "7.11.15", 40, E(12)).with(&[(36, 4)], record_sets_36),
    fixed(65, "RecordQueryR", 10, "7.11.14", 40, E(12)).with(&[(36, 4)], record_query_r),
    fixed(66, "CollisionElastic", 1, "7.2.4", 100, E(12)),
    fixed(67, "EntityStateUpdate", 1, "7.2.5", 72, E(12)).with(&[(19, 1)], entity_state_update),
    fixed(68, "DirectedEnergyFire", 2, "7.3.4", 88, E(12)).with(&[(86, 2)], de_fire),
    fixed(69, "EntityDamageStatus", 2, "7.3.5", 24, E(12)).with(&[(22, 2)], entity_damage_status),
    fixed(70, "IOAction", 13, "7.12.2", 56, E(12)).with(&[(54, 2)], io_action),
    fixed(71, "IOReport", 13, "7.12.3", 40, E(12)).with(&[(38, 2)], io_report),
    fixed(72, "Attribute", 1, "7.2.6", 32, S(12)).with(&[(30, 2)], attribute),
];

/// Every PDU type's layout, in PDU Type order.
pub fn layouts() -> &'static [Layout] {
    &LAYOUTS
}

/// The layout of one PDU type, if it is one of the 72 standard types.
pub fn layout(pdu_type: u8) -> Option<&'static Layout> {
    LAYOUTS.get((pdu_type as usize).wrapping_sub(1))
}

impl Layout {
    /// The size the layout needs for `pdu` (bytes from the PDU start, as
    /// far as its length field reaches), or why it can't say.
    fn needed(&self, pdu: &[u8]) -> Result<(usize, (usize, usize)), Stop> {
        if pdu.len() < self.fixed {
            return Err(Stop::Short(self.fixed));
        }
        let mut w = Walk {
            b: pdu,
            pos: self.fixed,
            last_pad: (0, 0),
        };
        if let Some(walk) = self.walk {
            walk(&mut w)?;
        }
        Ok((w.pos, w.last_pad))
    }

    fn entity(&self, pdu: &[u8]) -> Option<EntityId> {
        let u16_at = |at: usize| pdu.get(at..at + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
        match self.id {
            IdField::Entity(at) => Some(EntityId::new(u16_at(at)?, u16_at(at + 2)?, u16_at(at + 4)?)),
            IdField::Simulation(at) => Some(EntityId::new(u16_at(at)?, u16_at(at + 2)?, 0)),
            IdField::Live(at) => Some(EntityId::new(
                *pdu.get(at)? as u16,
                *pdu.get(at + 1)? as u16,
                u16_at(at + 2)?,
            )),
        }
    }
}

/// Check the structure of the PDU at the start of `buf` (the rest of a
/// datagram from where this PDU begins).
pub fn check(buf: &[u8]) -> Report {
    let mut r = Report {
        version: None,
        exercise: None,
        pdu_type: None,
        entity: None,
        findings: Vec::new(),
    };
    if buf.len() < HEADER_LEN {
        r.findings.push(Finding::HeaderTruncated { available: buf.len() });
        return r;
    }
    let (version, pdu_type, family) = (buf[0], buf[2], buf[3]);
    r.version = Some(version);
    r.exercise = Some(buf[1]);
    r.pdu_type = Some(pdu_type);
    let length = u16::from_be_bytes([buf[8], buf[9]]);
    let Some(layout) = layout(pdu_type) else {
        if (length as usize) < HEADER_LEN {
            r.findings.push(Finding::BadLength { length });
        }
        return r;
    };
    r.entity = layout.entity(buf);
    let checked = version == PROTOCOL_VERSION_7 || (version == PROTOCOL_VERSION_6 && layout.v6);
    if checked && family != layout.family {
        r.findings.push(Finding::Family {
            family,
            expected: layout.family,
        });
    }
    let length = length as usize;
    if length < HEADER_LEN {
        r.findings.push(Finding::BadLength { length: length as u16 });
        return r;
    }
    if length > buf.len() {
        r.findings.push(Finding::Truncated {
            length,
            available: buf.len(),
        });
        return r;
    }
    if !checked {
        return r;
    }
    match layout.needed(&buf[..length]) {
        Ok((needed, _)) if needed < length => r.findings.push(Finding::Padded { needed, length }),
        Ok((needed, (pad_end, pad))) if needed > length => {
            // Everything but the final alignment padding is present.
            if pad_end == needed && length >= needed - pad {
                r.findings.push(Finding::Unpadded { needed, length });
            } else {
                r.findings.push(Finding::Short { needed, length });
            }
        }
        Ok(_) => {}
        Err(Stop::Short(needed)) => r.findings.push(Finding::Short { needed, length }),
        Err(Stop::Inconsistent {
            field,
            declared,
            expected,
        }) => r.findings.push(Finding::Inconsistent {
            field,
            declared,
            expected,
        }),
    }
    r
}

/// The smallest valid PDU body (after the header) of a type: all zeros, so
/// every count is zero and every optional field absent, padded as the
/// layout requires.
pub fn minimal_body(pdu_type: u8) -> Option<Vec<u8>> {
    let l = layout(pdu_type)?;
    let mut pdu = vec![0; l.fixed];
    while let Ok((needed, _)) = l.needed(&pdu) {
        if needed <= pdu.len() {
            break;
        }
        pdu.resize(needed, 0);
    }
    Some(pdu.split_off(HEADER_LEN))
}
