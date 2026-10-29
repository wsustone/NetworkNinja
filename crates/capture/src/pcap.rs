//! Classic pcap reading and writing (no libpcap needed).

use crate::Datagram;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_IPV4: u32 = 228;

#[derive(Debug)]
pub enum PcapError {
    Io(io::Error),
    /// Neither a classic pcap nor a pcapng file.
    BadMagic(u32),
    UnsupportedLinkType(u32),
    /// The file is structurally broken.
    Corrupt(String),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "{e}"),
            PcapError::BadMagic(m) => write!(f, "not a pcap file (magic {m:#010x})"),
            PcapError::UnsupportedLinkType(l) => write!(f, "unsupported pcap link type {l}"),
            PcapError::Corrupt(why) => write!(f, "corrupt capture file: {why}"),
        }
    }
}

impl std::error::Error for PcapError {}

impl From<io::Error> for PcapError {
    fn from(e: io::Error) -> Self {
        PcapError::Io(e)
    }
}

/// Counts of records the reader skipped, so nothing is dropped silently.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PcapStats {
    pub records: u64,
    pub udp_datagrams: u64,
    pub not_ipv4_udp: u64,
    pub fragments: u64,
    pub truncated: u64,
}

const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;
const PCAPNG_IDB: u32 = 1;
const PCAPNG_OBSOLETE_PACKET: u32 = 2;
const PCAPNG_SIMPLE_PACKET: u32 = 3;
const PCAPNG_ENHANCED_PACKET: u32 = 6;
/// Largest pcapng block we accept, as a sanity bound.
const PCAPNG_MAX_BLOCK: usize = 64 * 1024 * 1024;

/// A pcapng interface: its link type and timestamp units per second.
#[derive(Debug, Clone, Copy)]
struct Interface {
    link_type: u32,
    units_per_sec: u64,
}

enum Format {
    Classic { nanos: bool, link_type: u32 },
    Ng { interfaces: Vec<Interface> },
}

/// One captured frame before link-layer parsing.
struct Frame {
    at: SystemTime,
    link_type: u32,
    data: Vec<u8>,
    /// Captured length was shorter than the original packet.
    snapped: bool,
}

/// Reads UDP datagrams from a classic pcap or a pcapng file.
pub struct PcapReader<R: Read> {
    input: R,
    big_endian: bool,
    format: Format,
    last_ts: SystemTime,
    pub stats: PcapStats,
}

fn read_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, PcapError> {
    match r.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e.into()),
    }
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut input: R) -> Result<Self, PcapError> {
        let mut first = [0u8; 4];
        input.read_exact(&mut first)?;
        if u32::from_le_bytes(first) == PCAPNG_SHB {
            let mut reader = PcapReader {
                input,
                big_endian: false,
                format: Format::Ng { interfaces: Vec::new() },
                last_ts: UNIX_EPOCH,
                stats: PcapStats::default(),
            };
            reader.read_section_header()?;
            return Ok(reader);
        }

        let mut rest = [0u8; 20];
        input.read_exact(&mut rest)?;
        let magic_le = u32::from_le_bytes(first);
        let magic_be = u32::from_be_bytes(first);
        let (big_endian, nanos) = match (magic_le, magic_be) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            _ => return Err(PcapError::BadMagic(magic_be)),
        };
        let b = &rest[16..20];
        let a = [b[0], b[1], b[2], b[3]];
        let link_type = if big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        } & 0x0fff_ffff;
        if !supported_link(link_type) {
            return Err(PcapError::UnsupportedLinkType(link_type));
        }
        Ok(PcapReader {
            input,
            big_endian,
            format: Format::Classic { nanos, link_type },
            last_ts: UNIX_EPOCH,
            stats: PcapStats::default(),
        })
    }

    fn u16_at(&self, b: &[u8], at: usize) -> u16 {
        let a = [b[at], b[at + 1]];
        if self.big_endian {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }

    fn u32_at(&self, b: &[u8], at: usize) -> u32 {
        let a = [b[at], b[at + 1], b[at + 2], b[at + 3]];
        if self.big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }

    /// Read the rest of a pcapng Section Header Block (its type is consumed).
    fn read_section_header(&mut self) -> Result<(), PcapError> {
        let mut hdr = [0u8; 8]; // total length, byte-order magic
        self.input.read_exact(&mut hdr)?;
        self.big_endian = match u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) {
            PCAPNG_BYTE_ORDER => false,
            m if m.swap_bytes() == PCAPNG_BYTE_ORDER => true,
            _ => {
                return Err(PcapError::Corrupt(
                    "pcapng section header has a bad byte-order magic".into(),
                ))
            }
        };
        let len = self.u32_at(&hdr, 0) as usize;
        if !(28..=PCAPNG_MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
            return Err(PcapError::Corrupt(format!("pcapng section header length {len}")));
        }
        let mut rest = vec![0u8; len - 12];
        self.input.read_exact(&mut rest)?;
        self.format = Format::Ng { interfaces: Vec::new() };
        Ok(())
    }

    /// Convert pcapng timestamp units to a time. Out-of-range values (a
    /// corrupt file) are an error, never a panic: `SystemTime`'s range is
    /// platform-specific and smaller on Windows.
    fn timestamp(&mut self, units: u64, units_per_sec: u64) -> Result<SystemTime, PcapError> {
        let secs = units / units_per_sec;
        let nanos = ((units % units_per_sec) as u128 * 1_000_000_000 / units_per_sec as u128) as u64;
        let t = UNIX_EPOCH
            .checked_add(Duration::from_secs(secs) + Duration::from_nanos(nanos))
            .ok_or_else(|| PcapError::Corrupt(format!("timestamp {units} out of range")))?;
        self.last_ts = t;
        Ok(t)
    }

    fn next_frame(&mut self) -> Result<Option<Frame>, PcapError> {
        if let Format::Classic { nanos, link_type } = self.format {
            let mut rec = [0u8; 16];
            if !read_or_eof(&mut self.input, &mut rec)? {
                return Ok(None);
            }
            let secs = self.u32_at(&rec, 0) as u64;
            let frac = self.u32_at(&rec, 4) as u64;
            let incl = self.u32_at(&rec, 8) as usize;
            let orig = self.u32_at(&rec, 12) as usize;
            if incl > PCAPNG_MAX_BLOCK {
                return Err(PcapError::Corrupt(format!("record length {incl}")));
            }
            let mut data = vec![0u8; incl];
            if !read_or_eof(&mut self.input, &mut data)? {
                self.stats.truncated += 1;
                return Ok(None);
            }
            let at =
                UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(if nanos { frac } else { frac * 1000 });
            return Ok(Some(Frame {
                at,
                link_type,
                data,
                snapped: incl < orig,
            }));
        }

        loop {
            let mut hdr = [0u8; 8];
            if !read_or_eof(&mut self.input, &mut hdr)? {
                return Ok(None);
            }
            let block_type = self.u32_at(&hdr, 0);
            if block_type == PCAPNG_SHB {
                // A new section: re-read byte order. The length we just read
                // may be in the new section's byte order, so read it again.
                let mut magic = [0u8; 4];
                self.input.read_exact(&mut magic)?;
                self.big_endian = match u32::from_le_bytes(magic) {
                    PCAPNG_BYTE_ORDER => false,
                    m if m.swap_bytes() == PCAPNG_BYTE_ORDER => true,
                    _ => {
                        return Err(PcapError::Corrupt(
                            "pcapng section header has a bad byte-order magic".into(),
                        ))
                    }
                };
                let len = self.u32_at(&hdr, 4) as usize;
                if !(28..=PCAPNG_MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
                    return Err(PcapError::Corrupt(format!("pcapng section header length {len}")));
                }
                let mut rest = vec![0u8; len - 12];
                self.input.read_exact(&mut rest)?;
                self.format = Format::Ng { interfaces: Vec::new() };
                continue;
            }
            let len = self.u32_at(&hdr, 4) as usize;
            if !(12..=PCAPNG_MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
                return Err(PcapError::Corrupt(format!("pcapng block length {len}")));
            }
            let mut body = vec![0u8; len - 8];
            if !read_or_eof(&mut self.input, &mut body)? {
                self.stats.truncated += 1;
                return Ok(None);
            }
            body.truncate(len - 12); // drop the trailing length copy
            let Format::Ng { interfaces } = &self.format else {
                unreachable!()
            };
            let iface = |i: usize| interfaces.get(i).copied();

            match block_type {
                PCAPNG_IDB => {
                    if body.len() < 8 {
                        return Err(PcapError::Corrupt("short interface block".into()));
                    }
                    let link_type = self.u16_at(&body, 0) as u32;
                    let mut units_per_sec = 1_000_000u64;
                    let mut off = 8;
                    while off + 4 <= body.len() {
                        let code = self.u16_at(&body, off);
                        let olen = self.u16_at(&body, off + 2) as usize;
                        if code == 0 || off + 4 + olen > body.len() {
                            break;
                        }
                        if code == 9 && olen >= 1 {
                            let v = body[off + 4];
                            let exp = (v & 0x7f) as u32;
                            units_per_sec = if v & 0x80 == 0 {
                                10u64.checked_pow(exp)
                            } else {
                                2u64.checked_pow(exp)
                            }
                            .filter(|&u| u > 0)
                            .ok_or_else(|| PcapError::Corrupt(format!("timestamp resolution {v:#x}")))?;
                        }
                        off += 4 + olen.div_ceil(4) * 4;
                    }
                    if let Format::Ng { interfaces } = &mut self.format {
                        interfaces.push(Interface {
                            link_type,
                            units_per_sec,
                        });
                    }
                }
                PCAPNG_ENHANCED_PACKET | PCAPNG_OBSOLETE_PACKET => {
                    if body.len() < 20 {
                        return Err(PcapError::Corrupt("short packet block".into()));
                    }
                    let id = if block_type == PCAPNG_ENHANCED_PACKET {
                        self.u32_at(&body, 0) as usize
                    } else {
                        self.u16_at(&body, 0) as usize
                    };
                    let Some(ifc) = iface(id) else {
                        return Err(PcapError::Corrupt(format!("packet for unknown interface {id}")));
                    };
                    let units = ((self.u32_at(&body, 4) as u64) << 32) | self.u32_at(&body, 8) as u64;
                    let caplen = self.u32_at(&body, 12) as usize;
                    let orig = self.u32_at(&body, 16) as usize;
                    if 20 + caplen > body.len() {
                        return Err(PcapError::Corrupt("packet data runs past its block".into()));
                    }
                    let data = body[20..20 + caplen].to_vec();
                    let at = self.timestamp(units, ifc.units_per_sec)?;
                    return Ok(Some(Frame {
                        at,
                        link_type: ifc.link_type,
                        data,
                        snapped: caplen < orig,
                    }));
                }
                PCAPNG_SIMPLE_PACKET => {
                    let Some(ifc) = iface(0) else {
                        return Err(PcapError::Corrupt("simple packet before any interface".into()));
                    };
                    if body.len() < 4 {
                        return Err(PcapError::Corrupt("short simple packet block".into()));
                    }
                    let orig = self.u32_at(&body, 0) as usize;
                    let caplen = orig.min(body.len() - 4);
                    let data = body[4..4 + caplen].to_vec();
                    return Ok(Some(Frame {
                        at: self.last_ts,
                        link_type: ifc.link_type,
                        data,
                        snapped: caplen < orig,
                    }));
                }
                _ => {} // statistics, name resolution, custom blocks: skip
            }
        }
    }

    /// Next UDP datagram, skipping (and counting) anything else.
    pub fn next_datagram(&mut self) -> Result<Option<Datagram>, PcapError> {
        while let Some(frame) = self.next_frame()? {
            self.stats.records += 1;
            if frame.snapped {
                self.stats.truncated += 1;
                continue;
            }
            match parse_frame(frame.link_type, &frame.data) {
                Parsed::Udp { src, dst, payload } => {
                    self.stats.udp_datagrams += 1;
                    return Ok(Some(Datagram {
                        received_at: frame.at,
                        source: SocketAddr::V4(src),
                        destination: Some(SocketAddr::V4(dst)),
                        payload: payload.to_vec(),
                    }));
                }
                Parsed::Fragment => self.stats.fragments += 1,
                Parsed::Truncated => self.stats.truncated += 1,
                Parsed::Other => self.stats.not_ipv4_udp += 1,
            }
        }
        Ok(None)
    }
}

fn supported_link(link_type: u32) -> bool {
    [LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4].contains(&link_type)
}

fn parse_frame(link_type: u32, frame: &[u8]) -> Parsed<'_> {
    let ip = match link_type {
        LINKTYPE_ETHERNET => {
            if frame.len() < 14 {
                return Parsed::Truncated;
            }
            let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
            let mut off = 14;
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if frame.len() < off + 4 {
                    return Parsed::Truncated;
                }
                ethertype = u16::from_be_bytes([frame[off + 2], frame[off + 3]]);
                off += 4;
            }
            if ethertype != 0x0800 {
                return Parsed::Other;
            }
            &frame[off..]
        }
        LINKTYPE_LINUX_SLL => {
            if frame.len() < 16 {
                return Parsed::Truncated;
            }
            if u16::from_be_bytes([frame[14], frame[15]]) != 0x0800 {
                return Parsed::Other;
            }
            &frame[16..]
        }
        LINKTYPE_RAW | LINKTYPE_IPV4 => frame,
        _ => return Parsed::Other,
    };
    parse_ipv4_udp(ip)
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = Result<Datagram, PcapError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_datagram().transpose()
    }
}

enum Parsed<'a> {
    Udp {
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &'a [u8],
    },
    Fragment,
    Truncated,
    Other,
}

fn parse_ipv4_udp(ip: &[u8]) -> Parsed<'_> {
    if ip.len() < 20 {
        return Parsed::Truncated;
    }
    if ip[0] >> 4 != 4 {
        return Parsed::Other;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    if ihl < 20 || total < ihl || ip.len() < total {
        return Parsed::Truncated;
    }
    let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
    if flags_frag & 0x3fff != 0 {
        return Parsed::Fragment; // more-fragments set or non-zero offset
    }
    if ip[9] != 17 {
        return Parsed::Other;
    }
    let src_ip = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst_ip = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let udp = &ip[ihl..total];
    if udp.len() < 8 {
        return Parsed::Truncated;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < 8 || udp_len > udp.len() {
        return Parsed::Truncated;
    }
    Parsed::Udp {
        src: SocketAddrV4::new(src_ip, src_port),
        dst: SocketAddrV4::new(dst_ip, dst_port),
        payload: &udp[8..udp_len],
    }
}

/// Writes UDP datagrams as Ethernet/IPv4/UDP frames in a classic
/// (microsecond, little-endian) pcap file.
pub struct PcapWriter<W: Write> {
    out: W,
    ip_id: u16,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut out: W) -> io::Result<Self> {
        out.write_all(&MAGIC_MICROS.to_le_bytes())?;
        out.write_all(&2u16.to_le_bytes())?; // version major
        out.write_all(&4u16.to_le_bytes())?; // version minor
        out.write_all(&0i32.to_le_bytes())?; // thiszone
        out.write_all(&0u32.to_le_bytes())?; // sigfigs
        out.write_all(&65_535u32.to_le_bytes())?; // snaplen
        out.write_all(&LINKTYPE_ETHERNET.to_le_bytes())?;
        Ok(PcapWriter { out, ip_id: 0 })
    }

    pub fn write_udp(
        &mut self,
        at: SystemTime,
        src: SocketAddrV4,
        dst: SocketAddrV4,
        payload: &[u8],
    ) -> io::Result<()> {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut frame = Vec::with_capacity(14 + ip_len);

        // Ethernet: broadcast/multicast/unicast MAC chosen from the IP.
        let d = dst.ip().octets();
        let dst_mac = if dst.ip().is_broadcast() || d[3] == 255 {
            [0xff; 6]
        } else if dst.ip().is_multicast() {
            [0x01, 0x00, 0x5e, d[1] & 0x7f, d[2], d[3]]
        } else {
            [0x02, 0x00, d[0], d[1], d[2], d[3]]
        };
        let s = src.ip().octets();
        frame.extend_from_slice(&dst_mac);
        frame.extend_from_slice(&[0x02, 0x00, s[0], s[1], s[2], s[3]]);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4 header.
        let ip_start = frame.len();
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(ip_len as u16).to_be_bytes());
        frame.extend_from_slice(&self.ip_id.to_be_bytes());
        self.ip_id = self.ip_id.wrapping_add(1);
        frame.extend_from_slice(&[0x40, 0x00, 64, 17, 0, 0]); // DF, TTL 64, UDP, checksum
        frame.extend_from_slice(&s);
        frame.extend_from_slice(&d);
        let csum = ipv4_checksum(&frame[ip_start..ip_start + 20]);
        frame[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());

        // UDP header (checksum 0 = not computed, valid for IPv4).
        frame.extend_from_slice(&src.port().to_be_bytes());
        frame.extend_from_slice(&dst.port().to_be_bytes());
        frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(payload);

        let since = at.duration_since(UNIX_EPOCH).unwrap_or_default();
        self.out.write_all(&(since.as_secs() as u32).to_le_bytes())?;
        self.out.write_all(&since.subsec_micros().to_le_bytes())?;
        self.out.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.out.write_all(&(frame.len() as u32).to_le_bytes())?;
        self.out.write_all(&frame)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    pub fn into_inner(self) -> W {
        self.out
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        sum += u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrip() {
        let t0 = UNIX_EPOCH + Duration::from_micros(1_761_700_000_123_456);
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 40001);
        let bcast = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 255), 3000);
        let mcast = SocketAddrV4::new(Ipv4Addr::new(239, 1, 2, 3), 3000);
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        w.write_udp(t0, src, bcast, b"hello").unwrap();
        w.write_udp(t0 + Duration::from_millis(5), src, mcast, &[7u8; 300])
            .unwrap();
        let bytes = w.into_inner();

        let mut r = PcapReader::new(&bytes[..]).unwrap();
        let a = r.next_datagram().unwrap().unwrap();
        assert_eq!(a.payload, b"hello");
        assert_eq!(a.source, SocketAddr::V4(src));
        assert_eq!(a.destination, Some(SocketAddr::V4(bcast)));
        assert_eq!(a.received_at, t0);
        let b = r.next_datagram().unwrap().unwrap();
        assert_eq!(b.payload.len(), 300);
        assert_eq!(b.destination, Some(SocketAddr::V4(mcast)));
        assert!(r.next_datagram().unwrap().is_none());
        assert_eq!(r.stats.udp_datagrams, 2);
    }

    #[test]
    fn checksum_of_written_header_verifies() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        let a = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 1);
        w.write_udp(UNIX_EPOCH, a, a, b"x").unwrap();
        let bytes = w.into_inner();
        let ip = &bytes[24 + 16 + 14..24 + 16 + 14 + 20];
        assert_eq!(ipv4_checksum(ip), 0);
    }

    /// Wrap the frames of a classic pcap into a pcapng file.
    fn to_pcapng(classic: &[u8], big_endian: bool, nanos: bool, simple_first: bool) -> Vec<u8> {
        let w32 = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let w16 = |v: u16| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let block = |out: &mut Vec<u8>, t: u32, body: &[u8]| {
            let mut b = body.to_vec();
            while !b.len().is_multiple_of(4) {
                b.push(0);
            }
            let len = (b.len() + 12) as u32;
            out.extend(w32(t));
            out.extend(w32(len));
            out.extend(&b);
            out.extend(w32(len));
        };
        let mut out = Vec::new();
        let mut shb = Vec::new();
        shb.extend(w32(PCAPNG_BYTE_ORDER));
        shb.extend(w16(1));
        shb.extend(w16(0));
        shb.extend([0xff; 8]); // section length unknown
        block(&mut out, PCAPNG_SHB, &shb);

        let mut idb = Vec::new();
        idb.extend(w16(1)); // Ethernet
        idb.extend(w16(0));
        idb.extend(w32(65535));
        if nanos {
            idb.extend(w16(9));
            idb.extend(w16(1));
            idb.extend([9, 0, 0, 0]);
        }
        idb.extend(w16(0));
        idb.extend(w16(0));
        block(&mut out, PCAPNG_IDB, &idb);
        block(&mut out, 0x0000_0bad, &[1, 2, 3, 4]); // unknown block, skipped

        let mut off = 24;
        let mut first = true;
        while off < classic.len() {
            let r = |i: usize| u32::from_le_bytes([classic[i], classic[i + 1], classic[i + 2], classic[i + 3]]);
            let (secs, micros, incl) = (r(off) as u64, r(off + 4) as u64, r(off + 8) as usize);
            let frame = &classic[off + 16..off + 16 + incl];
            if first && simple_first {
                let mut spb = Vec::new();
                spb.extend(w32(incl as u32));
                spb.extend(frame);
                block(&mut out, PCAPNG_SIMPLE_PACKET, &spb);
            } else {
                let units = if nanos {
                    secs * 1_000_000_000 + micros * 1000
                } else {
                    secs * 1_000_000 + micros
                };
                let mut epb = Vec::new();
                epb.extend(w32(0));
                epb.extend(w32((units >> 32) as u32));
                epb.extend(w32(units as u32));
                epb.extend(w32(incl as u32));
                epb.extend(w32(incl as u32));
                epb.extend(frame);
                block(&mut out, PCAPNG_ENHANCED_PACKET, &epb);
            }
            first = false;
            off += 16 + incl;
        }
        out
    }

    #[test]
    fn reads_pcapng_in_both_byte_orders_and_resolutions() {
        let t0 = UNIX_EPOCH + Duration::from_micros(1_761_700_000_123_456);
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 40001);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 255), 3000);
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        for i in 0..5u8 {
            w.write_udp(
                t0 + Duration::from_millis(i as u64 * 10),
                src,
                dst,
                &vec![i; 50 + i as usize],
            )
            .unwrap();
        }
        let classic = w.into_inner();
        for big_endian in [false, true] {
            for nanos in [false, true] {
                let ng = to_pcapng(&classic, big_endian, nanos, false);
                let mut r = PcapReader::new(&ng[..]).unwrap();
                let got: Vec<Datagram> = (&mut r).map(|d| d.unwrap()).collect();
                assert_eq!(got.len(), 5, "be={big_endian} ns={nanos}");
                for (i, d) in got.iter().enumerate() {
                    assert_eq!(d.payload, vec![i as u8; 50 + i]);
                    assert_eq!(d.received_at, t0 + Duration::from_millis(i as u64 * 10));
                    assert_eq!(d.source, SocketAddr::V4(src));
                }
            }
        }
        // A simple packet block (no timestamp) is read too.
        let ng = to_pcapng(&classic, false, false, true);
        let got: Vec<Datagram> = PcapReader::new(&ng[..]).unwrap().map(|d| d.unwrap()).collect();
        assert_eq!(got.len(), 5);
        assert_eq!(got[0].payload, vec![0u8; 50]);
    }

    #[test]
    fn corrupt_pcapng_is_an_error_not_a_panic() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        let a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
        w.write_udp(UNIX_EPOCH, a, a, b"x").unwrap();
        let ng = to_pcapng(&w.into_inner(), false, false, false);
        // Every truncation and every single-byte corruption must be handled.
        for cut in 4..ng.len() {
            if let Ok(mut r) = PcapReader::new(&ng[..cut]) {
                while let Ok(Some(_)) = r.next_datagram() {}
            }
        }
        for i in 0..ng.len() {
            let mut bad = ng.clone();
            bad[i] ^= 0xff;
            if let Ok(mut r) = PcapReader::new(&bad[..]) {
                while let Ok(Some(_)) = r.next_datagram() {}
            }
        }
    }

    #[test]
    fn non_udp_and_fragments_are_counted_not_returned() {
        let mut w = PcapWriter::new(Vec::new()).unwrap();
        let a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
        w.write_udp(UNIX_EPOCH, a, a, b"one").unwrap();
        w.write_udp(UNIX_EPOCH, a, a, b"two").unwrap();
        w.write_udp(UNIX_EPOCH, a, a, b"three").unwrap();
        let mut bytes = w.into_inner();
        // Record 2: make it TCP. Record 3: mark it as a fragment.
        let rec2 = 24 + (16 + 14 + 28 + 3);
        bytes[rec2 + 16 + 14 + 9] = 6;
        let rec3 = rec2 + 16 + 14 + 28 + 3;
        bytes[rec3 + 16 + 14 + 6] = 0x20; // more fragments
        let mut r = PcapReader::new(&bytes[..]).unwrap();
        let got: Vec<_> = (&mut r).map(|d| d.unwrap().payload).collect();
        assert_eq!(got, vec![b"one".to_vec()]);
        assert_eq!(r.stats.not_ipv4_udp, 1);
        assert_eq!(r.stats.fragments, 1);
    }
}
