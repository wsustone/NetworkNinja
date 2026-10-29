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
    /// Not a classic pcap file (pcapng is not supported yet).
    BadMagic(u32),
    UnsupportedLinkType(u32),
}

impl std::fmt::Display for PcapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PcapError::Io(e) => write!(f, "{e}"),
            PcapError::BadMagic(m) if *m == 0x0a0d_0d0a => {
                write!(f, "this is a pcapng file; only classic pcap is supported so far (convert with editcap -F pcap)")
            }
            PcapError::BadMagic(m) => write!(f, "not a pcap file (magic {m:#010x})"),
            PcapError::UnsupportedLinkType(l) => write!(f, "unsupported pcap link type {l}"),
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

/// Reads UDP datagrams from a classic pcap file.
pub struct PcapReader<R: Read> {
    input: R,
    big_endian: bool,
    nanos: bool,
    link_type: u32,
    pub stats: PcapStats,
}

impl<R: Read> PcapReader<R> {
    pub fn new(mut input: R) -> Result<Self, PcapError> {
        let mut hdr = [0u8; 24];
        input.read_exact(&mut hdr)?;
        let magic_le = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let magic_be = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let (big_endian, nanos) = match (magic_le, magic_be) {
            (MAGIC_MICROS, _) => (false, false),
            (MAGIC_NANOS, _) => (false, true),
            (_, MAGIC_MICROS) => (true, false),
            (_, MAGIC_NANOS) => (true, true),
            _ => return Err(PcapError::BadMagic(magic_be)),
        };
        let rd = |b: &[u8]| {
            let a = [b[0], b[1], b[2], b[3]];
            if big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
        };
        let link_type = rd(&hdr[20..24]) & 0x0fff_ffff;
        if ![LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL, LINKTYPE_IPV4].contains(&link_type) {
            return Err(PcapError::UnsupportedLinkType(link_type));
        }
        Ok(PcapReader { input, big_endian, nanos, link_type, stats: PcapStats::default() })
    }

    fn rd32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }

    /// Next UDP datagram, skipping (and counting) anything else.
    pub fn next_datagram(&mut self) -> Result<Option<Datagram>, PcapError> {
        loop {
            let mut rec = [0u8; 16];
            match self.input.read_exact(&mut rec) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(e) => return Err(e.into()),
            }
            let secs = self.rd32(&rec[0..4]) as u64;
            let frac = self.rd32(&rec[4..8]) as u64;
            let incl = self.rd32(&rec[8..12]) as usize;
            let orig = self.rd32(&rec[12..16]) as usize;
            let mut frame = vec![0u8; incl];
            match self.input.read_exact(&mut frame) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    self.stats.truncated += 1;
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
            self.stats.records += 1;
            if incl < orig {
                self.stats.truncated += 1;
                continue;
            }
            let nanos = if self.nanos { frac } else { frac * 1000 };
            let ts = UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(nanos);
            match self.parse_frame(&frame) {
                Parsed::Udp { src, dst, payload } => {
                    self.stats.udp_datagrams += 1;
                    return Ok(Some(Datagram {
                        received_at: ts,
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
    }

    fn parse_frame<'a>(&self, frame: &'a [u8]) -> Parsed<'a> {
        let ip = match self.link_type {
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
            _ => frame, // raw IP
        };
        parse_ipv4_udp(ip)
    }
}

impl<R: Read> Iterator for PcapReader<R> {
    type Item = Result<Datagram, PcapError>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_datagram().transpose()
    }
}

enum Parsed<'a> {
    Udp { src: SocketAddrV4, dst: SocketAddrV4, payload: &'a [u8] },
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
        w.write_udp(t0 + Duration::from_millis(5), src, mcast, &[7u8; 300]).unwrap();
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

    #[test]
    fn rejects_pcapng_with_a_clear_error() {
        let ng = [0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let err = PcapReader::new(&ng[..]).err().unwrap();
        assert!(err.to_string().contains("pcapng"));
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
