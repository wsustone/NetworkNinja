//! Native recording format (milestone 5).
//!
//! Append-only binary: an 8-byte magic, then records of
//! `u64 micros` | `u16 source_len` + source UTF-8 | `u32 payload_len` + payload.
//! A `serve --record` run captures every datagram it receives; `serve
//! --replay` feeds the recording back through the same monitor, rules and
//! dashboard so a past run replays exactly — alerts included.

use nn_capture::Datagram;
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAGIC: &[u8] = b"NNREC\x00\x01";
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;

pub struct Writer {
    w: BufWriter<File>,
    pub records: u64,
}

impl Writer {
    pub fn create(path: &Path) -> io::Result<Writer> {
        let mut w = BufWriter::new(File::create(path)?);
        w.write_all(MAGIC)?;
        Ok(Writer { w, records: 0 })
    }

    pub fn record(&mut self, d: &Datagram) -> io::Result<()> {
        let micros = d.received_at.duration_since(UNIX_EPOCH).unwrap_or_default().as_micros() as u64;
        self.w.write_all(&micros.to_be_bytes())?;
        let src = d.source.to_string();
        self.w.write_all(&(src.len() as u16).to_be_bytes())?;
        self.w.write_all(src.as_bytes())?;
        self.w.write_all(&(d.payload.len() as u32).to_be_bytes())?;
        self.w.write_all(&d.payload)?;
        self.records += 1;
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
}

pub struct Reader {
    r: BufReader<File>,
    /// Timestamp of the first record — replay paces everything off this.
    pub first_at: Option<SystemTime>,
}

impl Reader {
    pub fn open(path: &Path) -> io::Result<Reader> {
        let mut r = BufReader::new(File::open(path)?);
        let mut magic = vec![0u8; MAGIC.len()];
        r.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "not an nn recording"));
        }
        Ok(Reader { r, first_at: None })
    }

    pub fn next_datagram(&mut self) -> io::Result<Option<Datagram>> {
        let mut b = [0u8; 8];
        match self.r.read_exact(&mut b) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let micros = u64::from_be_bytes(b);
        let mut l = [0u8; 2];
        self.r.read_exact(&mut l)?;
        let mut sbuf = vec![0u8; u16::from_be_bytes(l) as usize];
        self.r.read_exact(&mut sbuf)?;
        let source: SocketAddr = String::from_utf8_lossy(&sbuf)
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad source addr"))?;
        let mut pl = [0u8; 4];
        self.r.read_exact(&mut pl)?;
        let plen = u32::from_be_bytes(pl) as usize;
        if plen > MAX_PAYLOAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "record too large"));
        }
        let mut payload = vec![0u8; plen];
        self.r.read_exact(&mut payload)?;
        let at = UNIX_EPOCH + Duration::from_micros(micros);
        self.first_at.get_or_insert(at);
        Ok(Some(Datagram {
            received_at: at,
            source,
            destination: None,
            payload,
        }))
    }
}
