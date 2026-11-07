//! Fuzzing the monitor: a bad packet must never crash it (spec, "decoders
//! are fuzz-tested against malformed and hostile input").
//!
//! A mutation fuzzer with no dependencies: it seeds from the generator's own
//! traffic (every PDU type, every fault preset, v6 and v7, every vendor
//! profile), bends it the ways a broken or hostile sender would (flipped
//! bits, extreme length and count fields, truncation, padding, splices,
//! random bytes) and feeds every mutant through a whole `Monitor` (decoder,
//! structure checks, every rule, the entity table, metrics, ticks), as live
//! traffic would. Mutated pcap files go through `PcapReader` too.
//!
//! The default run is short, for every `cargo test`. A long one:
//!
//! ```sh
//! NN_FUZZ_ITERS=2000000 NN_FUZZ_SEED=7 cargo test --release -p nn-rules --test fuzz -- --nocapture
//! ```
//!
//! A panic fails with the seed, the iteration and the input's bytes in hex.

use nn_capture::{Datagram, PcapReader, PcapWriter};
use nn_generator::presets::{schedule, Presets};
use nn_generator::{profile, run, Config, Sender, Sink};
use nn_rules::{Monitor, RuleConfig};
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, SystemTime};

struct Collect(SystemTime, Vec<Datagram>);

impl Sink for Collect {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        self.1.push(Datagram {
            received_at: self.0 + Duration::from_secs_f64(t),
            source: SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(10, 0, s.site as u8, s.host()),
                40_000 + s.generation,
            )),
            destination: None,
            payload: d.to_vec(),
            monotonic: None,
            listener: None,
        });
        Ok(())
    }
}

/// The seed corpus: one datagram per distinct (PDU type, length) the
/// generator produces across its presets, versions and profiles.
fn corpus() -> Vec<Datagram> {
    let mut runs = Vec::new();
    for (version, prof) in [(7, "standard"), (6, "legacy"), (7, "body-axis"), (7, "gateway")] {
        let mut cfg = Config {
            duration: 240.0,
            sites: 4,
            version,
            all_types: Some(10.0),
            ..Default::default()
        };
        profile(prof).expect("a vendor profile").apply(&mut cfg);
        schedule(&mut cfg, &Presets::all(), Vec::new(), Vec::new()).unwrap();
        let mut sink = Collect(cfg.start_time, Vec::new());
        run(&cfg, &mut sink).unwrap();
        runs.extend(sink.1);
    }
    let mut seen = std::collections::BTreeSet::new();
    runs.into_iter()
        .filter(|d| seen.insert((d.payload.get(2).copied(), d.payload.len())))
        .collect()
}

/// xorshift64*: deterministic, so a failure reproduces from its seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Values that break length and count arithmetic.
const EDGES: [u16; 8] = [0, 1, 2, 3, 4, 0x7fff, 0xfffe, 0xffff];

fn mutate(rng: &mut Rng, seed: &[u8], other: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..1 + rng.below(4) {
        let len = b.len().max(1);
        match rng.below(10) {
            // A flipped bit.
            0 => {
                let i = rng.below(len);
                if let Some(x) = b.get_mut(i) {
                    *x ^= 1 << rng.below(8);
                }
            }
            // A byte set to an extreme.
            1 => {
                let i = rng.below(len);
                if let Some(x) = b.get_mut(i) {
                    *x = [0, 1, 0x7f, 0x80, 0xff][rng.below(5)];
                }
            }
            // A 16-bit field (lengths, counts, IDs) set to an edge value,
            // often the PDU Length itself.
            2 | 3 => {
                let i = if rng.below(3) == 0 { 8 } else { rng.below(len) & !1 };
                let v = EDGES[rng.below(EDGES.len())].to_be_bytes();
                if i + 1 < b.len() {
                    b[i..i + 2].copy_from_slice(&v);
                }
            }
            // Truncated.
            4 => b.truncate(rng.below(len)),
            // Padded with junk.
            5 => {
                for _ in 0..rng.below(64) {
                    b.push(rng.next() as u8);
                }
            }
            // Spliced with another datagram (a second PDU, or garbage).
            6 => {
                let cut = rng.below(other.len().max(1));
                b.extend_from_slice(&other[cut.min(other.len())..]);
            }
            // The header of one type on another type's body.
            7 => {
                if let Some(x) = b.get_mut(2) {
                    *x = rng.below(80) as u8;
                }
            }
            // Random bytes over a stretch.
            8 => {
                let at = rng.below(len);
                for i in at..(at + rng.below(16)).min(b.len()) {
                    b[i] = rng.next() as u8;
                }
            }
            // Entirely random.
            _ => b = (0..rng.below(1500)).map(|_| rng.next() as u8).collect(),
        }
    }
    b
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn the_monitor_survives_malformed_traffic() {
    let iters: u64 = std::env::var("NN_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let seed: u64 = std::env::var("NN_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let corpus = corpus();
    assert!(corpus.len() > 100, "a corpus of every PDU type: {}", corpus.len());
    let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut m = Monitor::new(RuleConfig::default());
    let t0 = corpus[0].received_at;
    let started = std::time::Instant::now();
    for i in 0..iters {
        let a = &corpus[rng.below(corpus.len())];
        let b = &corpus[rng.below(corpus.len())];
        let payload = mutate(&mut rng, &a.payload, &b.payload);
        // Time moves on, mostly forward, so timers and timeouts run too.
        let d = Datagram {
            received_at: t0 + Duration::from_millis(i * 50),
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, rng.below(8) as u8, 10), 40_000)),
            payload,
            ..a.clone()
        };
        let now = nn_state::secs(d.received_at);
        let r = catch_unwind(AssertUnwindSafe(|| {
            m.ingest(&d);
            if i % 20 == 0 {
                m.tick(now);
            }
        }));
        if r.is_err() {
            panic!(
                "seed {seed}, iteration {i}: the monitor panicked on {}",
                hex(&d.payload)
            );
        }
        if std::env::var("NN_FUZZ_STATS").is_ok() && i % 100_000 == 0 {
            eprintln!(
                "{i}: {:?} since start, {} entities, {} scoped freezes, {} exercises, {} open alerts",
                started.elapsed(),
                m.table.entities.len(),
                m.table.scoped.len(),
                m.table.exercises.len(),
                m.engine.active().count()
            );
        }
    }
}

#[test]
fn the_pcap_reader_survives_malformed_files() {
    let iters: u64 = std::env::var("NN_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(2_000, |n| n / 10);
    let seed: u64 = std::env::var("NN_FUZZ_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let corpus = corpus();
    let mut file = Vec::new();
    {
        let mut w = PcapWriter::new(&mut file).unwrap();
        for d in corpus.iter().take(40) {
            let dst = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 255), 3000);
            let SocketAddr::V4(src) = d.source else { unreachable!() };
            w.write_udp(d.received_at, src, dst, &d.payload).unwrap();
        }
        w.flush().unwrap();
    }
    let mut rng = Rng(seed.wrapping_mul(0xD1B5_4A32_D192_ED03) | 1);
    for i in 0..iters {
        let other = &corpus[rng.below(corpus.len())].payload;
        let bytes = mutate(&mut rng, &file, other);
        let r = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut reader) = PcapReader::new(Cursor::new(&bytes)) {
                // Bounded: a mutant can't make the test loop forever.
                for _ in 0..1000 {
                    match reader.next_datagram() {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        }));
        if r.is_err() {
            panic!(
                "seed {seed}, iteration {i}: the pcap reader panicked on a {}-byte file starting {}",
                bytes.len(),
                hex(&bytes[..bytes.len().min(96)])
            );
        }
    }
}
