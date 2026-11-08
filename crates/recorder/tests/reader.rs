//! The recording reader on good and damaged files: it reports the right
//! length and count for a good one, and never panics on a damaged one.

use nn_capture::Datagram;
use nn_recorder::{Reader, Writer};
use std::net::SocketAddr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::{Duration, UNIX_EPOCH};

fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("nn-rec-{}-{name}.nnrec", std::process::id()))
}

/// A recording of `n` datagrams, one per second, from a dotted source.
fn recording(n: u64) -> Vec<u8> {
    let path = temp(&format!("good-{n}"));
    let mut w = Writer::create(&path).unwrap();
    for i in 0..n {
        w.record(&Datagram {
            received_at: UNIX_EPOCH + Duration::from_secs(1_790_000_000 + i),
            source: "10.0.1.10:40000".parse::<SocketAddr>().unwrap(),
            destination: None,
            payload: vec![7, 1, 1, 1, 0, 0, 0, 0, 0, 12, 0, 0],
            monotonic: None,
            listener: None,
        })
        .unwrap();
    }
    w.flush().unwrap();
    drop(w);
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    bytes
}

#[test]
fn a_good_recording_reports_its_length_and_count() {
    let path = temp("count");
    std::fs::write(&path, recording(11)).unwrap();
    let mut r = Reader::open(&path).unwrap();
    assert_eq!(r.records, 11);
    assert!((r.duration - 10.0).abs() < 1e-6, "{}", r.duration);
    let mut n = 0;
    while r.next_datagram().unwrap().is_some() {
        n += 1;
    }
    assert_eq!(n, 11);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn damaged_recordings_never_panic() {
    let good = recording(30);
    let path = temp("fuzz");
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rnd = || {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    for i in 0..3000 {
        let mut b = good.clone();
        for _ in 0..1 + rnd() % 4 {
            let at = (rnd() as usize) % b.len();
            match rnd() % 4 {
                0 => b[at] ^= 1 << (rnd() % 8),
                1 => b[at] = [0, 0xff, 0x7f, 0x80][(rnd() % 4) as usize],
                2 => b.truncate(at.max(7)),
                _ => {
                    // A time field set to an extreme (records are 41
                    // bytes: time 8, address length 2 + "10.0.1.10:40000"
                    // 15, payload length 4 + 12).
                    let rec = 7 + 41 * ((rnd() as usize) % 30);
                    if rec + 8 <= b.len() {
                        b[rec..rec + 8].copy_from_slice(&[u64::MAX, 0, 1 << 63][(rnd() % 3) as usize].to_be_bytes());
                    }
                }
            }
        }
        std::fs::write(&path, &b).unwrap();
        let r = catch_unwind(AssertUnwindSafe(|| {
            if let Ok(mut r) = Reader::open(&path) {
                for _ in 0..100 {
                    match r.next_datagram() {
                        Ok(Some(_)) => {}
                        _ => break,
                    }
                }
            }
        }));
        assert!(r.is_ok(), "iteration {i}: the reader panicked on a damaged recording");
    }
    let _ = std::fs::remove_file(&path);
}
