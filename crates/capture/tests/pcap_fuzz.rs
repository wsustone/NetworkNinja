//! Robustness: mutated classic pcap files must never panic the reader.
//!
//! A deterministic stand-in for a cargo-fuzz run, like the decoder's
//! `hostile_input_never_panics`. The pcapng reader has its own exhaustive
//! truncation and byte-flip test in `src/pcap.rs`.

use nn_capture::{PcapReader, PcapWriter};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn mutated_classic_pcap_never_panics() {
    let a = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 5000);
    let mut w = PcapWriter::new(Vec::new()).unwrap();
    for i in 0..4u8 {
        let at = UNIX_EPOCH + Duration::from_secs(1_700_000_000 + i as u64);
        w.write_udp(at, a, a, &[i; 60]).unwrap();
    }
    let valid = w.into_inner();

    let mut seed: u64 = 0x1234_5678_9abc_def1;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut datagrams = 0u64;
    for _ in 0..200_000 {
        let mut buf = valid.clone();
        for _ in 0..(1 + next() % 8) {
            let idx = (next() as usize) % buf.len();
            buf[idx] = next() as u8;
        }
        let cut = (next() as usize) % (buf.len() + 1);
        buf.truncate(cut.max(4));
        if let Ok(reader) = PcapReader::new(&buf[..]) {
            for d in reader {
                if d.is_err() {
                    break;
                }
                datagrams += 1;
            }
        }
    }
    // Most mutations leave some records readable; make sure the loop did real work.
    assert!(datagrams > 10_000, "only {datagrams} datagrams read");
}
