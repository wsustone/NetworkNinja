//! Milestone 1 exit checks: everything the generator emits decodes, by pcap
//! and over a live UDP socket, and the totals match the generator's truth.

use nn_capture::{PcapReader, PcapWriter, UdpConfig, UdpSource};
use nn_decode::EntityId;
use nn_generator::{run, Config, Event, EventKind, Sender, Sink, Target, Truth};
use nn_server::Tally;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

fn scenario(version: u8, bundle: bool) -> Config {
    let id = |s, e| Target::Entity(EntityId::new(s, 1, e));
    Config {
        version,
        bundle,
        duration: 60.0,
        sites: 3,
        entities_per_site: 25,
        fire_every: Some(4.0),
        events: vec![
            Event {
                kind: EventKind::DropHeartbeat,
                target: id(1, 1),
                at: 10.0,
            },
            Event {
                kind: EventKind::CloneId,
                target: id(1, 2),
                at: 15.0,
            },
            Event {
                kind: EventKind::Teleport,
                target: id(1, 3),
                at: 20.0,
            },
            Event {
                kind: EventKind::Remove,
                target: id(2, 1),
                at: 10.0,
            },
            Event {
                kind: EventKind::RestartPort,
                target: Target::Site(2),
                at: 25.0,
            },
            Event {
                kind: EventKind::Freeze,
                target: Target::Exercise,
                at: 30.0,
            },
            Event {
                kind: EventKind::Resume,
                target: Target::Exercise,
                at: 40.0,
            },
        ],
        ..Default::default()
    }
}

fn assert_matches_truth(tally: &Tally, truth: &Truth) {
    assert_eq!(tally.errors(), 0, "decode errors: {:?}", tally.errors_by_kind);
    assert_eq!(tally.datagrams, truth.datagrams);
    assert_eq!(tally.bytes, truth.bytes);
    assert_eq!(tally.pdus_by_type, truth.pdus_by_type);
    let expected: std::collections::BTreeSet<_> = truth.entities.iter().copied().collect();
    assert_eq!(tally.entities, expected);
}

struct PcapSink(PcapWriter<Vec<u8>>, std::time::SystemTime);
impl Sink for PcapSink {
    fn emit(&mut self, t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 0, s.site as u8, s.host()), 40_000 + s.generation);
        let dst = SocketAddrV4::new(Ipv4Addr::new(10, 255, 255, 255), 3000);
        self.0.write_udp(self.1 + Duration::from_secs_f64(t), src, dst, d)
    }
}

#[test]
fn pcap_path_decodes_everything_v6_and_v7() {
    for version in [6, 7] {
        for bundle in [false, true] {
            let cfg = scenario(version, bundle);
            let mut sink = PcapSink(PcapWriter::new(Vec::new()).unwrap(), cfg.start_time);
            let truth = run(&cfg, &mut sink).unwrap();
            let bytes = sink.0.into_inner();

            let mut tally = Tally::default();
            let mut reader = PcapReader::new(&bytes[..]).unwrap();
            while let Some(d) = reader.next_datagram().unwrap() {
                tally.ingest(&d);
            }
            assert_matches_truth(&tally, &truth);
            assert_eq!(tally.by_version.keys().copied().collect::<Vec<_>>(), vec![version]);
            // 3 sites + site 2 restarted + the rogue clone = 5 distinct sources.
            assert_eq!(tally.senders.len(), 5, "v{version} bundle={bundle}");
        }
    }
}

/// Sends immediately (no real-time pacing) from one socket per sender.
struct FastUdpSink {
    target: std::net::SocketAddr,
    sockets: std::collections::HashMap<Sender, UdpSocket>,
}
impl Sink for FastUdpSink {
    fn emit(&mut self, _t: f64, s: Sender, d: &[u8]) -> io::Result<()> {
        let sock = self
            .sockets
            .entry(s)
            .or_insert_with(|| UdpSocket::bind("127.0.0.1:0").unwrap());
        sock.send_to(d, self.target)?;
        // Pace lightly so the loopback receive buffer never overflows.
        std::thread::sleep(Duration::from_micros(50));
        Ok(())
    }
}

#[test]
fn live_udp_path_decodes_everything() {
    let mut source = UdpSource::open(&UdpConfig {
        bind: Ipv4Addr::LOCALHOST,
        port: 0,
        ..Default::default()
    })
    .unwrap();
    let target = source.local_addr();
    let cfg = Config {
        duration: 30.0,
        ..scenario(7, false)
    };

    let sender = std::thread::spawn(move || {
        let mut sink = FastUdpSink {
            target,
            sockets: Default::default(),
        };
        run(&cfg, &mut sink).unwrap()
    });

    let mut tally = Tally::default();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut truth = None;
    while Instant::now() < deadline {
        if let Some(d) = source.recv().unwrap() {
            tally.ingest(&d);
        } else if sender.is_finished() {
            truth = Some(sender.join().unwrap());
            // Drain anything still queued.
            while let Some(d) = source.recv().unwrap() {
                tally.ingest(&d);
            }
            break;
        }
    }
    let truth = truth.expect("generator finished");
    assert_matches_truth(&tally, &truth);
}
