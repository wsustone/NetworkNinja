//! Several UDP listeners at once (ports, multicast groups, interfaces),
//! each read on its own thread into one stream for the monitor, with
//! per-listener counters for the dashboard's inputs status.

use crate::udp::{UdpConfig, UdpSource};
use crate::Datagram;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Datagrams waiting for the monitor before the readers block (and the
/// kernel buffer starts to fill instead).
const QUEUE: usize = 65_536;

/// One listener's configuration and live counters.
#[derive(Debug)]
pub struct ListenerStats {
    pub name: String,
    pub local: SocketAddr,
    pub groups: Vec<Ipv4Addr>,
    pub interface: Ipv4Addr,
    pub share: bool,
    /// Receive buffer asked for and granted, bytes.
    pub recv_buffer_asked: usize,
    pub recv_buffer: usize,
    pub datagrams: AtomicU64,
    pub bytes: AtomicU64,
    /// Steady-clock time of the last datagram (`f64` bits); 0 = none yet.
    last_at: AtomicU64,
    pub errors: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

impl ListenerStats {
    pub fn last_at(&self) -> Option<f64> {
        let v = f64::from_bits(self.last_at.load(Ordering::Relaxed));
        (v > 0.0).then_some(v)
    }
}

/// Running listeners. Dropping it stops the reader threads.
pub struct Listeners {
    rx: Receiver<Datagram>,
    pub stats: Vec<Arc<ListenerStats>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Listeners {
    /// Open every listener; fails (opening none) if any can't be opened,
    /// naming it.
    pub fn open(cfgs: &[UdpConfig]) -> Result<Listeners, String> {
        if cfgs.is_empty() {
            return Err("no listeners configured".into());
        }
        let mut sources = Vec::new();
        for c in cfgs {
            let s = UdpSource::open(c).map_err(|e| {
                let hint = if e.kind() == std::io::ErrorKind::AddrInUse && !c.share {
                    " (another program holds the port: if it's a simulator on this host and the \
                     traffic is broadcast or multicast, set share = true)"
                } else {
                    ""
                };
                format!("cannot open listener '{}' on {}:{}: {e}{hint}", c.name, c.bind, c.port)
            })?;
            sources.push((c.clone(), s));
        }
        let (tx, rx) = sync_channel(QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let mut stats = Vec::new();
        let mut threads = Vec::new();
        for (c, mut src) in sources {
            let st = Arc::new(ListenerStats {
                name: c.name.clone(),
                local: src.local_addr(),
                groups: c.multicast_groups.clone(),
                interface: c.multicast_interface,
                share: c.share,
                recv_buffer_asked: c.recv_buffer,
                recv_buffer: src.recv_buffer,
                datagrams: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                last_at: AtomicU64::new(0),
                errors: AtomicU64::new(0),
                last_error: Mutex::new(None),
            });
            let (tx, stop, s) = (tx.clone(), Arc::clone(&stop), Arc::clone(&st));
            threads.push(std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match src.recv() {
                        Ok(Some(d)) => {
                            s.datagrams.fetch_add(1, Ordering::Relaxed);
                            s.bytes.fetch_add(d.payload.len() as u64, Ordering::Relaxed);
                            s.last_at.store(d.monotonic.unwrap_or(0.0).to_bits(), Ordering::Relaxed);
                            if tx.send(d).is_err() {
                                break;
                            }
                        }
                        Ok(None) => {}
                        Err(e) => {
                            s.errors.fetch_add(1, Ordering::Relaxed);
                            *s.last_error.lock().unwrap() = Some(e.to_string());
                            std::thread::sleep(Duration::from_millis(100));
                        }
                    }
                }
            }));
            stats.push(st);
        }
        Ok(Listeners {
            rx,
            stats,
            stop,
            threads,
        })
    }

    /// The next datagram from any listener, waiting up to `timeout`.
    pub fn recv(&self, timeout: Duration) -> Option<Datagram> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl Drop for Listeners {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Readers notice within their read timeout; a full queue unblocks
        // when `rx` drops after this.
        while self.rx.try_recv().is_ok() {}
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    fn on(name: &str) -> UdpConfig {
        UdpConfig {
            name: name.into(),
            bind: Ipv4Addr::LOCALHOST,
            port: 0,
            read_timeout: Duration::from_millis(50),
            ..Default::default()
        }
    }

    #[test]
    fn two_ports_feed_one_stream_with_their_own_counters() {
        let l = Listeners::open(&[on("a"), on("b")]).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"one", l.stats[0].local).unwrap();
        tx.send_to(b"two", l.stats[1].local).unwrap();
        tx.send_to(b"three", l.stats[1].local).unwrap();
        let mut got = Vec::new();
        while got.len() < 3 {
            got.push(l.recv(Duration::from_secs(2)).expect("datagram").payload);
        }
        got.sort();
        assert_eq!(got, [b"one".to_vec(), b"three".to_vec(), b"two".to_vec()]);
        assert_eq!(l.stats[0].datagrams.load(Ordering::Relaxed), 1);
        assert_eq!(l.stats[1].datagrams.load(Ordering::Relaxed), 2);
        assert!(l.stats[1].last_at().is_some());
    }

    #[test]
    fn a_held_port_names_the_listener_and_suggests_sharing() {
        let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let cfg = UdpConfig {
            port: holder.local_addr().unwrap().port(),
            ..on("dis")
        };
        let e = Listeners::open(&[cfg]).err().unwrap();
        assert!(e.contains("'dis'") && e.contains("share = true"), "{e}");
    }

    #[test]
    fn two_sharing_listeners_can_bind_one_port() {
        // What `share` is for: a second socket on a port another one holds.
        // (Which of them gets a unicast datagram is the OS's choice; that's
        // why sharing is for broadcast and multicast ports.)
        let a = Listeners::open(&[UdpConfig { share: true, ..on("a") }]).unwrap();
        let port = a.stats[0].local.port();
        let b = Listeners::open(&[UdpConfig {
            share: true,
            port,
            ..on("b")
        }]);
        assert!(b.is_ok(), "{:?}", b.err());
    }
}

#[cfg(test)]
mod multicast {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};

    /// Joins a group on loopback and receives a datagram sent to it from
    /// loopback only (nothing leaves the host). Ignored by default: some CI
    /// sandboxes have no multicast on loopback. `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn joins_a_group_on_an_interface_and_receives_it() {
        let group = Ipv4Addr::new(239, 255, 77, 77);
        let cfg = UdpConfig {
            name: "mc".into(),
            port: 0,
            multicast_groups: vec![group],
            multicast_interface: Ipv4Addr::LOCALHOST,
            read_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let l = Listeners::open(&[cfg]).unwrap();
        let port = l.stats[0].local.port();
        let tx = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        tx.set_multicast_if_v4(&Ipv4Addr::LOCALHOST).unwrap();
        tx.set_multicast_loop_v4(true).unwrap();
        tx.set_multicast_ttl_v4(0).unwrap();
        let tx: std::net::UdpSocket = tx.into();
        tx.send_to(b"mc", (group, port)).unwrap();
        let d = l.recv(Duration::from_secs(2)).expect("the multicast datagram");
        assert_eq!(d.payload, b"mc");
    }
}
