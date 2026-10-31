//! Several UDP listeners at once (ports, multicast groups, interfaces),
//! each read on its own thread into one stream for the monitor, with
//! per-listener counters for the dashboard's inputs status. Listeners can
//! be added, replaced and removed while running.

use crate::udp::{UdpConfig, UdpSource};
use crate::Datagram;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Datagrams waiting for the monitor before the readers block (and the
/// kernel buffer starts to fill instead).
const QUEUE: usize = 65_536;

/// One listener's configuration and live counters.
#[derive(Debug)]
pub struct ListenerStats {
    /// The configuration it was opened with.
    pub config: UdpConfig,
    pub local: SocketAddr,
    /// Receive buffer the kernel granted, bytes.
    pub recv_buffer: usize,
    pub datagrams: AtomicU64,
    pub bytes: AtomicU64,
    /// Steady-clock time of the last datagram (`f64` bits); 0 = none yet.
    last_at: AtomicU64,
    pub errors: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

impl ListenerStats {
    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn last_at(&self) -> Option<f64> {
        let v = f64::from_bits(self.last_at.load(Ordering::Relaxed));
        (v > 0.0).then_some(v)
    }
}

struct Reader {
    stats: Arc<ListenerStats>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Reader {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            // Exits within its read timeout.
            let _ = t.join();
        }
    }
}

/// Running listeners. Dropping it stops the reader threads.
pub struct Listeners {
    rx: Receiver<Datagram>,
    tx: SyncSender<Datagram>,
    readers: Vec<Reader>,
}

fn open_one(c: &UdpConfig) -> Result<UdpSource, String> {
    UdpSource::open(c).map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::AddrInUse && !c.share {
            " (another program holds the port: if it's a simulator on this host and the \
             traffic is broadcast or multicast, set share = true)"
        } else {
            ""
        };
        format!("cannot open listener '{}' on {}:{}: {e}{hint}", c.name, c.bind, c.port)
    })
}

impl Listeners {
    /// No listeners yet; add them with [`Listeners::add`].
    pub fn empty() -> Listeners {
        let (tx, rx) = sync_channel(QUEUE);
        Listeners {
            rx,
            tx,
            readers: Vec::new(),
        }
    }

    /// Open every listener; fails (opening none) if any can't be opened,
    /// naming it.
    pub fn open(cfgs: &[UdpConfig]) -> Result<Listeners, String> {
        if cfgs.is_empty() {
            return Err("no listeners configured".into());
        }
        let mut l = Listeners::empty();
        for c in cfgs {
            l.add(c.clone())?;
        }
        Ok(l)
    }

    /// Start a listener. Its name must be new.
    pub fn add(&mut self, cfg: UdpConfig) -> Result<(), String> {
        if self.readers.iter().any(|r| r.stats.name() == cfg.name) {
            return Err(format!("a listener named '{}' already exists", cfg.name));
        }
        let mut src = open_one(&cfg)?;
        let name: Arc<str> = Arc::from(cfg.name.as_str());
        let stats = Arc::new(ListenerStats {
            local: src.local_addr(),
            recv_buffer: src.recv_buffer,
            config: cfg,
            datagrams: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            last_at: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            last_error: Mutex::new(None),
        });
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, flag, s) = (self.tx.clone(), Arc::clone(&stop), Arc::clone(&stats));
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match src.recv() {
                    Ok(Some(mut d)) => {
                        s.datagrams.fetch_add(1, Ordering::Relaxed);
                        s.bytes.fetch_add(d.payload.len() as u64, Ordering::Relaxed);
                        s.last_at.store(d.monotonic.unwrap_or(0.0).to_bits(), Ordering::Relaxed);
                        d.listener = Some(Arc::clone(&name));
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
        });
        self.readers.push(Reader {
            stats,
            stop,
            thread: Some(thread),
        });
        Ok(())
    }

    /// Stop and close a listener. False if there is none by that name.
    pub fn remove(&mut self, name: &str) -> bool {
        let Some(i) = self.readers.iter().position(|r| r.stats.name() == name) else {
            return false;
        };
        self.readers.remove(i).stop();
        true
    }

    /// Replace listener `name` with `cfg` (which may rename it). The old one
    /// closes first, so the new one can take its port; if the new one can't
    /// open, the old one is reopened and the error returned.
    pub fn replace(&mut self, name: &str, cfg: UdpConfig) -> Result<(), String> {
        let Some(i) = self.readers.iter().position(|r| r.stats.name() == name) else {
            return Err(format!("no listener named '{name}'"));
        };
        if cfg.name != name && self.readers.iter().any(|r| r.stats.name() == cfg.name) {
            return Err(format!("a listener named '{}' already exists", cfg.name));
        }
        let old = self.readers.remove(i);
        let old_cfg = old.stats.config.clone();
        old.stop();
        if let Err(e) = self.add(cfg) {
            self.add(old_cfg)
                .map_err(|e2| format!("{e}; and the old listener couldn't reopen: {e2}"))?;
            return Err(e);
        }
        Ok(())
    }

    /// Every listener's configuration and counters, in the order added.
    pub fn stats(&self) -> Vec<Arc<ListenerStats>> {
        self.readers.iter().map(|r| Arc::clone(&r.stats)).collect()
    }

    pub fn configs(&self) -> Vec<UdpConfig> {
        self.readers.iter().map(|r| r.stats.config.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.readers.is_empty()
    }

    /// The next datagram from any listener, waiting up to `timeout`.
    pub fn recv(&self, timeout: Duration) -> Option<Datagram> {
        self.rx.recv_timeout(timeout).ok()
    }
}

impl Drop for Listeners {
    fn drop(&mut self) {
        for r in &self.readers {
            r.stop.store(true, Ordering::Relaxed);
        }
        // Unblock any reader stuck on a full queue, then wait for them.
        while self.rx.try_recv().is_ok() {}
        for r in self.readers.drain(..) {
            r.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, UdpSocket};

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
    fn two_ports_feed_one_stream_tagged_with_their_listener() {
        let l = Listeners::open(&[on("a"), on("b")]).unwrap();
        let st = l.stats();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(b"one", st[0].local).unwrap();
        tx.send_to(b"two", st[1].local).unwrap();
        tx.send_to(b"three", st[1].local).unwrap();
        let mut got = Vec::new();
        while got.len() < 3 {
            let d = l.recv(Duration::from_secs(2)).expect("datagram");
            got.push((d.listener.unwrap().to_string(), d.payload));
        }
        got.sort();
        assert_eq!(
            got,
            [
                ("a".to_string(), b"one".to_vec()),
                ("b".to_string(), b"three".to_vec()),
                ("b".to_string(), b"two".to_vec())
            ]
        );
        assert_eq!(st[0].datagrams.load(Ordering::Relaxed), 1);
        assert_eq!(st[1].datagrams.load(Ordering::Relaxed), 2);
        assert!(st[1].last_at().is_some());
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
        let port = a.stats()[0].local.port();
        let b = Listeners::open(&[UdpConfig {
            share: true,
            port,
            ..on("b")
        }]);
        assert!(b.is_ok(), "{:?}", b.err());
    }

    #[test]
    fn listeners_are_added_replaced_and_removed_while_running() {
        let mut l = Listeners::open(&[on("a")]).unwrap();
        assert!(l.add(on("a")).unwrap_err().contains("already exists"));
        l.add(on("b")).unwrap();
        // Replace b with a listener on a fixed port, then send to it.
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        l.replace("b", UdpConfig { port, ..on("b2") }).unwrap();
        assert_eq!(
            l.configs().iter().map(|c| c.name.as_str()).collect::<Vec<_>>(),
            ["a", "b2"]
        );
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"x", ("127.0.0.1", port))
            .unwrap();
        let d = l.recv(Duration::from_secs(2)).expect("datagram on the new port");
        assert_eq!(d.listener.as_deref(), Some("b2"));
        // A replacement that can't open leaves the old one running.
        let holder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let held = holder.local_addr().unwrap().port();
        assert!(l.replace("a", UdpConfig { port: held, ..on("a") }).is_err());
        assert!(l.configs().iter().any(|c| c.name == "a"));
        assert!(l.remove("a") && !l.remove("a"));
        assert_eq!(l.configs().len(), 1);
    }
}

#[cfg(test)]
mod multicast {
    use super::*;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::Ipv4Addr;

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
            multicast_interfaces: vec![Ipv4Addr::LOCALHOST],
            read_timeout: Duration::from_millis(50),
            ..Default::default()
        };
        let l = Listeners::open(&[cfg]).unwrap();
        let port = l.stats()[0].local.port();
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
