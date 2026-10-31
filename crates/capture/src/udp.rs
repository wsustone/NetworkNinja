//! Receive-only UDP socket source.

use crate::Datagram;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, SystemTime};

/// Largest UDP payload we accept.
const MAX_DATAGRAM: usize = 65_535;

/// Receive buffer asked of the kernel unless configured: room for about a
/// second of a busy exercise, so a pause in the reader doesn't drop traffic.
pub const DEFAULT_RECV_BUFFER: usize = 8 << 20;

/// How to open the socket.
#[derive(Debug, Clone, PartialEq)]
pub struct UdpConfig {
    /// A label for status and logs, e.g. "dis" or "radio".
    pub name: String,
    /// Local address to bind. Use 0.0.0.0 to receive broadcast and multicast.
    pub bind: Ipv4Addr,
    pub port: u16,
    /// IPv4 multicast groups to join.
    pub multicast_groups: Vec<Ipv4Addr>,
    /// Interfaces (by IPv4 address) to join every group on; empty lets the
    /// OS choose one, which is often the wrong NIC on a multi-homed host.
    /// Joining a group on several interfaces still gives one copy of each
    /// datagram: it arrives on one of them.
    pub multicast_interfaces: Vec<Ipv4Addr>,
    /// The interfaces as configured ("en0" or an address), parallel to
    /// `multicast_interfaces`, for display and for saving the config back.
    pub interface_names: Vec<String>,
    /// How long `recv` blocks before returning `Ok(None)`.
    pub read_timeout: Duration,
    /// Share the port with other sockets on this host (SO_REUSEADDR, and
    /// SO_REUSEPORT on Unix), e.g. a simulator already bound to it. Safe for
    /// broadcast and multicast, which every sharing socket receives; unicast
    /// datagrams go to only one of them, so sharing a port that carries
    /// unicast can take traffic away from the simulator.
    pub share: bool,
    /// Kernel receive buffer to ask for, bytes. The kernel may grant less
    /// (Linux `net.core.rmem_max`, macOS `kern.ipc.maxsockbuf`).
    pub recv_buffer: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        UdpConfig {
            name: "udp".into(),
            bind: Ipv4Addr::UNSPECIFIED,
            port: 3000,
            multicast_groups: Vec::new(),
            multicast_interfaces: Vec::new(),
            interface_names: Vec::new(),
            read_timeout: Duration::from_millis(250),
            share: false,
            recv_buffer: DEFAULT_RECV_BUFFER,
        }
    }
}

/// A passive UDP listener. It never sends: the socket is only read from.
pub struct UdpSource {
    socket: UdpSocket,
    local: SocketAddr,
    /// Receive buffer the kernel granted, bytes (Linux reports double what
    /// it reserves for data).
    pub recv_buffer: usize,
    buf: Vec<u8>,
    pub datagrams: u64,
    pub bytes: u64,
}

impl UdpSource {
    pub fn open(cfg: &UdpConfig) -> io::Result<Self> {
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        if cfg.share {
            sock.set_reuse_address(true)?;
            #[cfg(unix)]
            sock.set_reuse_port(true)?;
        }
        // Best effort: the kernel caps it, and we report what we got.
        let _ = sock.set_recv_buffer_size(cfg.recv_buffer);
        sock.bind(&SocketAddrV4::new(cfg.bind, cfg.port).into())?;
        let recv_buffer = sock.recv_buffer_size().unwrap_or(0);
        let socket: UdpSocket = sock.into();
        for group in &cfg.multicast_groups {
            if !group.is_multicast() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{group} is not a multicast address"),
                ));
            }
            if cfg.multicast_interfaces.is_empty() {
                socket.join_multicast_v4(group, &Ipv4Addr::UNSPECIFIED)?;
            }
            for iface in &cfg.multicast_interfaces {
                socket
                    .join_multicast_v4(group, iface)
                    .map_err(|e| io::Error::new(e.kind(), format!("joining {group} on {iface}: {e}")))?;
            }
        }
        socket.set_read_timeout(Some(cfg.read_timeout))?;
        let local = socket.local_addr()?;
        Ok(UdpSource {
            socket,
            local,
            recv_buffer,
            buf: vec![0u8; MAX_DATAGRAM],
            datagrams: 0,
            bytes: 0,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Wait for the next datagram; `Ok(None)` when the read timeout passes.
    pub fn recv(&mut self) -> io::Result<Option<Datagram>> {
        match self.socket.recv_from(&mut self.buf) {
            Ok((n, source)) => {
                self.datagrams += 1;
                self.bytes += n as u64;
                Ok(Some(Datagram {
                    received_at: SystemTime::now(),
                    source,
                    destination: Some(self.local),
                    payload: self.buf[..n].to_vec(),
                    monotonic: Some(crate::steady_now()),
                    listener: None,
                }))
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// A socket for *sending* DIS (the generator's): broadcast allowed when
/// asked, and for multicast the outgoing interface (`None` = the OS's
/// choice, often the wrong NIC on a multi-homed host) and TTL (1 keeps it
/// on the local subnet).
pub fn sender_socket(broadcast: bool, multicast_if: Option<Ipv4Addr>, ttl: u32) -> io::Result<UdpSocket> {
    let s = UdpSocket::bind("0.0.0.0:0")?;
    s.set_broadcast(broadcast)?;
    s.set_multicast_ttl_v4(ttl)?;
    if let Some(i) = multicast_if {
        socket2::SockRef::from(&s).set_multicast_if_v4(&i)?;
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receives_from_loopback() {
        let cfg = UdpConfig {
            bind: Ipv4Addr::LOCALHOST,
            port: 0,
            ..Default::default()
        };
        let mut src = UdpSource::open(&cfg).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"ping", src.local_addr()).unwrap();
        let d = loop {
            if let Some(d) = src.recv().unwrap() {
                break d;
            }
        };
        assert_eq!(d.payload, b"ping");
        assert_eq!(d.source, sender.local_addr().unwrap());
        assert_eq!(src.datagrams, 1);
    }

    #[test]
    fn rejects_non_multicast_group() {
        let cfg = UdpConfig {
            bind: Ipv4Addr::LOCALHOST,
            port: 0,
            multicast_groups: vec![Ipv4Addr::new(10, 0, 0, 1)],
            ..Default::default()
        };
        assert!(UdpSource::open(&cfg).is_err());
    }
}
