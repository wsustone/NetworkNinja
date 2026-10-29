//! Receive-only UDP socket source.

use crate::Datagram;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, SystemTime};

/// Largest UDP payload we accept.
const MAX_DATAGRAM: usize = 65_535;

/// How to open the socket.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    /// Local address to bind. Use 0.0.0.0 to receive broadcast and multicast.
    pub bind: Ipv4Addr,
    pub port: u16,
    /// IPv4 multicast groups to join.
    pub multicast_groups: Vec<Ipv4Addr>,
    /// Interface (by its IPv4 address) for the IGMP joins. 0.0.0.0 lets the
    /// OS choose, which is often the wrong NIC on a multi-homed host.
    pub multicast_interface: Ipv4Addr,
    /// How long `recv` blocks before returning `Ok(None)`.
    pub read_timeout: Duration,
}

impl Default for UdpConfig {
    fn default() -> Self {
        UdpConfig {
            bind: Ipv4Addr::UNSPECIFIED,
            port: 3000,
            multicast_groups: Vec::new(),
            multicast_interface: Ipv4Addr::UNSPECIFIED,
            read_timeout: Duration::from_millis(250),
        }
    }
}

/// A passive UDP listener. It never sends: the socket is only read from.
pub struct UdpSource {
    socket: UdpSocket,
    local: SocketAddr,
    buf: Vec<u8>,
    pub datagrams: u64,
    pub bytes: u64,
}

impl UdpSource {
    pub fn open(cfg: &UdpConfig) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddrV4::new(cfg.bind, cfg.port))?;
        for group in &cfg.multicast_groups {
            if !group.is_multicast() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("{group} is not a multicast address"),
                ));
            }
            socket.join_multicast_v4(group, &cfg.multicast_interface)?;
        }
        socket.set_read_timeout(Some(cfg.read_timeout))?;
        let local = socket.local_addr()?;
        Ok(UdpSource {
            socket,
            local,
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
                }))
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => Ok(None),
            Err(e) => Err(e),
        }
    }
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
