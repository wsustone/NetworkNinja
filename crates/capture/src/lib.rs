//! Passive capture of DIS traffic.
//!
//! Sources produce [`Datagram`]s: one UDP payload with its receive time and
//! addresses. Two sources exist today:
//!
//! - [`UdpSource`]: a receive-only UDP socket, with broadcast and IPv4
//!   multicast (explicit IGMP join on a chosen interface).
//! - [`PcapReader`]: classic pcap files (Ethernet, Linux cooked or raw IP).
//!
//! [`PcapWriter`] writes Ethernet/IPv4/UDP frames, used by the generator and
//! for pcap export.
//!
//! Still to come in milestone 1: live libpcap capture on a SPAN port, pcapng
//! import, and kernel drop counters.

mod pcap;
mod udp;

pub use pcap::{PcapError, PcapReader, PcapStats, PcapWriter};
pub use udp::{UdpConfig, UdpSource};

use std::net::SocketAddr;
use std::time::SystemTime;

/// One captured UDP payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Datagram {
    /// When the datagram was received (live) or captured (pcap).
    pub received_at: SystemTime,
    pub source: SocketAddr,
    /// Destination address, when the source knows it (pcap does; a socket
    /// only knows its own bound address).
    pub destination: Option<SocketAddr>,
    pub payload: Vec<u8>,
}
