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
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Seconds on this process's steady clock, anchored to the wall clock the
/// first time it is read. It reads like epoch seconds but never steps when
/// NTP or PTP corrects the host clock, so rule timing (timeouts, rates)
/// stays honest across a correction.
pub fn steady_now() -> f64 {
    static ANCHOR: OnceLock<(f64, Instant)> = OnceLock::new();
    let (wall, at) = ANCHOR.get_or_init(|| {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        (wall, Instant::now())
    });
    wall + at.elapsed().as_secs_f64()
}

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
    /// [`steady_now`] at receipt, for live sources. The monitor runs its
    /// rules on this when present, and on `received_at` otherwise (pcap and
    /// recordings, whose stamps are all there is).
    pub monotonic: Option<f64>,
}
