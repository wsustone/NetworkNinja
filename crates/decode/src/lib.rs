//! DIS v6/v7 PDU codec for NetworkNinja.
//!
//! A thin, dependency-free codec covering the PDU header for every PDU type
//! and full decoding of the six PDUs the MVP uses in depth: Entity State,
//! Fire, Detonation, Start/Resume, Stop/Freeze and Remove Entity. Every other
//! PDU type is returned as [`Pdu::Other`] with its header decoded and the body
//! kept as raw bytes, so rule packs can still check enumerated header fields.
//! [`structure`] checks every type's length against its layout (ADR 0010
//! tier S).
//!
//! All multi-byte fields are big-endian, per IEEE 1278.1.
//!
//! This crate is the fallback described in ADR 0001: it can be replaced by
//! (or wrapped around) dis-rs later without changing its callers.

mod codec;
pub mod fields;
mod pdu;
pub mod structure;
mod time;

pub use codec::{decode_datagram, decode_datagram_spans, decode_pdu, encode_pdu, DecodeError};
pub use pdu::*;
pub use time::DisTimestamp;
