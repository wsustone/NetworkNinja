//! One module per DIS protocol family (ADR 0010). Each owns the PDU types of
//! its family: when they are sent, and the faults and controls that change
//! them. The run calls every family's hooks in a fixed order each tick, so
//! output stays deterministic.

use crate::world::{Tick, World};
use crate::{Event, Sender};
use nn_decode::Pdu;

pub(crate) mod coverage;
pub(crate) mod entity_info;
pub(crate) mod handshakes;
pub(crate) mod sim_mgmt;
pub(crate) mod warfare;

/// PDUs produced this tick, in send order, each with its sender.
#[derive(Default)]
pub(crate) struct Out(pub Vec<Outgoing>);

pub(crate) struct Outgoing {
    pub sender: Sender,
    pub pdu: Pdu,
    /// Bytes cut from the end of the encoded PDU, after its length field is
    /// set: a PDU truncated on the wire. Sent in a datagram of its own.
    pub cut: usize,
}

impl Out {
    pub fn new() -> Out {
        Out::default()
    }
    pub fn push(&mut self, (sender, pdu): (Sender, Pdu)) {
        self.0.push(Outgoing { sender, pdu, cut: 0 });
    }
    pub fn push_cut(&mut self, sender: Sender, pdu: Pdu, cut: usize) {
        self.0.push(Outgoing { sender, pdu, cut });
    }
}

pub(crate) trait Family {
    /// Start of a tick, before scheduled events apply.
    fn begin(&mut self, _w: &mut World, _tick: &Tick, _out: &mut Out) {}

    /// A scheduled event. `None`: not this family's; `Some(applied)`:
    /// handled, and whether it found its target.
    fn on_event(&mut self, _w: &mut World, _tick: &Tick, _ev: &Event, _out: &mut Out) -> Option<bool> {
        None
    }

    /// After events and motion: this tick's regular traffic.
    fn emit(&mut self, _w: &mut World, _tick: &Tick, _out: &mut Out) {}
}

/// The families of a run, in hook order.
pub(crate) fn all(w: &World) -> Vec<Box<dyn Family>> {
    vec![
        Box::new(sim_mgmt::SimManagement),
        Box::new(entity_info::EntityInfo::default()),
        Box::new(warfare::Warfare::new(w.cfg)),
        Box::new(coverage::Coverage::default()),
        Box::new(handshakes::Handshakes::default()),
    ]
}
