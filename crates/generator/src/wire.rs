//! The wire layer (ADR 0010): between the simulation and the sink. Counts
//! the tick's PDUs into the ground truth, encodes them, groups them by
//! sender and, with `bundle`, packs each sender's PDUs into shared
//! datagrams, and with `gateway` repeats each datagram from the gateway's
//! address. Ground truth counts the simulator's datagrams, not the copies.

use crate::families::{Out, Outgoing};
use crate::{Config, Sender, Sink, Truth, BUNDLE_LIMIT};
use nn_decode::*;
use std::collections::BTreeMap;
use std::io;

pub(crate) struct Wire {
    bundle: bool,
    gateway: bool,
}

impl Wire {
    pub fn new(cfg: &Config) -> Wire {
        Wire {
            bundle: cfg.bundle,
            gateway: cfg.gateway,
        }
    }

    /// One datagram to the sink, and its gateway copy.
    fn emit(&self, truth: &mut Truth, t: f64, sender: Sender, d: &[u8], sink: &mut dyn Sink) -> io::Result<()> {
        truth.datagrams += 1;
        truth.bytes += d.len() as u64;
        sink.emit(t, sender, d)?;
        if self.gateway {
            sink.emit(t, Sender { relay: true, ..sender }, d)?;
        }
        Ok(())
    }

    /// Send one tick's PDUs at time `t`.
    pub fn send(&self, truth: &mut Truth, t: f64, out: Out, sink: &mut dyn Sink) -> io::Result<()> {
        for Outgoing { pdu, .. } in &out.0 {
            *truth.pdus_by_type.entry(pdu.type_name()).or_insert(0) += 1;
            if let PduBody::EntityState(es) = &pdu.body {
                *truth.entity_states_by_entity.entry(es.entity_id).or_insert(0) += 1;
            }
        }
        let mut by_sender: BTreeMap<Sender, Vec<Vec<u8>>> = BTreeMap::new();
        let mut cut: Vec<(Sender, Vec<u8>)> = Vec::new();
        for o in &out.0 {
            let mut bytes = encode_pdu(&o.pdu);
            if o.cut > 0 {
                bytes.truncate(bytes.len().saturating_sub(o.cut));
                cut.push((o.sender, bytes));
            } else {
                by_sender.entry(o.sender).or_default().push(bytes);
            }
        }
        for (sender, pdus) in by_sender {
            let datagrams: Vec<Vec<u8>> = if self.bundle {
                let mut v: Vec<Vec<u8>> = vec![Vec::new()];
                for p in pdus {
                    if !v.last().unwrap().is_empty() && v.last().unwrap().len() + p.len() > BUNDLE_LIMIT {
                        v.push(Vec::new());
                    }
                    v.last_mut().unwrap().extend(p);
                }
                v
            } else {
                pdus
            };
            for d in datagrams {
                self.emit(truth, t, sender, &d, sink)?;
            }
        }
        // A truncated PDU would swallow whatever followed it in a bundle.
        for (sender, d) in cut {
            self.emit(truth, t, sender, &d, sink)?;
        }
        Ok(())
    }
}
