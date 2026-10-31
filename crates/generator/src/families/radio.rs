//! Radio Communications (family 4, IEEE 1278.1 5.8.3–5.8.5): with
//! `radio_every`, each site's first vehicle carries radio 1. Every radio
//! heartbeats a Transmitter PDU every 2 s (HBT_PDU_TRANSMITTER; its antenna
//! moves with the vehicle) and a Receiver PDU every 5 s (HBT_PDU_RECEIVER).
//! Every `radio_every` seconds the next site in turn talks for 2 s: a
//! Transmitter going to "On and transmitting", 16-bit PCM Signal PDUs every
//! 50 ms (400 samples at 8 kHz), then a Transmitter back to "On but not
//! transmitting".
//!
//! Faults, by site: its radio keys up and never sends a Signal (`hot-mic`),
//! sends a Signal for a radio with no Transmitter (`orphan-signal`), sends a
//! Signal whose Data Length disagrees with its Samples (`bad-signal`), or
//! stops sending Transmitter PDUs mid-transmission while its Signals carry
//! on (`drop-transmitter`).

use super::{Family, Out};
use crate::world::{Tick, World};
use crate::{Event, EventKind, Target, TICK};
use nn_decode::structure::minimal_body;
use nn_decode::*;
use std::collections::{BTreeMap, BTreeSet};

const TRANSMITTER_HEARTBEAT: f64 = 2.0;
const RECEIVER_HEARTBEAT: f64 = 5.0;
const TALK: f64 = 2.0;
const SAMPLE_RATE: u32 = 8000;
/// Samples per Signal PDU: one tick's worth of audio.
const SAMPLES: u16 = (SAMPLE_RATE as f64 * TICK) as u16;
/// Encoding Scheme: class 0 (encoded audio), type 4 (16-bit linear PCM).
const PCM16: u16 = 4;

struct RadioState {
    /// Transmit State last sent: 1 on, 2 transmitting.
    state: u8,
    last_transmitter: f64,
    last_receiver: f64,
    /// When the current transmission ends; `None` while not talking.
    talking_until: Option<f64>,
}

impl RadioState {
    /// A radio switched on, its first heartbeats due now.
    fn on() -> RadioState {
        RadioState {
            state: 1,
            last_transmitter: f64::NEG_INFINITY,
            last_receiver: f64::NEG_INFINITY,
            talking_until: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct Radio {
    radios: BTreeMap<u16, RadioState>,
    next_talk: f64,
    turn: u16,
    hot_mic: BTreeSet<u16>,
    no_transmitter: BTreeSet<u16>,
    bad_signal: BTreeSet<u16>,
}

fn put(body: &mut [u8], at: usize, bytes: &[u8]) {
    body[at - HEADER_LEN..at - HEADER_LEN + bytes.len()].copy_from_slice(bytes);
}

fn radio_ids(body: &mut [u8], carrier: EntityId, number: u16) {
    put(body, 12, &carrier.site.to_be_bytes());
    put(body, 14, &carrier.application.to_be_bytes());
    put(body, 16, &carrier.entity.to_be_bytes());
    put(body, 18, &number.to_be_bytes());
}

fn transmitter(tick: &Tick, carrier: EntityId, antenna: WorldCoord, state: u8) -> Pdu {
    let mut b = minimal_body(25).expect("Transmitter layout");
    radio_ids(&mut b, carrier, 1);
    put(&mut b, 20, &[7, 1, 0, 225, 1, 0, 0, 0]); // radio type: kind 7, land, US
    put(&mut b, 28, &[state]);
    put(&mut b, 32, &antenna.x.to_be_bytes());
    put(&mut b, 40, &antenna.y.to_be_bytes());
    put(&mut b, 48, &antenna.z.to_be_bytes());
    let frequency = 30_000_000u64 + carrier.site as u64 * 25_000;
    put(&mut b, 72, &frequency.to_be_bytes());
    put(&mut b, 80, &25_000f32.to_be_bytes()); // bandwidth, Hz
    put(&mut b, 84, &40f32.to_be_bytes()); // power, dBm
    put(&mut b, 90, &3u16.to_be_bytes()); // major modulation: angle
    put(&mut b, 92, &1u16.to_be_bytes()); // detail: FM
    put(&mut b, 94, &1u16.to_be_bytes()); // modulation system: generic radio
    Pdu {
        header: tick.header(25),
        body: PduBody::Other(b),
    }
}

fn signal(tick: &Tick, carrier: EntityId, number: u16, bad_length: bool) -> Pdu {
    let mut b = minimal_body(26).expect("Signal layout");
    radio_ids(&mut b, carrier, number);
    let bits = SAMPLES * 16;
    put(&mut b, 20, &PCM16.to_be_bytes());
    put(&mut b, 24, &SAMPLE_RATE.to_be_bytes());
    put(&mut b, 28, &(if bad_length { bits - 8 } else { bits }).to_be_bytes());
    put(&mut b, 30, &SAMPLES.to_be_bytes());
    b.extend(std::iter::repeat_n(0u8, bits as usize / 8));
    Pdu {
        header: tick.header(26),
        body: PduBody::Other(b),
    }
}

fn receiver(tick: &Tick, carrier: EntityId) -> Pdu {
    let mut b = minimal_body(27).expect("Receiver layout");
    radio_ids(&mut b, carrier, 1);
    put(&mut b, 20, &1u16.to_be_bytes()); // on, not receiving
    put(&mut b, 24, &(-90f32).to_be_bytes()); // received power, dBm
    Pdu {
        header: tick.header(27),
        body: PduBody::Other(b),
    }
}

impl Family for Radio {
    fn on_event(&mut self, w: &mut World, tick: &Tick, ev: &Event, out: &mut Out) -> Option<bool> {
        let Target::Site(site) = ev.target else { return None };
        let carrier = EntityId::new(site, w.cfg.application, 1);
        match ev.kind {
            EventKind::HotMic => {
                self.hot_mic.insert(site);
            }
            EventKind::DropTransmitter => {
                self.no_transmitter.insert(site);
            }
            EventKind::BadSignal => {
                self.bad_signal.insert(site);
            }
            // Radio 9 has never sent a Transmitter PDU.
            EventKind::OrphanSignal => out.push((w.sender(site), signal(tick, carrier, 9, false))),
            _ => return None,
        }
        Some(true)
    }

    fn emit(&mut self, w: &mut World, tick: &Tick, out: &mut Out) {
        let Some(every) = w.cfg.radio_every else { return };
        if w.frozen && w.cfg.silent_when_frozen {
            return;
        }
        let t = tick.t;
        let app = w.cfg.application;
        // Whose turn to talk.
        if t + 1e-9 >= self.next_talk {
            self.next_talk = t + every;
            let site = w.cfg.site_base + self.turn % w.cfg.sites;
            self.turn += 1;
            let r = self.radios.entry(site).or_insert_with(RadioState::on);
            if r.talking_until.is_none() {
                r.talking_until = Some(t + TALK);
            }
        }
        for s in 0..w.cfg.sites {
            let site = w.cfg.site_base + s;
            let carrier = EntityId::new(site, app, 1);
            let Some(i) = w.find(&carrier) else { continue };
            let antenna = w.entities[i].kinematics(w.motion_time).0;
            let sender = w.sender(site);
            let hot = self.hot_mic.contains(&site);
            let r = self.radios.entry(site).or_insert_with(RadioState::on);
            // A hot mic keys up and stays keyed.
            if hot && r.talking_until.is_none() {
                r.talking_until = Some(f64::INFINITY);
            }
            let talking = r.talking_until.is_some_and(|end| t < end);
            let silent_tx = self.no_transmitter.contains(&site);
            if talking && r.state != 2 {
                r.state = 2;
                out.push((sender, transmitter(tick, carrier, antenna, 2)));
                r.last_transmitter = t;
            } else if !talking && r.state == 2 {
                r.state = 1;
                r.talking_until = None;
                if !silent_tx {
                    out.push((sender, transmitter(tick, carrier, antenna, 1)));
                }
                r.last_transmitter = t;
            } else if t - r.last_transmitter >= TRANSMITTER_HEARTBEAT && !(silent_tx && talking) {
                out.push((sender, transmitter(tick, carrier, antenna, r.state)));
                r.last_transmitter = t;
            }
            if talking && !hot {
                let bad = self.bad_signal.remove(&site);
                out.push((sender, signal(tick, carrier, 1, bad)));
                // A dropped Transmitter keeps the radio talking.
                if silent_tx {
                    r.talking_until = Some(f64::INFINITY);
                }
            }
            if t - r.last_receiver >= RECEIVER_HEARTBEAT {
                out.push((sender, receiver(tick, carrier)));
                r.last_receiver = t;
            }
        }
    }
}
