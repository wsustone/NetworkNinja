//! Radio communications (ADR 0010 step 5, IEEE 1278.1 5.8.3–5.8.5): do
//! Transmitter, Signal and Receiver PDUs tell a consistent story?
//!
//! A radio is its Radio Reference ID plus Radio Number. Findings, all point
//! events of the `radio` rule:
//! - a Signal for a radio whose Transmitter has never been seen (5.8.4.4;
//!   only once the monitor has watched for a stationary heartbeat timeout,
//!   since a transmission may have started before it did);
//! - a Signal while the radio's Transmitter says it isn't transmitting
//!   (5.8.4.3.1), allowing `signal_slack` for Signals still in flight;
//! - a transmitting radio whose Transmitter PDUs stop: silent for longer
//!   than its heartbeat × `timeout_multiplier` (HBT_PDU_TRANSMITTER 2 s if
//!   its antenna moves, HBT_STATIONARY 60 s if not; 5.8.3.3 a);
//! - a Receiver that is on but silent for longer than HBT_PDU_RECEIVER 5 s
//!   × the multiplier (5.8.5.3 a);
//! - Signal fields that contradict each other (5.8.4.3.2): a database index
//!   needs Sample Rate 0 and Data Length 96; anything but encoded audio
//!   needs Samples 0; encoded audio of a fixed-width encoding needs Data
//!   Length = Samples × bits per sample;
//! - a radio's encoded-audio Encoding Type changing (5.8.4.3.1, "shall not
//!   change during the duration of a simulation exercise");
//! - a radio transmitting for `idle_transmit` seconds with no Signal at all
//!   (a stuck key), except unmodulated carriers.

use nn_decode::EntityId;
use std::collections::HashMap;
use std::net::SocketAddr;

/// Radio thresholds, seconds (IEEE 1278.1 defaults; `[rules.radio]`).
#[derive(Debug, Clone, PartialEq)]
pub struct RadioConfig {
    pub transmitter_heartbeat: f64,
    pub stationary_heartbeat: f64,
    pub receiver_heartbeat: f64,
    pub timeout_multiplier: f64,
    pub idle_transmit: f64,
    pub signal_slack: f64,
}

impl Default for RadioConfig {
    fn default() -> Self {
        RadioConfig {
            transmitter_heartbeat: 2.0,
            stationary_heartbeat: 60.0,
            receiver_heartbeat: 5.0,
            timeout_multiplier: 2.4,
            idle_transmit: 30.0,
            signal_slack: 1.0,
        }
    }
}

/// A radio: exercise, Radio Reference ID, Radio Number.
type RadioKey = (u8, EntityId, u16);

const TRANSMITTER: u8 = 25;
const SIGNAL: u8 = 26;
const RECEIVER: u8 = 27;
/// Transmit State: Off, On but not transmitting, On and transmitting.
const TRANSMITTING: u8 = 2;
/// Major Modulation: Unmodulated.
const UNMODULATED: u16 = 6;

#[derive(Debug, Clone)]
struct Tx {
    last_seen: f64,
    state: u8,
    /// When the state last changed.
    since: f64,
    source: SocketAddr,
    antenna: [f64; 3],
    moving: bool,
    unmodulated: bool,
    last_signal: Option<f64>,
    /// A finding already raised for the current silence or idle key.
    reported_silent: bool,
    reported_idle: bool,
}

#[derive(Debug, Clone)]
struct Rx {
    last_seen: f64,
    on: bool,
    source: SocketAddr,
    reported: bool,
}

/// A radio finding, for the engine to raise.
#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub kind: &'static str,
    pub exercise: u8,
    /// The radio's Radio Reference ID (its entity or object).
    pub id: EntityId,
    pub sender: SocketAddr,
    pub message: String,
    pub facts: crate::engine::Facts,
}

#[derive(Debug, Default)]
pub struct Radios {
    transmitters: HashMap<RadioKey, Tx>,
    receivers: HashMap<RadioKey, Rx>,
    /// Encoded-audio Encoding Type last used by each radio.
    encodings: HashMap<RadioKey, u16>,
    started: Option<f64>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(at)?,
        *b.get(at + 1)?,
        *b.get(at + 2)?,
        *b.get(at + 3)?,
    ]))
}

fn f64_at(b: &[u8], at: usize) -> Option<f64> {
    Some(f64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// The radio a Transmitter, Signal or Receiver PDU is about.
fn radio(pdu: &[u8]) -> Option<RadioKey> {
    let id = EntityId::new(u16_at(pdu, 12)?, u16_at(pdu, 14)?, u16_at(pdu, 16)?);
    Some((*pdu.get(1)?, id, u16_at(pdu, 18)?))
}

/// Bits per sample of the fixed-width audio encodings (SISO-REF-010 UID 271).
fn bits_per_sample(encoding_type: u16) -> Option<u32> {
    Some(match encoding_type {
        1 => 8,    // 8-bit mu-law
        2 => 1,    // CVSD
        3 => 4,    // ADPCM
        4 => 16,   // 16-bit linear PCM, big endian
        5 => 8,    // 8-bit linear PCM
        100 => 16, // 16-bit linear PCM, little endian
        _ => return None,
    })
}

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

impl Radios {
    /// One PDU's bytes (header included).
    pub fn observe(&mut self, now: f64, source: SocketAddr, pdu: &[u8], cfg: &RadioConfig) -> Vec<Finding> {
        let started = *self.started.get_or_insert(now);
        let (Some(&pdu_type), Some(key)) = (pdu.get(2), radio(pdu)) else {
            return Vec::new();
        };
        let (exercise, id, number) = key;
        let finding = |kind, message: String, mut facts: crate::engine::Facts| {
            facts.insert(0, ("radio", format!("{id} / {number}")));
            Finding {
                kind,
                exercise,
                id,
                sender: source,
                message: format!("radio {id}/{number}: {message}"),
                facts,
            }
        };
        let mut out = Vec::new();
        match pdu_type {
            TRANSMITTER => {
                let (Some(&state), Some(x), Some(y), Some(z), Some(major)) = (
                    pdu.get(28),
                    f64_at(pdu, 32),
                    f64_at(pdu, 40),
                    f64_at(pdu, 48),
                    u16_at(pdu, 90),
                ) else {
                    return out;
                };
                let antenna = [x, y, z];
                let tx = self.transmitters.entry(key).or_insert(Tx {
                    last_seen: now,
                    state,
                    since: now,
                    source,
                    antenna,
                    moving: false,
                    unmodulated: false,
                    last_signal: None,
                    reported_silent: false,
                    reported_idle: false,
                });
                let moved = antenna
                    .iter()
                    .zip(tx.antenna)
                    .map(|(a, b)| (a - b).powi(2))
                    .sum::<f64>()
                    > 1.0;
                tx.moving = moved;
                tx.antenna = antenna;
                if tx.state != state {
                    tx.since = now;
                    tx.reported_idle = false;
                }
                tx.state = state;
                tx.last_seen = now;
                tx.source = source;
                tx.unmodulated = major == UNMODULATED;
                tx.reported_silent = false;
            }
            SIGNAL => {
                let (Some(scheme), Some(rate), Some(length), Some(samples)) =
                    (u16_at(pdu, 20), u32_at(pdu, 24), u16_at(pdu, 28), u16_at(pdu, 30))
                else {
                    return out;
                };
                let tdl = u16_at(pdu, 22).unwrap_or(0);
                match self.transmitters.get_mut(&key) {
                    None if now - started > cfg.stationary_heartbeat * cfg.timeout_multiplier => out.push(finding(
                        "signal-without-transmitter",
                        format!("Signal with no Transmitter PDU for this radio{}", cite("5.8.4.4")),
                        vec![("Transmitter PDUs seen", "none".into())],
                    )),
                    None => {}
                    Some(tx) => {
                        tx.last_signal = Some(now);
                        let ended_long_ago = now - tx.since > cfg.signal_slack;
                        if tx.state != TRANSMITTING && ended_long_ago {
                            out.push(finding(
                                "signal-not-transmitting",
                                format!(
                                    "Signal while its Transmitter reports Transmit State {} (not transmitting){}",
                                    tx.state,
                                    cite("5.8.4.3.1")
                                ),
                                vec![
                                    ("Transmit State", format!("{} (2 = on and transmitting)", tx.state)),
                                    ("state since", format!("{:.1} s ago", now - tx.since)),
                                ],
                            ));
                        }
                    }
                }
                let (class, low) = (scheme >> 14, scheme & 0x3fff);
                let bad = |what: String| format!("Signal {what}{}", cite("5.8.4.3.2"));
                if class == 3 && (rate != 0 || length != 96) {
                    out.push(finding(
                        "signal-fields",
                        bad(format!("is a database index but has Sample Rate {rate} and Data Length {length} (must be 0 and 96)")),
                        vec![
                            ("encoding class", "3 (database index)".into()),
                            ("Sample Rate", format!("{rate} (expected 0)")),
                            ("Data Length", format!("{length} bits (expected 96)")),
                        ],
                    ));
                }
                if class != 0 && samples != 0 {
                    out.push(finding(
                        "signal-fields",
                        bad(format!(
                            "of encoding class {class} has Samples {samples} (must be 0 unless encoded audio)"
                        )),
                        vec![
                            ("encoding class", class.to_string()),
                            ("Samples", format!("{samples} (expected 0)")),
                        ],
                    ));
                }
                if class != 0 && tdl == 0 && low != 0 {
                    out.push(finding(
                        "signal-fields",
                        bad(format!("of encoding class {class} with TDL Type Other has {low} in the Encoding Scheme's low 14 bits (must be 0)")),
                        vec![
                            ("encoding class", class.to_string()),
                            ("TDL Type", "0 (Other)".into()),
                            ("Encoding Scheme low bits", format!("{low} (expected 0)")),
                        ],
                    ));
                }
                if class == 0 {
                    if let Some(bits) = bits_per_sample(low) {
                        let want = samples as u32 * bits;
                        if length as u32 != want {
                            out.push(finding(
                                "signal-fields",
                                bad(format!(
                                    "Data Length {length} bits, but {samples} samples of encoding type {low} ({bits} bits each) are {want}"
                                )),
                                vec![
                                    ("Data Length", format!("{length} bits")),
                                    ("expected", format!("{want} bits ({samples} samples × {bits} bits)")),
                                    ("encoding type", low.to_string()),
                                ],
                            ));
                        }
                    }
                    if let Some(prev) = self.encodings.insert(key, low) {
                        if prev != low {
                            out.push(finding(
                                "encoding-changed",
                                format!(
                                    "encoded-audio Encoding Type changed from {prev} to {low}{}",
                                    cite("5.8.4.3.1")
                                ),
                                vec![("was", prev.to_string()), ("now", low.to_string())],
                            ));
                        }
                    }
                }
            }
            RECEIVER => {
                let Some(state) = u16_at(pdu, 20) else { return out };
                self.receivers.insert(
                    key,
                    Rx {
                        last_seen: now,
                        on: state != 0,
                        source,
                        reported: false,
                    },
                );
            }
            _ => {}
        }
        out
    }

    /// Radios gone silent or keyed too long; forget long-dead ones. Frozen
    /// time doesn't count: `frozen(exercise, id)` says whether a radio's
    /// entity is frozen, and its clocks restart while it is.
    pub fn expire(&mut self, now: f64, cfg: &RadioConfig, frozen: impl Fn(u8, EntityId) -> bool) -> Vec<Finding> {
        let mut out = Vec::new();
        for (&(exercise, id, number), tx) in self.transmitters.iter_mut() {
            if frozen(exercise, id) {
                tx.last_seen = now;
                tx.last_signal = Some(now);
                continue;
            }
            let heartbeat = if tx.moving {
                cfg.transmitter_heartbeat
            } else {
                cfg.stationary_heartbeat
            };
            let timeout = heartbeat * cfg.timeout_multiplier;
            let silent = now - tx.last_seen;
            if tx.state == TRANSMITTING && silent > timeout && !tx.reported_silent {
                tx.reported_silent = true;
                out.push(Finding {
                    kind: "transmitter-timeout",
                    exercise,
                    id,
                    sender: tx.source,
                    message: format!(
                        "radio {id}/{number}: transmitting, but no Transmitter PDU for {silent:.1} s (timeout {timeout:.1} s){}",
                        cite("5.8.3.3")
                    ),
                    facts: vec![
                        ("radio", format!("{id} / {number}")),
                        ("silent for", format!("{silent:.1} s")),
                        ("timeout", format!("{timeout:.1} s ({heartbeat} s × {})", cfg.timeout_multiplier)),
                        ("antenna", if tx.moving { "moving" } else { "stationary" }.into()),
                    ],
                });
            }
            let quiet_since = tx.last_signal.map_or(tx.since, |s| s.max(tx.since));
            if tx.state == TRANSMITTING
                && !tx.unmodulated
                && silent <= timeout
                && now - quiet_since > cfg.idle_transmit
                && !tx.reported_idle
            {
                tx.reported_idle = true;
                out.push(Finding {
                    kind: "transmitting-idle",
                    exercise,
                    id,
                    sender: tx.source,
                    message: format!(
                        "radio {id}/{number}: transmitting for {:.0} s with no Signal PDU (stuck key?){}",
                        now - quiet_since,
                        cite("5.8.4.3.1")
                    ),
                    facts: vec![
                        ("radio", format!("{id} / {number}")),
                        ("keyed with no Signal for", format!("{:.0} s", now - quiet_since)),
                        ("allowed", format!("{:.0} s (idle_transmit)", cfg.idle_transmit)),
                    ],
                });
            }
        }
        let rx_timeout = cfg.receiver_heartbeat * cfg.timeout_multiplier;
        for (&(exercise, id, number), rx) in self.receivers.iter_mut() {
            if frozen(exercise, id) {
                rx.last_seen = now;
                continue;
            }
            let silent = now - rx.last_seen;
            if rx.on && silent > rx_timeout && !rx.reported {
                rx.reported = true;
                out.push(Finding {
                    kind: "receiver-timeout",
                    exercise,
                    id,
                    sender: rx.source,
                    message: format!(
                        "radio {id}/{number}: receiver on, but no Receiver PDU for {silent:.1} s (timeout {rx_timeout:.1} s){}",
                        cite("5.8.5.3")
                    ),
                    facts: vec![
                        ("radio", format!("{id} / {number}")),
                        ("silent for", format!("{silent:.1} s")),
                        ("timeout", format!("{rx_timeout:.1} s")),
                    ],
                });
            }
        }
        // A radio not heard from in ten minutes is gone, not silent.
        self.transmitters.retain(|_, t| now - t.last_seen < 600.0);
        self.receivers.retain(|_, r| now - r.last_seen < 600.0);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }

    fn ids(b: &mut [u8], pdu_type: u8) {
        b[1] = 1;
        b[2] = pdu_type;
        b[12..18].copy_from_slice(&[0, 1, 0, 1, 0, 1]);
        b[18..20].copy_from_slice(&1u16.to_be_bytes());
    }

    fn transmitter(state: u8) -> Vec<u8> {
        let mut b = vec![0u8; 104];
        ids(&mut b, TRANSMITTER);
        b[28] = state;
        b
    }

    fn signal(scheme: u16, rate: u32, length: u16, samples: u16) -> Vec<u8> {
        let mut b = vec![0u8; 32];
        ids(&mut b, SIGNAL);
        b[20..22].copy_from_slice(&scheme.to_be_bytes());
        b[24..28].copy_from_slice(&rate.to_be_bytes());
        b[28..30].copy_from_slice(&length.to_be_bytes());
        b[30..32].copy_from_slice(&samples.to_be_bytes());
        b
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn signal_field_rules() {
        let cfg = RadioConfig::default();
        let mut r = Radios::default();
        r.observe(0.0, src(), &transmitter(2), &cfg);
        // Database index: rate 0 and length 96.
        assert!(r.observe(0.1, src(), &signal(3 << 14, 0, 96, 0), &cfg).is_empty());
        assert_eq!(
            kinds(&r.observe(0.2, src(), &signal(3 << 14, 8000, 96, 0), &cfg)),
            ["signal-fields"]
        );
        // Raw binary data carries no Samples, and no type without a TDL.
        assert_eq!(
            kinds(&r.observe(0.3, src(), &signal(1 << 14, 9600, 64, 8), &cfg)),
            ["signal-fields"]
        );
        assert_eq!(
            kinds(&r.observe(0.4, src(), &signal((1 << 14) | 5, 9600, 64, 0), &cfg)),
            ["signal-fields"]
        );
        // Mu-law: 8 bits a sample. Changing encoding type is reported.
        assert!(r.observe(0.5, src(), &signal(1, 8000, 3200, 400), &cfg).is_empty());
        assert_eq!(
            kinds(&r.observe(0.6, src(), &signal(4, 8000, 6400, 400), &cfg)),
            ["encoding-changed"]
        );
    }

    #[test]
    fn signals_may_trail_the_end_of_a_transmission_briefly() {
        let cfg = RadioConfig::default();
        let mut r = Radios::default();
        r.observe(0.0, src(), &transmitter(2), &cfg);
        r.observe(5.0, src(), &transmitter(1), &cfg);
        assert!(r.observe(5.5, src(), &signal(4, 8000, 6400, 400), &cfg).is_empty());
        assert_eq!(
            kinds(&r.observe(7.0, src(), &signal(4, 8000, 6400, 400), &cfg)),
            ["signal-not-transmitting"]
        );
    }

    #[test]
    fn frozen_time_does_not_count_toward_radio_timeouts() {
        let cfg = RadioConfig::default();
        let mut r = Radios::default();
        r.observe(0.0, src(), &transmitter(2), &cfg);
        // Stationary: 60 s x 2.4. Frozen for 200 s, then 100 s running.
        for t in (10..200).step_by(10) {
            assert!(r.expire(t as f64, &cfg, |_, _| true).is_empty());
        }
        assert!(r
            .expire(300.0, &cfg, |_, _| false)
            .iter()
            .all(|f| f.kind != "transmitter-timeout"));
        assert_eq!(kinds(&r.expire(345.0, &cfg, |_, _| false)), ["transmitter-timeout"]);
    }
}
