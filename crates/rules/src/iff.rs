//! IFF (ADR 0010 Wave 2; IEEE 1278.1 5.7.6, 7.6.5, Annex B), on raw PDU
//! bytes, DIS v7 only (v6's IFF/ATC/NAVAIDS layers differ). Systems keyed by
//! (exercise, emitting entity, System Type, System Designator). The heartbeat,
//! which continues while the system is off, is the `heartbeat` rule's. Point
//! events of the `iff` rule:
//!
//! - `layer-bits`: Layer 1's Information Layers record doesn't match the
//!   layers the PDU holds (it must name Layer 1 and each layer present).
//! - `layer-order`: layers out of ascending order, repeated, or numbered
//!   outside 2-7 (Layer 1 has no Layer Header) (7.6.5.1 a).
//! - `mode5-missing` / `modes-missing`: a system that's on, of a type whose
//!   layer table requires Layer 3 (Mode 5: types 6, 7, 9, 10) or Layer 4
//!   (Mode S: types 9, 11), without it (Annex B.5, Table 166).
//! - `layer2-no-parameters`: Layer 2 with no IFF Fundamental Parameter Data
//!   record (5.7.6.3 m 1).
//! - `initial-unflagged`: a system's first PDU, seen after the monitor has
//!   watched a while, without the Change Indicator (5.7.6.3 f 2).
//! - `change-unflagged`: Layer 1 data changed, Change Indicator clear.
//! - `heartbeat-unflagged`: the heartbeat after a change PDU clears the
//!   Change Indicator; it must repeat it once (5.7.6.3 l 5 ii). Types 6 and
//!   up, which must set the Heartbeat Indicator.
//! - `mode-mismatch`: System On/Off and System Mode disagree (Off is Off;
//!   On isn't Off) (5.7.6.3 l 1).
//! - `after-deactivated` / `destroyed-on`: the entity was deactivated or
//!   removed, or is Destroyed, and the system still reports On past
//!   IFF_PDU_FINAL (5.7.6.3 i, k, l 2).
//!
//! Interactive-mode PDUs (Simulation Mode 1) carry their own flags
//! (B.5.1.2.4 c) and don't count as changes.

use crate::interactions::Finding;
use nn_decode::EntityId;
use nn_state::{EntityKey, EntityTable};
use std::collections::HashMap;
use std::net::SocketAddr;

pub const IFF: u8 = 28;
const LAYER1_END: usize = 60;
/// Appearance Damage (bits 3-4) value Destroyed.
const DESTROYED: u32 = 3;

fn cite(clause: &str) -> String {
    format!(" (IEEE 1278.1 {clause}, draft D16r18)")
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn id_at(b: &[u8], at: usize) -> Option<EntityId> {
    Some(EntityId::new(u16_at(b, at)?, u16_at(b, at + 2)?, u16_at(b, at + 4)?))
}

/// The system types whose layer tables require Layer 3 (Mode 5) and Layer
/// 4 (Mode S) in every PDU (Annex B Tables B.68-B.73).
const MODE5_TYPES: [u16; 4] = [6, 7, 9, 10];
const MODES_TYPES: [u16; 2] = [9, 11];

#[derive(Debug)]
struct System {
    /// Layer 1 from Relative Antenna Location on, Change/Options and
    /// Information Layers zeroed.
    layer1: Vec<u8>,
    /// A change PDU set the Change Indicator; the next heartbeat repeats it.
    owe_flag: bool,
    gone_since: Option<f64>,
    reported_gone: bool,
    last_seen: f64,
}

#[derive(Debug, Default)]
pub struct Systems {
    systems: HashMap<(u8, EntityId, u16, u8), System>,
    started: Option<f64>,
}

/// Layers 2-7 after Layer 1: (number, offset, length).
fn layers(pdu: &[u8]) -> Vec<(u8, usize, usize)> {
    let mut out = Vec::new();
    let mut at = LAYER1_END;
    while let Some(len) = u16_at(pdu, at + 2) {
        let len = len as usize;
        if len < 4 || at + len > pdu.len() {
            break; // the structure check reports it
        }
        out.push((pdu[at], at, len));
        at += len;
    }
    out
}

fn bits(layers: impl Iterator<Item = u8>) -> String {
    let v: Vec<String> = layers.map(|l| l.to_string()).collect();
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

impl Systems {
    /// An IFF PDU's bytes. `grace` is how long to watch before judging a
    /// system's first PDU as its initial report; `final_window` is
    /// IFF_PDU_FINAL.
    pub fn observe(
        &mut self,
        now: f64,
        source: SocketAddr,
        pdu: &[u8],
        table: &EntityTable,
        (grace, final_window): (f64, f64),
    ) -> Vec<Finding> {
        let (Some(&7), Some(&exercise), Some(&IFF), Some(entity), Some(system_type)) =
            (pdu.first(), pdu.get(1), pdu.get(2), id_at(pdu, 12), u16_at(pdu, 36))
        else {
            return Vec::new();
        };
        if pdu.len() < LAYER1_END {
            return Vec::new();
        }
        let started = *self.started.get_or_insert(now);
        let (mode, options, designator, status, info) = (pdu[40], pdu[41], pdu[42], pdu[44], pdu[46]);
        let on = status & 1 == 1;
        let change = options & 1 == 1;
        let heartbeat = options & 0b1000 != 0;
        let interactive = options & 0b10_0000 != 0;
        let key = EntityKey { exercise, id: entity };
        let mut out = Vec::new();
        let mut push = |kind: &'static str, message: String, mut facts: crate::engine::Facts| {
            facts.insert(0, ("emitting entity", entity.to_string()));
            facts.insert(1, ("system type", system_type.to_string()));
            facts.insert(2, ("system designator", designator.to_string()));
            out.push(Finding {
                kind,
                key,
                sender: source,
                message: format!("{entity} IFF (system type {system_type}): {message}"),
                facts,
            });
        };

        let ls = layers(pdu);
        let present: Vec<u8> = std::iter::once(1).chain(ls.iter().map(|l| l.0)).collect();
        let declared: Vec<u8> = (1..=7).filter(|n| info >> n & 1 == 1).collect();
        let mut sorted = present.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted != declared {
            push(
                "layer-bits",
                format!(
                    "the Information Layers record says layers {} but the PDU holds {}{}",
                    bits(declared.iter().copied()),
                    bits(present.iter().copied()),
                    cite("6.2.45, 7.6.5.1")
                ),
                vec![
                    (
                        "information layers",
                        format!("{info:#010b}: {}", bits(declared.iter().copied())),
                    ),
                    ("layers present", bits(present.iter().copied())),
                ],
            );
        }
        let ordered = present.windows(2).all(|w| w[0] < w[1]);
        if !ordered || ls.iter().any(|l| !(2..=7).contains(&l.0)) {
            push(
                "layer-order",
                format!(
                    "layers {} aren't each 2-7, once, in ascending order after Layer 1{}",
                    bits(present.iter().copied()),
                    cite("7.6.5.1 a)")
                ),
                vec![("layers present", bits(present.iter().copied()))],
            );
        }
        if on {
            for (types, layer, kind, what) in [
                (&MODE5_TYPES[..], 3, "mode5-missing", "Mode 5"),
                (&MODES_TYPES[..], 4, "modes-missing", "Mode S"),
            ] {
                if types.contains(&system_type) && !present.contains(&layer) {
                    push(
                        kind,
                        format!(
                            "this system type has a {what} capability, so every PDU while it's on carries Layer {layer}; this one doesn't{}",
                            cite("7.6.5.1, Annex B.5")
                        ),
                        vec![
                            ("layers present", bits(present.iter().copied())),
                            ("required", format!("Layer {layer} ({what})")),
                        ],
                    );
                }
            }
        }
        if let Some(&(_, at, _)) = ls.iter().find(|l| l.0 == 2) {
            if u16_at(pdu, at + 26) == Some(0) {
                push(
                    "layer2-no-parameters",
                    format!(
                        "Layer 2 holds no IFF Fundamental Parameter Data record; it needs at least one{}",
                        cite("5.7.6.3 m) 1)")
                    ),
                    vec![("fundamental parameter records", "0".into())],
                );
            }
        }
        if mode != 0 && (on == (mode == 1)) {
            push(
                "mode-mismatch",
                format!(
                    "System On/Off is {} but System Mode is {mode}; Off goes with Off (1), On with a mode other than Off{}",
                    if on { "On" } else { "Off" },
                    cite("5.7.6.3 l) 1)")
                ),
                vec![
                    ("system on/off", if on { "On (1)" } else { "Off (0)" }.into()),
                    ("system mode", mode.to_string()),
                ],
            );
        }

        // Change Indicator: against this system's last regeneration PDU.
        // Change/Options and Information Layers say what this PDU carries,
        // not the system's state: leave them out of the comparison.
        let mut l1 = pdu[24..LAYER1_END].to_vec();
        l1[41 - 24] = 0;
        l1[46 - 24] = 0;
        let sys_key = (exercise, entity, system_type, designator);
        let fresh = !self.systems.contains_key(&sys_key);
        let s = self.systems.entry(sys_key).or_insert(System {
            layer1: l1.clone(),
            owe_flag: false,
            gone_since: None,
            reported_gone: false,
            last_seen: now,
        });
        s.last_seen = now;
        if !interactive {
            let flag = [("change indicator", if change { "1" } else { "0" }.to_string())];
            if fresh {
                if !change && now - started >= grace {
                    push(
                        "initial-unflagged",
                        format!(
                            "the system's first IFF PDU doesn't set the Change Indicator (Initial Report/Change){}",
                            cite("5.7.6.3 f) 2)")
                        ),
                        flag.to_vec(),
                    );
                }
            } else if s.layer1 != l1 && !change {
                push(
                    "change-unflagged",
                    format!(
                        "Layer 1 data changed but the Change Indicator is clear{}",
                        cite("5.7.6.3 f) 2)")
                    ),
                    flag.to_vec(),
                );
            }
            if system_type >= 6 && heartbeat {
                if s.owe_flag && !change {
                    push(
                        "heartbeat-unflagged",
                        format!(
                            "the heartbeat after a change must repeat the Change Indicator; this one clears it{}",
                            cite("5.7.6.3 l) 5) ii)")
                        ),
                        flag.to_vec(),
                    );
                }
                s.owe_flag = false;
            } else if system_type >= 6 && change {
                s.owe_flag = true;
            }
            s.layer1 = l1;
        }

        // Still on after its entity ceased to exist, or was destroyed.
        let rec = table.get(&key);
        let gone = rec.is_some_and(|r| r.removed || r.deactivated());
        let destroyed = rec.is_some_and(|r| (r.appearance >> 3) & 0b11 == DESTROYED);
        if on && (gone || destroyed) {
            let since = *s.gone_since.get_or_insert(now);
            if now - since >= final_window && !s.reported_gone {
                s.reported_gone = true;
                let (kind, what, clause) = if gone {
                    ("after-deactivated", "was removed or deactivated", "5.7.6.3 l) 2)")
                } else {
                    ("destroyed-on", "is Destroyed", "5.7.6.3 i) 2), k)")
                };
                push(
                    kind,
                    format!(
                        "the entity {what}, but the system still reports On {:.0} s later; its final IFF PDU sets System On/Off to Off{}",
                        now - since,
                        cite(clause)
                    ),
                    vec![
                        ("entity", what.into()),
                        ("system on/off", "On (1)".into()),
                        ("IFF_PDU_FINAL", format!("{final_window} s")),
                    ],
                );
            }
        } else {
            s.gone_since = None;
        }
        out
    }

    /// Forget systems not heard from in ten minutes.
    pub fn expire(&mut self, now: f64) {
        self.systems.retain(|_, s| now - s.last_seen < 600.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> SocketAddr {
        "10.0.0.1:3000".parse().unwrap()
    }
    const ME: EntityId = EntityId::new(1, 1, 1);

    /// A Mark XIIA transponder (type 9) IFF PDU, on, with the given layers
    /// (2: 52 bytes with one parameter record, 3: 28, 4: 36) and flags.
    fn iff(system_type: u16, layers: &[u8], change: bool, heartbeat: bool, code: u16) -> Vec<u8> {
        let mut b = vec![0u8; LAYER1_END];
        b[0] = 7;
        b[1] = 1;
        b[2] = IFF;
        for (i, v) in [ME.site, ME.application, ME.entity].iter().enumerate() {
            b[12 + 2 * i..14 + 2 * i].copy_from_slice(&v.to_be_bytes());
        }
        b[36..38].copy_from_slice(&system_type.to_be_bytes());
        b[40] = 3; // Normal
        b[41] = change as u8 | (heartbeat as u8) << 3;
        b[44] = 1; // on
        b[46] = 0b10;
        b[52..54].copy_from_slice(&code.to_be_bytes()); // Parameter 3, Mode 3/A
        for &l in layers {
            let len: usize = match l {
                2 => 52,
                3 => 28,
                _ => 36,
            };
            let mut layer = vec![0u8; len];
            layer[0] = l;
            layer[2..4].copy_from_slice(&(len as u16).to_be_bytes());
            if l == 2 {
                layer[26..28].copy_from_slice(&1u16.to_be_bytes());
            }
            b.extend(layer);
            b[46] |= 1 << l;
        }
        let len = b.len() as u16;
        b[8..10].copy_from_slice(&len.to_be_bytes());
        b
    }

    fn kinds(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|f| f.kind).collect()
    }

    fn run(s: &mut Systems, now: f64, pdu: &[u8]) -> Vec<Finding> {
        s.observe(now, src(), pdu, &EntityTable::default(), (0.0, 10.0))
    }

    #[test]
    fn a_transponder_told_right_is_silent() {
        let mut s = Systems::default();
        let mut found = Vec::new();
        // Initial report, heartbeats, a Mode 3/A change, the heartbeat that
        // repeats the flag, then plain heartbeats.
        found.extend(run(&mut s, 0.0, &iff(9, &[2, 3, 4], true, false, 1200)));
        found.extend(run(&mut s, 10.0, &iff(9, &[3, 4], true, true, 1200)));
        found.extend(run(&mut s, 20.0, &iff(9, &[2, 3, 4], false, true, 1200)));
        found.extend(run(&mut s, 25.0, &iff(9, &[3, 4], true, false, 4321)));
        found.extend(run(&mut s, 30.0, &iff(9, &[2, 3, 4], true, true, 4321)));
        found.extend(run(&mut s, 40.0, &iff(9, &[3, 4], false, true, 4321)));
        // An old Mark X with no layers past 1.
        found.extend(run(&mut s, 0.0, &iff(1, &[], true, false, 1200)));
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn each_finding_is_named() {
        let mut s = Systems::default();
        let mut bad_bits = iff(9, &[3, 4], true, false, 0);
        bad_bits[46] |= 1 << 2;
        assert_eq!(kinds(&run(&mut s, 0.0, &bad_bits)), ["layer-bits"]);
        let mut s = Systems::default();
        assert_eq!(
            kinds(&run(&mut s, 0.0, &iff(9, &[4, 3], true, false, 0))),
            ["layer-order"]
        );
        let mut s = Systems::default();
        assert_eq!(
            kinds(&run(&mut s, 0.0, &iff(10, &[], true, false, 0))),
            ["mode5-missing"]
        );
        let mut s = Systems::default();
        assert_eq!(
            kinds(&run(&mut s, 0.0, &iff(11, &[], true, false, 0))),
            ["modes-missing"]
        );
        let mut s = Systems::default();
        let mut empty2 = iff(1, &[2], true, false, 0);
        empty2[LAYER1_END + 26..LAYER1_END + 28].copy_from_slice(&[0, 0]);
        assert_eq!(kinds(&run(&mut s, 0.0, &empty2)), ["layer2-no-parameters"]);
        let mut s = Systems::default();
        let mut off_mode = iff(1, &[], true, false, 0);
        off_mode[40] = 1;
        assert_eq!(kinds(&run(&mut s, 0.0, &off_mode)), ["mode-mismatch"]);
        // The Change Indicator.
        let mut s = Systems::default();
        assert_eq!(
            kinds(&run(&mut s, 0.0, &iff(1, &[], false, false, 0))),
            ["initial-unflagged"]
        );
        assert_eq!(
            kinds(&run(&mut s, 10.0, &iff(1, &[], false, false, 7))),
            ["change-unflagged"]
        );
        let mut s = Systems::default();
        run(&mut s, 0.0, &iff(9, &[3, 4], true, false, 0));
        run(&mut s, 5.0, &iff(9, &[3, 4], true, false, 7));
        assert_eq!(
            kinds(&run(&mut s, 10.0, &iff(9, &[3, 4], false, true, 7))),
            ["heartbeat-unflagged"]
        );
        // Not before the monitor has watched a while.
        let mut s = Systems::default();
        assert!(s
            .observe(
                0.0,
                src(),
                &iff(1, &[], false, false, 0),
                &EntityTable::default(),
                (144.0, 10.0)
            )
            .is_empty());
        // v6 isn't judged.
        let mut v6 = iff(10, &[], false, false, 0);
        v6[0] = 6;
        assert!(run(&mut Systems::default(), 0.0, &v6).is_empty());
    }
}
