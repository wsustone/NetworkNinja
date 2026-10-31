//! SISO-REF-010 enumerations (ADR 0010 tier E), read at run time from the
//! XML file SISO publishes (`serve --siso FILE`).
//!
//! The file is not shipped: each site uses its own copy from SISO, so the
//! enumerations stay current without a NetworkNinja release. Only `<enum>`
//! elements are read (their `<enumrow>` values and `<enumrow_range>`
//! ranges); bitfields, records and the entity-type tree are not used yet.
//!
//! [`Siso::pack`] turns the enumerations into a rule pack of `[[enum]]`
//! checks for every registry field with a UID, layered between the base
//! pack and site packs.

use crate::pack::{registry, EnumEntry, RulePack};
use std::collections::BTreeMap;
use std::ops::RangeInclusive;
use std::path::Path;

/// One SISO enumeration: its name and the values it defines.
#[derive(Debug, Clone, PartialEq)]
pub struct SisoEnum {
    pub name: String,
    /// Field size in bits.
    pub size: u32,
    /// Defined values, sorted and merged into ranges.
    pub values: Vec<RangeInclusive<u64>>,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Siso {
    /// e.g. "SISO-REF-010-v37".
    pub title: String,
    pub date: String,
    pub enums: BTreeMap<u16, SisoEnum>,
}

/// `name="value"` attributes of one start tag, entities unescaped.
fn attributes(tag: &str) -> BTreeMap<&str, String> {
    let mut out = BTreeMap::new();
    let mut rest = tag;
    while let Some(eq) = rest.find("=\"") {
        let name = rest[..eq].rsplit(|c: char| c.is_whitespace()).next().unwrap_or("");
        let after = &rest[eq + 2..];
        let Some(end) = after.find('"') else { break };
        let value = after[..end]
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&apos;", "'")
            .replace("&amp;", "&");
        out.insert(name, value);
        rest = &after[end + 1..];
    }
    out
}

fn merge(mut v: Vec<RangeInclusive<u64>>) -> Vec<RangeInclusive<u64>> {
    v.sort_by_key(|r| *r.start());
    let mut out: Vec<RangeInclusive<u64>> = Vec::new();
    for r in v {
        match out.last_mut() {
            Some(last) if *r.start() <= last.end().saturating_add(1) => {
                if r.end() > last.end() {
                    *last = *last.start()..=*r.end();
                }
            }
            _ => out.push(r),
        }
    }
    out
}

impl Siso {
    pub fn load(path: &Path) -> Result<Siso, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Siso::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Parse SISO-REF-010 XML.
    pub fn parse(xml: &str) -> Result<Siso, String> {
        let mut siso = Siso::default();
        let mut current: Option<(u16, SisoEnum)> = None;
        let mut rest = xml;
        while let Some(lt) = rest.find('<') {
            rest = &rest[lt + 1..];
            // CDATA and comments may hold '<' and '>' of their own.
            if let Some(r) = rest.strip_prefix("![CDATA[") {
                rest = r.find("]]>").map_or("", |e| &r[e + 3..]);
                continue;
            }
            if let Some(r) = rest.strip_prefix("!--") {
                rest = r.find("-->").map_or("", |e| &r[e + 3..]);
                continue;
            }
            let end = tag_end(rest).ok_or("unterminated tag")?;
            let tag = &rest[..end];
            rest = &rest[end + 1..];
            let name = tag
                .split(char::is_whitespace)
                .next()
                .unwrap_or("")
                .trim_end_matches('/');
            match name {
                "ebv" => {
                    let a = attributes(tag);
                    siso.title = a.get("title").cloned().unwrap_or_default();
                    siso.date = a.get("date").cloned().unwrap_or_default();
                }
                "enum" => {
                    let a = attributes(tag);
                    let uid = a
                        .get("uid")
                        .and_then(|u| u.parse().ok())
                        .ok_or_else(|| format!("<enum> without a numeric uid: {tag}"))?;
                    let e = SisoEnum {
                        name: a.get("name").cloned().unwrap_or_default(),
                        size: a.get("size").and_then(|s| s.parse().ok()).unwrap_or(0),
                        values: Vec::new(),
                    };
                    if tag.ends_with('/') {
                        siso.enums.insert(uid, e);
                    } else {
                        current = Some((uid, e));
                    }
                }
                "/enum" => {
                    if let Some((uid, mut e)) = current.take() {
                        e.values = merge(std::mem::take(&mut e.values));
                        siso.enums.insert(uid, e);
                    }
                }
                "enumrow" | "enumrow_range" => {
                    let Some((_, e)) = current.as_mut() else { continue };
                    let a = attributes(tag);
                    let num = |k: &str| a.get(k).and_then(|v| v.parse::<u64>().ok());
                    let range = if name == "enumrow" {
                        num("value").map(|v| v..=v)
                    } else {
                        num("value_min").zip(num("value_max")).map(|(lo, hi)| lo..=hi)
                    };
                    if let Some(r) = range {
                        e.values.push(r);
                    }
                }
                _ => {}
            }
        }
        if siso.enums.is_empty() {
            return Err("no <enum> elements: not a SISO-REF-010 file".into());
        }
        Ok(siso)
    }

    /// The version number from the title ("SISO-REF-010-v37" → 37).
    pub fn version(&self) -> u64 {
        let digits: String = self
            .title
            .rsplit('v')
            .next()
            .unwrap_or("")
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().unwrap_or(0)
    }

    /// A rule pack with one `[[enum]]` check per registry field whose UID
    /// this file defines. Its checks cite the UID and enumeration name.
    pub fn pack(&self) -> RulePack {
        let mut enums = Vec::new();
        for spec in registry() {
            let Some(e) = spec.uid.and_then(|u| self.enums.get(&u)) else {
                continue;
            };
            if e.values.is_empty() {
                continue;
            }
            enums.push(EnumEntry {
                spec,
                allowed: e.values.clone(),
                severity: None,
                off: false,
                source: Some(format!("SISO-REF-010 UID {} ({})", spec.uid.unwrap(), e.name)),
            });
        }
        RulePack {
            id: "siso-ref-010".into(),
            name: if self.title.is_empty() {
                "SISO-REF-010".into()
            } else {
                self.title.clone()
            },
            version: self.version(),
            source: Some(format!("{} ({})", self.title, self.date)),
            description: Some(
                "Enumerations for Simulation Interoperability. Reprinted with permission from SISO Inc.".into(),
            ),
            enum_repeat_seconds: None,
            tick_interval: None,
            rules: BTreeMap::new(),
            enums,
            captures: Vec::new(),
        }
    }
}

/// Index of the `>` closing a tag, skipping quoted attribute values.
fn tag_end(s: &str) -> Option<usize> {
    let mut quoted = false;
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '>' if !quoted => return Some(i),
            _ => {}
        }
    }
    None
}
