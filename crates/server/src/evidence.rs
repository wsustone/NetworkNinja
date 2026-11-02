//! The PDU behind an alert, for `/api/evidence`: its header fields, what the
//! decoder makes of its body (the deep-decoded types) or its enumerated
//! fields (the rest), and a hex dump with offsets, so an integrator can see
//! exactly what the sender put on the wire.

use nn_decode::{decode_datagram, fields::enum_fields_of, pdu_type_name, structure, DisTimestamp, PduBody};

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

fn pairs(v: &[(String, String)]) -> String {
    let items: Vec<String> = v
        .iter()
        .map(|(k, x)| format!("[\"{}\",\"{}\"]", esc(k), esc(x)))
        .collect();
    format!("[{}]", items.join(","))
}

/// The header's fields, named, as the PDU states them.
pub fn header_fields(pdu: &[u8]) -> Vec<(String, String)> {
    let mut f = Vec::new();
    let b = |i: usize| pdu.get(i).copied();
    if let Some(v) = b(0) {
        f.push(("Protocol Version".into(), v.to_string()));
    }
    if let Some(v) = b(1) {
        f.push(("Exercise ID".into(), v.to_string()));
    }
    if let Some(t) = b(2) {
        f.push(("PDU Type".into(), format!("{t} ({})", pdu_type_name(t))));
    }
    if let Some(fam) = b(3) {
        let expected = b(2).map(nn_decode::default_family);
        let note = match expected {
            Some(e) if e != fam => format!(" (this type's family is {e})"),
            _ => String::new(),
        };
        f.push(("Protocol Family".into(), format!("{fam}{note}")));
    }
    if let Some(ts) = pdu.get(4..8) {
        let t = DisTimestamp(u32::from_be_bytes(ts.try_into().unwrap()));
        f.push((
            "Timestamp".into(),
            format!(
                "{:.3} s past the hour ({})",
                t.seconds_past_hour(),
                if t.is_absolute() { "absolute" } else { "relative" }
            ),
        ));
    }
    if let Some(l) = pdu.get(8..10) {
        let len = u16::from_be_bytes([l[0], l[1]]);
        f.push(("Length".into(), format!("{len} bytes ({} received)", pdu.len())));
    }
    if let (Some(v), Some(s)) = (b(0), b(10)) {
        if v >= 7 {
            f.push(("PDU Status".into(), format!("0x{s:02x} ({s:08b})")));
        }
    }
    if let (Some(t), Some(body)) = (b(2), pdu.get(nn_decode::HEADER_LEN..)) {
        if let Some(id) = structure::first_id(t, body) {
            f.push(("First identifier".into(), id.to_string()));
        }
    }
    f
}

/// Offset-annotated hex dump, 16 bytes a line, with printable ASCII.
pub fn hex_dump(pdu: &[u8]) -> String {
    let mut s = String::new();
    for (i, chunk) in pdu.chunks(16).enumerate() {
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        let (a, b) = hex.split_at(hex.len().min(8));
        let ascii: String = chunk
            .iter()
            .map(|&c| if (0x20..0x7f).contains(&c) { c as char } else { '.' })
            .collect();
        s += &format!("{:04x}  {:<23}  {:<23}  {ascii}\n", i * 16, a.join(" "), b.join(" "));
    }
    s
}

/// `/api/evidence` body for one alert's PDU.
pub fn json(seq: u64, at: f64, source: &str, pdu: &[u8]) -> String {
    let header = header_fields(pdu);
    // The deep decoder's view, or the enumerated fields of a type it keeps raw.
    let (decoded, fields) = match decode_datagram(pdu).into_iter().next() {
        Some(Ok(p)) if !matches!(p.body, PduBody::Other(_)) => (Some(format!("{:#?}", p.body)), Vec::new()),
        Some(Err(e)) => (Some(format!("the decoder rejects it: {e}")), Vec::new()),
        _ => {
            let t = pdu.get(2).copied().unwrap_or(0);
            let f = enum_fields_of(t)
                .filter_map(|f| {
                    f.read(pdu)
                        .map(|v| (format!("{} (offset {})", f.name, f.offset), v.to_string()))
                })
                .collect();
            (None, f)
        }
    };
    format!(
        "{{\"seq\":{seq},\"at\":{at},\"source\":\"{}\",\"length\":{},\"header\":{},\"fields\":{},\"decoded\":{},\"hex\":\"{}\"}}",
        esc(source),
        pdu.len(),
        pairs(&header),
        pairs(&fields),
        decoded.map_or("null".into(), |d| format!("\"{}\"", esc(&d))),
        esc(&hex_dump(pdu))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iff_wrong_family() -> Vec<u8> {
        let mut b = vec![0u8; 12];
        b[0] = 7;
        b[1] = 1;
        b[2] = 28; // IFF
        b[3] = 5; // should be 6
        let body = structure::minimal_body(28).unwrap();
        let len = (12 + body.len()) as u16;
        b[8..10].copy_from_slice(&len.to_be_bytes());
        b.extend(body);
        b
    }

    #[test]
    fn header_fields_name_what_the_pdu_says() {
        let f = header_fields(&iff_wrong_family());
        let get = |k: &str| f.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
        assert_eq!(get("PDU Type"), Some("28 (IFF)"));
        assert_eq!(get("Protocol Family"), Some("5 (this type's family is 6)"));
        assert!(get("Length").unwrap().contains("received"));
        assert_eq!(get("PDU Status"), Some("0x00 (00000000)"));
    }

    #[test]
    fn hex_dump_lines_up() {
        let d = hex_dump(&(0u8..20).collect::<Vec<_>>());
        let lines: Vec<&str> = d.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(
            lines[0].starts_with("0000  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f"),
            "{d}"
        );
        assert!(lines[1].starts_with("0010  10 11 12 13"), "{d}");
    }

    #[test]
    fn json_carries_raw_types_fields_and_is_escaped() {
        let j = json(7, 12.5, "10.0.0.1:3000", &iff_wrong_family());
        assert!(
            j.starts_with("{\"seq\":7,\"at\":12.5,\"source\":\"10.0.0.1:3000\""),
            "{j}"
        );
        assert!(j.contains("\"decoded\":null"), "IFF isn't deep-decoded: {j}");
        assert!(j.contains("\"hex\":\"0000  07 01 1c 05"), "{j}");
        assert!(!j.contains('\n'), "newlines escaped");
    }
}
