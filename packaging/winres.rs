// Windows version resource for the release binaries: ProductName
// "NetworkNinja" and ProductVersion = the workspace version, which code
// signing checks before it signs (packaging/SIGNING.md). Each binary's
// build.rs `include!`s this and calls `version_resource(file_name)`.
//
// Writes the compiled .res directly (no rc.exe or resource crate needed) and
// hands it to link.exe, which takes .res files as inputs. Other targets get
// nothing.

fn version_resource(file_name: &str) {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../../packaging/winres.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os != "windows" || target_env != "msvc" {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let description = std::env::var("CARGO_PKG_DESCRIPTION").unwrap_or_default();
    let out = std::path::Path::new(&std::env::var("OUT_DIR").unwrap()).join("version.res");
    let strings = [
        ("CompanyName", "NetworkNinja"),
        ("FileDescription", description.as_str()),
        ("FileVersion", version.as_str()),
        ("InternalName", file_name.trim_end_matches(".exe")),
        ("LegalCopyright", "Copyright 2026 Juston Morgan. Apache License 2.0."),
        ("OriginalFilename", file_name),
        ("ProductName", "NetworkNinja"),
        ("ProductVersion", version.as_str()),
    ];
    std::fs::write(&out, res_file(&version, &strings)).unwrap();
    println!("cargo:rustc-link-arg-bins={}", out.display());
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect()
}

fn pad4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

/// One VS_VERSIONINFO-style node: wLength, wValueLength, wType, the key,
/// the value and the children, each DWORD-aligned.
fn node(key: &str, text: bool, value: &[u8], value_len: u16, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0, 0];
    b.extend(value_len.to_le_bytes());
    b.extend((text as u16).to_le_bytes());
    b.extend(utf16z(key));
    pad4(&mut b);
    b.extend(value);
    for c in children {
        pad4(&mut b);
        b.extend(c);
    }
    let len = b.len() as u16;
    b[..2].copy_from_slice(&len.to_le_bytes());
    b
}

/// "0.1.3" as the fixed-info pair (MS, LS) = (0 << 16 | 1, 3 << 16 | 0).
fn version_words(v: &str) -> (u32, u32) {
    let mut p = v
        .split(|c: char| !c.is_ascii_digit())
        .map(|n| n.parse::<u32>().unwrap_or(0))
        .chain(std::iter::repeat(0));
    let mut w = [0u32; 4];
    for x in &mut w {
        *x = p.next().unwrap() & 0xFFFF;
    }
    (w[0] << 16 | w[1], w[2] << 16 | w[3])
}

fn res_file(version: &str, strings: &[(&str, &str)]) -> Vec<u8> {
    let (ms, ls) = version_words(version);
    let fixed: Vec<u8> = [
        0xFEEF04BD, // signature
        0x0001_0000,
        ms,
        ls, // file version
        ms,
        ls, // product version
        0x3F,
        0,           // flags mask, flags
        0x0004_0004, // VOS_NT_WINDOWS32
        1,           // VFT_APP
        0,
        0,
        0,
    ]
    .iter()
    .flat_map(|w: &u32| w.to_le_bytes())
    .collect();
    let entries: Vec<Vec<u8>> = strings
        .iter()
        .map(|(k, v)| node(k, true, &utf16z(v), v.encode_utf16().count() as u16 + 1, &[]))
        .collect();
    // US English, Unicode.
    let table = node("040904B0", true, &[], 0, &entries);
    let string_info = node("StringFileInfo", true, &[], 0, &[table]);
    let translation = node("Translation", false, &[0x09, 0x04, 0xB0, 0x04], 4, &[]);
    let var_info = node("VarFileInfo", true, &[], 0, &[translation]);
    let info = node("VS_VERSION_INFO", false, &fixed, fixed.len() as u16, &[string_info, var_info]);

    // A .res file: an empty entry, then RT_VERSION (16) #1, language 0x0409.
    let header = |size: u32, ty: u16, name: u16, flags: u16, lang: u16| {
        let mut h = Vec::new();
        h.extend(size.to_le_bytes());
        h.extend(32u32.to_le_bytes());
        h.extend([0xFF, 0xFF]);
        h.extend(ty.to_le_bytes());
        h.extend([0xFF, 0xFF]);
        h.extend(name.to_le_bytes());
        h.extend(0u32.to_le_bytes()); // data version
        h.extend(flags.to_le_bytes());
        h.extend(lang.to_le_bytes());
        h.extend(0u32.to_le_bytes()); // version
        h.extend(0u32.to_le_bytes()); // characteristics
        h
    };
    let mut res = header(0, 0, 0, 0, 0);
    res.extend(header(info.len() as u32, 16, 1, 0x0030, 0x0409));
    res.extend(&info);
    pad4(&mut res);
    res
}
