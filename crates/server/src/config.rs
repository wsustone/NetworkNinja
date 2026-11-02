//! `serve --config FILE`: where to listen and how to run, in one file.
//!
//! ```toml
//! [serve]
//! http = "0.0.0.0:8080"
//! db = "events.db"
//! siso = "siso/SISO-REF-010.xml"
//! rulepacks = ["site.toml"]
//!
//! [[listen]]                 # broadcast DIS on 3000
//! name = "dis"
//! port = 3000
//!
//! [[listen]]                 # radio on its own multicast group
//! name = "radio"
//! port = 3001
//! multicast = ["239.1.2.10"]
//! interface = "en0"          # name or IPv4 address, or a list:
//!                            # ["en0", "en5"] joins the group on both
//! share = true               # a simulator on this host holds the port
//! receive_buffer_mb = 16
//! ```
//!
//! Command-line flags override `[serve]` keys; any listener given on the
//! command line (`--listen`, `--port`, `--multicast`, ...) replaces the
//! file's `[[listen]]` list.

use nn_capture::{iface, UdpConfig};
use nn_rules::minitoml::{self, Table, Value};
use std::net::Ipv4Addr;

/// The `[serve]` settings a config file may give; `None` = not set.
#[derive(Debug, Default, Clone)]
pub struct ServeConfig {
    pub listeners: Vec<UdpConfig>,
    pub http: Option<String>,
    pub db: Option<String>,
    pub log: Option<String>,
    pub siso: Option<String>,
    pub rulepacks: Vec<String>,
    pub capture: Option<String>,
    pub capture_budget_mb: Option<f64>,
    pub metrics_retention_days: Option<f64>,
    pub record: Option<String>,
    pub runs: Option<String>,
    pub users: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    /// `[[sender]]` blocks: friendly names for senders and simulations.
    pub senders: crate::names::Names,
}

const SERVE_KEYS: &[&str] = &[
    "http",
    "db",
    "log",
    "siso",
    "rulepacks",
    "capture",
    "capture_budget_mb",
    "metrics_retention_days",
    "record",
    "runs",
    "users",
    "cert",
    "key",
];
const SENDER_KEYS: &[&str] = &["name", "address", "simulation"];
const LISTEN_KEYS: &[&str] = &[
    "name",
    "port",
    "bind",
    "multicast",
    "interface",
    "share",
    "receive_buffer_mb",
];

fn string(v: &Value, what: &str) -> Result<String, String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        _ => Err(format!("{what} must be a string")),
    }
}

fn number(v: &Value, what: &str) -> Result<f64, String> {
    match v {
        Value::Integer(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        _ => Err(format!("{what} must be a number")),
    }
}

fn strings(v: &Value, what: &str) -> Result<Vec<String>, String> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) => a.iter().map(|x| string(x, what)).collect(),
        _ => Err(format!("{what} must be a string or an array of strings")),
    }
}

fn check_keys(t: &Table, allowed: &[&str], what: &str) -> Result<(), String> {
    for k in t.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!(
                "unknown key '{k}' in {what} (expected one of: {})",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

/// Multicast groups, checked to be multicast addresses.
pub fn groups(specs: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    specs
        .iter()
        .map(|g| {
            let ip: Ipv4Addr = g.trim().parse().map_err(|_| format!("'{g}' is not an IPv4 address"))?;
            if !ip.is_multicast() {
                return Err(format!("{ip} is not a multicast address (224.0.0.0-239.255.255.255)"));
            }
            Ok(ip)
        })
        .collect()
}

/// A `[[sender]]` block: a name and exactly one of `address`, `simulation`.
fn sender(t: &Table, n: usize) -> Result<(crate::names::Target, String), String> {
    use crate::names::Target;
    let what = format!("[[sender]] #{n}");
    check_keys(t, SENDER_KEYS, &what)?;
    let name = string(
        t.get("name").ok_or(format!("{what} needs a name"))?,
        &format!("{what} name"),
    )?;
    let target = match (t.get("address"), t.get("simulation")) {
        (Some(a), None) => Target::address(&string(a, &format!("{what} address"))?),
        (None, Some(s)) => Target::simulation(&string(s, &format!("{what} simulation"))?),
        _ => Err("give either address or simulation".to_string()),
    }
    .map_err(|e| format!("{what} ('{name}'): {e}"))?;
    Ok((target, name))
}

fn listener(t: &Table, n: usize) -> Result<UdpConfig, String> {
    let what = format!("[[listen]] #{n}");
    check_keys(t, LISTEN_KEYS, &what)?;
    let mut c = UdpConfig {
        name: format!("listen{n}"),
        ..Default::default()
    };
    if let Some(v) = t.get("name") {
        c.name = string(v, &format!("{what} name"))?;
    }
    let what = format!("listener '{}'", c.name);
    let port = number(
        t.get("port").ok_or(format!("{what} needs a port"))?,
        &format!("{what} port"),
    )?;
    if !(1.0..=65535.0).contains(&port) || port.fract() != 0.0 {
        return Err(format!("{what} port must be 1-65535"));
    }
    c.port = port as u16;
    if let Some(v) = t.get("bind") {
        c.bind = string(v, &format!("{what} bind"))?
            .parse()
            .map_err(|_| format!("{what} bind must be an IPv4 address"))?;
    }
    if let Some(v) = t.get("multicast") {
        c.multicast_groups = groups(&strings(v, &format!("{what} multicast"))?).map_err(|e| format!("{what}: {e}"))?;
    }
    if let Some(v) = t.get("interface") {
        set_interfaces(&mut c, strings(v, &format!("{what} interface"))?).map_err(|e| format!("{what}: {e}"))?;
    }
    if let Some(v) = t.get("share") {
        c.share = matches!(v, Value::Bool(true));
        if !matches!(v, Value::Bool(_)) {
            return Err(format!("{what} share must be true or false"));
        }
    }
    if let Some(v) = t.get("receive_buffer_mb") {
        let mb = number(v, &format!("{what} receive_buffer_mb"))?;
        if mb <= 0.0 {
            return Err(format!("{what} receive_buffer_mb must be > 0"));
        }
        c.recv_buffer = (mb * 1024.0 * 1024.0) as usize;
    }
    Ok(c)
}

fn set_interfaces(c: &mut UdpConfig, names: Vec<String>) -> Result<(), String> {
    c.multicast_interfaces = names
        .iter()
        .map(|n| iface::resolve(n.trim()))
        .collect::<Result<_, _>>()?;
    c.interface_names = names.into_iter().map(|n| n.trim().to_string()).collect();
    Ok(())
}

/// Parse a config file's text.
pub fn parse(src: &str) -> Result<ServeConfig, String> {
    let root = minitoml::parse(src).map_err(|e| e.to_string())?;
    check_keys(&root, &["serve", "listen", "sender"], "the config file")?;
    let mut cfg = ServeConfig::default();
    if let Some(v) = root.get("serve") {
        let Value::Table(t) = v else {
            return Err("[serve] must be a table".into());
        };
        check_keys(t, SERVE_KEYS, "[serve]")?;
        let s = |k: &str| t.get(k).map(|v| string(v, &format!("serve.{k}"))).transpose();
        cfg.http = s("http")?;
        cfg.db = s("db")?;
        cfg.log = s("log")?;
        cfg.siso = s("siso")?;
        cfg.capture = s("capture")?;
        cfg.record = s("record")?;
        cfg.runs = s("runs")?;
        cfg.users = s("users")?;
        cfg.cert = s("cert")?;
        cfg.key = s("key")?;
        if let Some(v) = t.get("rulepacks") {
            cfg.rulepacks = strings(v, "serve.rulepacks")?;
        }
        let n = |k: &str| t.get(k).map(|v| number(v, &format!("serve.{k}"))).transpose();
        cfg.capture_budget_mb = n("capture_budget_mb")?;
        cfg.metrics_retention_days = n("metrics_retention_days")?;
    }
    match root.get("listen") {
        None => {}
        Some(Value::Tables(ts)) => {
            for (i, t) in ts.iter().enumerate() {
                cfg.listeners.push(listener(t, i + 1)?);
            }
        }
        Some(_) => return Err("listeners are [[listen]] blocks".into()),
    }
    match root.get("sender") {
        None => {}
        Some(Value::Tables(ts)) => {
            for (i, t) in ts.iter().enumerate() {
                let (target, name) = sender(t, i + 1)?;
                cfg.senders.set(target, &name);
            }
        }
        Some(_) => return Err("sender names are [[sender]] blocks".into()),
    }
    let mut names: Vec<&str> = cfg.listeners.iter().map(|l| l.name.as_str()).collect();
    names.sort();
    if let Some(w) = names.windows(2).find(|w| w[0] == w[1]) {
        return Err(format!("two listeners are named '{}'", w[0]));
    }
    Ok(cfg)
}

pub fn load(path: &str) -> Result<ServeConfig, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse(&text).map_err(|e| format!("{path}: {e}"))
}

/// `--listen PORT[:GROUP,GROUP...][@INTERFACE,INTERFACE...]`, e.g.
/// `3000`, `3001:239.1.2.10`, `3001:239.1.2.10,239.1.2.11@en0,en5`.
pub fn listen_spec(spec: &str, n: usize) -> Result<UdpConfig, String> {
    let bad = |m: &str| format!("--listen '{spec}': {m} (expected PORT[:GROUP,...][@INTERFACE,...])");
    let (rest, interface) = match spec.split_once('@') {
        Some((r, i)) => (r, Some(i)),
        None => (spec, None),
    };
    let (port, groups_spec) = match rest.split_once(':') {
        Some((p, g)) => (p, Some(g)),
        None => (rest, None),
    };
    let port: u16 = port.parse().ok().filter(|p| *p > 0).ok_or_else(|| bad("bad port"))?;
    let mut c = UdpConfig {
        name: format!("listen{n}"),
        port,
        ..Default::default()
    };
    if let Some(g) = groups_spec {
        let list: Vec<String> = g.split(',').map(str::to_string).collect();
        c.multicast_groups = groups(&list).map_err(|e| bad(&e))?;
    }
    if let Some(i) = interface {
        set_interfaces(&mut c, i.split(',').map(str::to_string).collect()).map_err(|e| bad(&e))?;
    }
    Ok(c)
}

/// A listener from the dashboard's fields (all strings, as a form sends
/// them): name, port, bind, groups and interfaces (comma-separated), share
/// ("true"/"false"), receive_buffer_mb. Validated like a `[[listen]]` block.
pub fn listener_from_fields(f: &std::collections::BTreeMap<String, String>) -> Result<UdpConfig, String> {
    let mut t = Table::new();
    let list = |s: &str| {
        Value::Array(
            s.split(',')
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(|x| Value::String(x.to_string()))
                .collect(),
        )
    };
    for (k, v) in f {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let value = match k.as_str() {
            "name" | "bind" => Value::String(v.to_string()),
            "port" => Value::Integer(v.parse().map_err(|_| format!("port '{v}' is not a number"))?),
            "receive_buffer_mb" => Value::Float(
                v.parse()
                    .map_err(|_| format!("receive_buffer_mb '{v}' is not a number"))?,
            ),
            "share" => Value::Bool(v == "true" || v == "1" || v == "on"),
            "groups" => {
                t.insert("multicast".into(), list(v));
                continue;
            }
            "interfaces" => {
                t.insert("interface".into(), list(v));
                continue;
            }
            other => return Err(format!("unknown listener field '{other}'")),
        };
        t.insert(k.clone(), value);
    }
    if !t.contains_key("name") {
        return Err("a listener needs a name".into());
    }
    listener(&t, 0)
}

fn quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `[[listen]]` blocks for these listeners, in config-file form.
pub fn to_toml(listeners: &[UdpConfig]) -> String {
    let mut out = String::new();
    for c in listeners {
        out += &format!("[[listen]]\nname = {}\nport = {}\n", quote(&c.name), c.port);
        if !c.bind.is_unspecified() {
            out += &format!("bind = {}\n", quote(&c.bind.to_string()));
        }
        if !c.multicast_groups.is_empty() {
            let g: Vec<String> = c.multicast_groups.iter().map(|g| quote(&g.to_string())).collect();
            out += &format!("multicast = [{}]\n", g.join(", "));
        }
        let names: Vec<String> = if c.interface_names.len() == c.multicast_interfaces.len() {
            c.interface_names.clone()
        } else {
            c.multicast_interfaces.iter().map(|i| i.to_string()).collect()
        };
        match names.len() {
            0 => {}
            1 => out += &format!("interface = {}\n", quote(&names[0])),
            _ => {
                out += &format!(
                    "interface = [{}]\n",
                    names.iter().map(|n| quote(n)).collect::<Vec<_>>().join(", ")
                )
            }
        }
        if c.share {
            out += "share = true\n";
        }
        if c.recv_buffer != nn_capture::DEFAULT_RECV_BUFFER {
            out += &format!("receive_buffer_mb = {}\n", c.recv_buffer as f64 / (1024.0 * 1024.0));
        }
        out += "\n";
    }
    out
}

/// Rewrite a config file's `[[listen]]` blocks as `listeners`, keeping the
/// rest of the file (`[serve]`, comments outside listener blocks) as it was.
/// Comments inside the old listener blocks are dropped. The result is
/// re-parsed before it is written, and the old file kept as FILE.bak.
pub fn save_listeners(path: &str, listeners: &[UdpConfig]) -> Result<(), String> {
    save_blocks(path, "[[listen]]", &to_toml(listeners))
}

/// Rewrite a config file's `[[sender]]` blocks as `names`, the same way.
pub fn save_senders(path: &str, names: &crate::names::Names) -> Result<(), String> {
    save_blocks(path, "[[sender]]", &names.to_toml())
}

/// Replace every `header` block of a config file with `blocks`, keeping the
/// rest; check the result parses, keep the old file as FILE.bak.
fn save_blocks(path: &str, header: &str, blocks: &str) -> Result<(), String> {
    let old = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut kept = Vec::new();
    let mut inside = false;
    for line in old.lines() {
        let t = line.trim_start();
        if t.starts_with(header) {
            inside = true;
            continue;
        }
        if t.starts_with('[') {
            inside = false;
        }
        if !inside {
            kept.push(line);
        }
    }
    while kept.last().is_some_and(|l| l.trim().is_empty()) {
        kept.pop();
    }
    let new = format!("{}\n\n{}", kept.join("\n"), blocks);
    parse(&new).map_err(|e| format!("the saved file wouldn't parse ({e}); not written"))?;
    std::fs::write(format!("{path}.bak"), &old).map_err(|e| format!("{path}.bak: {e}"))?;
    std::fs::write(path, new.trim_start()).map_err(|e| format!("{path}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sender_names_parse_save_and_keep_the_rest() {
        let src = "# exercise box\n[serve]\nhttp = \"0.0.0.0:8080\"\n\n[[sender]]\nname = \"VBS4 host\"\naddress = \"10.0.5.10\"\n\n[[listen]]\nname = \"dis\"\nport = 3000\n";
        let c = parse(src).unwrap();
        assert_eq!(c.senders.of_sender("10.0.5.10:3000"), Some("VBS4 host"));
        assert_eq!(c.listeners.len(), 1);
        let path = std::env::temp_dir().join(format!("nn-senders-{}.toml", std::process::id()));
        let path = path.to_str().unwrap();
        std::fs::write(path, src).unwrap();
        let mut names = c.senders.clone();
        names.set(crate::names::Target::simulation("9:9").unwrap(), "JSAF \"B\"");
        save_senders(path, &names).unwrap();
        let back = load(path).unwrap();
        assert_eq!(back.senders, names);
        assert_eq!(back.listeners.len(), 1, "listeners untouched");
        assert_eq!(back.http.as_deref(), Some("0.0.0.0:8080"));
        assert!(std::fs::read_to_string(path).unwrap().starts_with("# exercise box"));
        for ext in ["", ".bak"] {
            let _ = std::fs::remove_file(format!("{path}{ext}"));
        }
        assert!(parse("[[sender]]\nname = \"x\"\n")
            .unwrap_err()
            .contains("either address or simulation"));
        assert!(parse("[[sender]]\nname = \"x\"\naddress = \"nope\"\n").is_err());
    }

    #[test]
    fn parses_serve_settings_and_listeners() {
        let c = parse(
            r#"
[serve]
http = "0.0.0.0:8080"
db = "events.db"
rulepacks = ["a.toml", "b.toml"]
capture_budget_mb = 512

[[listen]]
name = "dis"
port = 3000

[[listen]]
name = "radio"
port = 3001
multicast = ["239.1.2.10", "239.1.2.11"]
interface = "127.0.0.1"
share = true
receive_buffer_mb = 16
"#,
        )
        .unwrap();
        assert_eq!(c.http.as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(c.rulepacks, ["a.toml", "b.toml"]);
        assert_eq!(c.capture_budget_mb, Some(512.0));
        assert_eq!(c.listeners.len(), 2);
        let r = &c.listeners[1];
        assert_eq!((r.name.as_str(), r.port, r.share), ("radio", 3001, true));
        assert_eq!(
            r.multicast_groups,
            [Ipv4Addr::new(239, 1, 2, 10), Ipv4Addr::new(239, 1, 2, 11)]
        );
        assert_eq!(r.multicast_interfaces, [Ipv4Addr::LOCALHOST]);
        assert_eq!(r.interface_names, ["127.0.0.1"]);
        assert_eq!(r.recv_buffer, 16 << 20);
        assert!(!c.listeners[0].share, "sharing is opt-in");
    }

    #[test]
    fn mistakes_are_named() {
        let e = |src: &str| parse(src).unwrap_err();
        assert!(e("[[listen]]\nname = \"x\"\n").contains("needs a port"));
        assert!(e("[[listen]]\nport = 3000\nmulticast = \"10.0.0.1\"\n").contains("not a multicast address"));
        assert!(e("[[listen]]\nport = 3000\ngroups = [\"239.1.1.1\"]\n").contains("unknown key 'groups'"));
        assert!(e("[serve]\nhtp = \"x\"\n").contains("unknown key 'htp'"));
        assert!(
            e("[[listen]]\nname = \"a\"\nport = 1\n[[listen]]\nname = \"a\"\nport = 2\n").contains("two listeners")
        );
        assert!(e("[[listen]]\nport = 3000\ninterface = \"no-such-if-9\"\n").contains("nn-server interfaces"));
    }

    #[test]
    fn listen_specs() {
        let c = listen_spec("3001:239.1.2.10,239.1.2.11@127.0.0.1,127.0.0.1", 2).unwrap();
        assert_eq!(c.port, 3001);
        assert_eq!(c.multicast_groups.len(), 2);
        assert_eq!(c.multicast_interfaces, [Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST]);
        assert!(listen_spec("3000", 1).unwrap().multicast_groups.is_empty());
        assert!(listen_spec("x", 1).is_err());
        assert!(listen_spec("3000:10.1.1.1", 1).unwrap_err().contains("not a multicast"));
    }

    #[test]
    fn dashboard_fields_validate_like_the_file() {
        let f = |pairs: &[(&str, &str)]| {
            listener_from_fields(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
        };
        let c = f(&[
            ("name", "radio"),
            ("port", "3001"),
            ("groups", "239.1.2.10, 239.1.2.11"),
            ("interfaces", "127.0.0.1"),
            ("share", "true"),
            ("receive_buffer_mb", "2"),
        ])
        .unwrap();
        assert_eq!(
            (c.port, c.share, c.multicast_groups.len(), c.recv_buffer),
            (3001, true, 2, 2 << 20)
        );
        assert!(f(&[("name", "x"), ("port", "3000"), ("groups", "10.0.0.1")])
            .unwrap_err()
            .contains("not a multicast"));
        assert!(f(&[("port", "3000")]).unwrap_err().contains("needs a name"));
        assert!(f(&[("name", "x")]).unwrap_err().contains("needs a port"));
    }

    #[test]
    fn saving_rewrites_only_the_listeners() {
        let dir = std::env::temp_dir().join(format!("nn-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nn.toml");
        let path = path.to_str().unwrap();
        std::fs::write(
            path,
            "# my exercise\n[serve]\nhttp = \"0.0.0.0:8080\" # all NICs\n\n[[listen]]\n# old\nname = \"old\"\nport = 1\n",
        )
        .unwrap();
        let radio = listen_spec("3001:239.1.2.10@127.0.0.1", 1).unwrap();
        let radio = UdpConfig {
            name: "radio".into(),
            share: true,
            ..radio
        };
        let dis = UdpConfig {
            name: "dis".into(),
            ..listen_spec("3000", 2).unwrap()
        };
        save_listeners(path, &[dis, radio]).unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        assert!(
            text.starts_with("# my exercise\n[serve]\nhttp = \"0.0.0.0:8080\" # all NICs"),
            "{text}"
        );
        assert!(!text.contains("old"), "{text}");
        let back = parse(&text).unwrap();
        assert_eq!(back.listeners.len(), 2);
        assert_eq!(back.listeners[1].interface_names, ["127.0.0.1"]);
        assert!(back.listeners[1].share);
        assert!(std::fs::read_to_string(format!("{path}.bak")).unwrap().contains("old"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
