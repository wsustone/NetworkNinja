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
//! interface = "en0"          # name or IPv4 address
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
        c.multicast_interface =
            iface::resolve(&string(v, &format!("{what} interface"))?).map_err(|e| format!("{what}: {e}"))?;
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

/// Parse a config file's text.
pub fn parse(src: &str) -> Result<ServeConfig, String> {
    let root = minitoml::parse(src).map_err(|e| e.to_string())?;
    check_keys(&root, &["serve", "listen"], "the config file")?;
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

/// `--listen PORT[:GROUP,GROUP...][@INTERFACE]`, e.g. `3000`,
/// `3001:239.1.2.10`, `3001:239.1.2.10,239.1.2.11@en0`.
pub fn listen_spec(spec: &str, n: usize) -> Result<UdpConfig, String> {
    let bad = |m: &str| format!("--listen '{spec}': {m} (expected PORT[:GROUP,...][@INTERFACE])");
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
        c.multicast_interface = iface::resolve(i).map_err(|e| bad(&e))?;
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(r.multicast_interface, Ipv4Addr::LOCALHOST);
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
        let c = listen_spec("3001:239.1.2.10,239.1.2.11@127.0.0.1", 2).unwrap();
        assert_eq!(c.port, 3001);
        assert_eq!(c.multicast_groups.len(), 2);
        assert_eq!(c.multicast_interface, Ipv4Addr::LOCALHOST);
        assert!(listen_spec("3000", 1).unwrap().multicast_groups.is_empty());
        assert!(listen_spec("x", 1).is_err());
        assert!(listen_spec("3000:10.1.1.1", 1).unwrap_err().contains("not a multicast"));
    }
}
