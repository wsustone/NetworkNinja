//! `/api/monitors` (ADR 0008 slice 3): list, add or replace, delete and
//! preview user monitors. They live in the serve loop's `Monitor`, so the
//! web side sends each request over a channel and waits for the answer;
//! [`handle`] is what the loop runs. Changes are saved to the `--monitors`
//! file (`[[monitor]]` blocks, FILE.bak kept), or last until restart.
//!
//! Requests are JSON: `{"cmd":"list"}`, `{"cmd":"put","toml":"[[monitor]]…"}`
//! (one monitor, replacing any with its id), `{"cmd":"delete","id":"…"}`,
//! `{"cmd":"preview","toml":"…"}` ("would have fired N times" over what
//! memory holds, about the last ten minutes).

use crate::report::json_string;
use nn_rules::monitors::{MonitorDef, MAX_WINDOW};
use nn_rules::{AlertEvent, Monitor};
use std::sync::mpsc::Sender;

/// A request body and where its answer goes: the reply (JSON or an error)
/// and the alert events the change caused (resolutions), for the log.
pub type MonitorReq = (String, Sender<Result<String, String>>);

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn def_json(m: &Monitor, d: &MonitorDef) -> String {
    let q = |s: &str| format!("\"{}\"", esc(s));
    let opt = |s: Option<String>| s.map_or("null".into(), |v| q(&v));
    let wh: Vec<String> = d
        .filter
        .iter()
        .map(|(k, v)| format!("[{},{}]", q(k.name()), q(v)))
        .collect();
    let by: Vec<String> = d.by.iter().map(|k| q(k.name())).collect();
    let firing: Vec<String> = m
        .user_monitors
        .firing()
        .filter(|(id, _, _)| *id == d.id)
        .map(|(_, g, v)| {
            let g: Vec<String> = g.iter().map(|(k, v)| format!("{}={v}", k.name())).collect();
            format!("{{\"group\":{},\"value\":{v}}}", q(&g.join(", ")))
        })
        .collect();
    format!(
        "{{\"id\":{},\"name\":{},\"type\":{},\"metric\":{},\"event\":{},\"where\":[{}],\"by\":[{}],\"agg\":{},\"window\":{},\"condition\":{},\"for\":{},\"severity\":{},\"describe\":{},\"toml\":{},\"firing\":[{}]}}",
        q(&d.id),
        q(&d.name),
        q(d.kind.name()),
        opt(d.metric.map(|x| x.name().to_string())),
        opt(d.event.clone()),
        wh.join(","),
        by.join(","),
        q(d.agg.name()),
        d.window,
        opt(d.condition.map(|c| c.to_string())),
        d.for_secs,
        q(match d.severity {
            nn_rules::Severity::Critical => "critical",
            nn_rules::Severity::Warning => "warning",
        }),
        q(&d.describe()),
        q(&d.to_toml()),
        firing.join(",")
    )
}

/// The monitors and their open groups.
pub fn list_json(m: &Monitor, file: Option<&str>) -> String {
    let items: Vec<String> = m.user_monitors.defs.iter().map(|d| def_json(m, d)).collect();
    format!(
        "{{\"file\":{},\"max_window\":{MAX_WINDOW},\"monitors\":[{}]}}",
        file.map_or("null".into(), |f| format!("\"{}\"", esc(f))),
        items.join(",")
    )
}

/// One monitor from a request's `toml`.
fn one(body: &str) -> Result<MonitorDef, String> {
    let src = json_string(body, "toml").ok_or("missing \"toml\": a [[monitor]] block")?;
    let mut defs = MonitorDef::parse_all(&src)?;
    match defs.len() {
        1 => Ok(defs.remove(0)),
        0 => Err("no [[monitor]] block in \"toml\"".into()),
        n => Err(format!("one monitor per request, got {n}")),
    }
}

/// Write every monitor to `path` (the old file kept as PATH.bak).
pub fn save(path: &str, defs: &[MonitorDef]) -> Result<(), String> {
    let mut text = String::from(
        "# NetworkNinja user monitors (ADR 0008): edited from the dashboard's Monitors tab.\n# See docs/rule-packs.md for the fields.\n\n",
    );
    for d in defs {
        text += &d.to_toml();
    }
    // Check it reads back before replacing anything.
    MonitorDef::parse_all(&text).map_err(|e| format!("the saved file wouldn't parse ({e}); not written"))?;
    if let Ok(old) = std::fs::read_to_string(path) {
        std::fs::write(format!("{path}.bak"), old).map_err(|e| format!("{path}.bak: {e}"))?;
    }
    std::fs::write(path, text).map_err(|e| format!("{path}: {e}"))
}

/// Load `path`'s monitors; a missing file is no monitors.
pub fn load(path: &str) -> Result<Vec<MonitorDef>, String> {
    match std::fs::read_to_string(path) {
        Ok(src) => MonitorDef::parse_all(&src).map_err(|e| format!("{path}: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("{path}: {e}")),
    }
}

/// Run one request against the serve loop's monitor. Returns the answer
/// and the alert events a change caused (to log).
pub fn handle(m: &mut Monitor, body: &str, file: Option<&str>) -> (Result<String, String>, Vec<AlertEvent>) {
    let mut events = Vec::new();
    let saved = |defs: &[MonitorDef]| -> Result<String, String> {
        match file {
            Some(p) => save(p, defs).map(|_| format!("saved to {p}")),
            None => Ok("until restart: start with --monitors FILE to keep monitors".into()),
        }
    };
    let r = match json_string(body, "cmd").as_deref() {
        Some("list") | None => Ok(list_json(m, file)),
        Some("put") => one(body).and_then(|def| {
            let mut defs = m.user_monitors.defs.clone();
            let id = def.id.clone();
            let verb = match defs.iter().position(|d| d.id == id) {
                Some(i) => {
                    defs[i] = def;
                    "updated"
                }
                None => {
                    defs.push(def);
                    "added"
                }
            };
            let where_ = saved(&defs)?;
            events = m.set_monitors(defs);
            Ok(format!(
                "{{\"ok\":true,\"message\":\"{verb} monitor {id}; {}\"}}",
                esc(&where_)
            ))
        }),
        Some("delete") => (|| {
            let id = json_string(body, "id").ok_or("missing \"id\"")?;
            let mut defs = m.user_monitors.defs.clone();
            let before = defs.len();
            defs.retain(|d| d.id != id);
            if defs.len() == before {
                return Err(format!("no monitor '{id}'"));
            }
            let where_ = saved(&defs)?;
            events = m.set_monitors(defs);
            Ok(format!(
                "{{\"ok\":true,\"message\":\"deleted monitor {id}; {}\"}}",
                esc(&where_)
            ))
        })(),
        Some("preview") => one(body).map(|def| {
            let now = m.now;
            let from = now - MAX_WINDOW as f64 + def.window.max(def.for_secs) as f64;
            let (n, groups) = m.user_monitors.preview(&def, &m.metrics, (from, now, 5.0));
            let g: Vec<String> = groups
                .iter()
                .map(|g| {
                    let t: Vec<String> = g.iter().map(|(k, v)| format!("{}={v}", k.name())).collect();
                    format!("\"{}\"", esc(&t.join(", ")))
                })
                .collect();
            format!(
                "{{\"would_fire\":{n},\"groups\":[{}],\"span\":{:.0},\"describe\":\"{}\"}}",
                g.join(","),
                (now - from).max(0.0),
                esc(&def.describe())
            )
        }),
        Some(c) => Err(format!("unknown cmd '{c}' (expected list, put, delete or preview)")),
    };
    (r, events)
}
