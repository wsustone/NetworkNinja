//! nn-server: milestone 1 console tool.
//!
//! `listen` decodes live DIS traffic from a receive-only UDP socket;
//! `replay` decodes a pcap file. Both print one line per PDU (unless
//! --quiet) and a running summary.

use nn_capture::{Datagram, PcapReader, UdpConfig, UdpSource};
use nn_decode::{Pdu, PduBody};
use nn_rules::{AlertEvent, AlertState, Merged, Monitor, Severity};
use nn_server::web::{alert_json, error_json, info_json, now_secs, state_json, Hub};
use nn_server::{describe, Tally};
use nn_state::secs;
use std::collections::VecDeque;
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

const USAGE: &str = "\
nn-server: decode DIS traffic and raise alerts on the console (NetworkNinja)

USAGE:
    nn-server listen [OPTIONS]        Receive live traffic (receive-only)
    nn-server replay FILE [OPTIONS]   Decode a pcap file
    nn-server serve [OPTIONS]         Receive traffic and serve the dashboard

LISTEN / SERVE OPTIONS
    --port N              UDP port (default 3000)
    --bind IP             Local address (default 0.0.0.0, needed for broadcast/multicast)
    --multicast GROUP     Join an IPv4 multicast group (repeatable)
    --iface IP            Interface address for multicast joins (default: OS choice)
    --duration SECS       Stop after this long (default: run until killed)
    --http ADDR           Dashboard bind (serve only; default 127.0.0.1:8080)
    --log FILE            Append the event log to FILE and show past runs
                          (serve only; JSON lines, loaded back at startup)

REPLAY OPTIONS
    --speed X             Replay at X times real time (default: as fast as possible)

COMMON OPTIONS (display filters; totals always count everything)
    --exercise N          Only show PDUs from this exercise
    --site N              Only show PDUs whose entity/originator is on this site
    --type NAME           Only show this PDU type, e.g. EntityState (repeatable)
    --quiet               No per-PDU lines; alerts and summaries only
    --alerts-only         Same as --quiet
    --every SECS          Print a summary every N seconds (default 10)
    --rulepack FILE       Layer a rule pack over the built-in base pack
                          (repeatable; later files win)
";

#[derive(Default)]
struct Filter {
    exercise: Option<u8>,
    site: Option<u16>,
    types: Vec<String>,
}

impl Filter {
    fn matches(&self, p: &Pdu) -> bool {
        if self.exercise.is_some_and(|x| x != p.header.exercise_id) {
            return false;
        }
        if !self.types.is_empty() && !self.types.iter().any(|t| t.eq_ignore_ascii_case(p.type_name())) {
            return false;
        }
        if let Some(site) = self.site {
            let s = match &p.body {
                PduBody::EntityState(e) => Some(e.entity_id.site),
                PduBody::Fire(f) => Some(f.firing_entity.site),
                PduBody::Detonation(d) => Some(d.firing_entity.site),
                PduBody::StartResume(x) => Some(x.originating.site),
                PduBody::StopFreeze(x) => Some(x.originating.site),
                PduBody::RemoveEntity(x) => Some(x.originating.site),
                PduBody::Other(_) => None,
            };
            if s != Some(site) {
                return false;
            }
        }
        true
    }
}

struct Common {
    filter: Filter,
    quiet: bool,
    every: f64,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nn-server: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), String> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return Ok(());
    }
    let command = args.remove(0);
    let mut file = None;
    if command == "replay" {
        if args.is_empty() || args[0].starts_with("--") {
            return Err("replay needs a pcap FILE".into());
        }
        file = Some(args.remove(0));
    }

    let mut udp = UdpConfig::default();
    let mut duration = None;
    let mut speed = None;
    let mut http: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let mut log_file: Option<String> = None;
    let mut pack_files: Vec<String> = Vec::new();
    let mut common = Common {
        filter: Filter::default(),
        quiet: false,
        every: 10.0,
    };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{a} needs a value"));
        let bad = |e: &dyn std::fmt::Display| format!("{a}: {e}");
        match a.as_str() {
            "--port" => udp.port = val()?.parse().map_err(|e| bad(&e))?,
            "--bind" => udp.bind = val()?.parse().map_err(|e| bad(&e))?,
            "--multicast" => udp
                .multicast_groups
                .push(val()?.parse::<Ipv4Addr>().map_err(|e| bad(&e))?),
            "--iface" => udp.multicast_interface = val()?.parse().map_err(|e| bad(&e))?,
            "--duration" => duration = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--speed" => speed = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--exercise" => common.filter.exercise = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--site" => common.filter.site = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--type" => common.filter.types.push(val()?),
            "--quiet" | "--alerts-only" => common.quiet = true,
            "--every" => common.every = val()?.parse().map_err(|e| bad(&e))?,
            "--rulepack" => pack_files.push(val()?),
            "--http" => http = val()?.parse().map_err(|e| bad(&e))?,
            "--log" => log_file = Some(val()?),
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }

    let packs = Merged::load(&pack_files).map_err(|e| e.to_string())?;
    match command.as_str() {
        "listen" => listen(&udp, duration, &common, &packs),
        "replay" => replay(file.as_deref().unwrap(), speed, &common, &packs),
        "serve" => serve(&udp, http, duration, log_file.as_deref(), &packs),
        other => Err(format!("unknown command '{other}' (expected listen, replay or serve)")),
    }
}

/// Totals for the console, plus the monitor that runs the alert rules.
struct Pipeline {
    tally: Tally,
    monitor: Monitor,
    /// Time zero for display, seconds since the epoch.
    origin: f64,
    alerts_fired: u64,
}

impl Pipeline {
    fn new(packs: &Merged) -> Self {
        Pipeline {
            tally: Tally::default(),
            monitor: Monitor::with_packs(packs),
            origin: 0.0,
            alerts_fired: 0,
        }
    }

    fn summary(&self, now: f64) -> String {
        let w1 = self.monitor.metrics.window(now, 1);
        let w10 = self.monitor.metrics.window(now, 10);
        format!(
            "{}  live: {} active entities  {} alerts open  {:.0} PDU/s (1 s)  {:.0} PDU/s (10 s)  {:.1} kB/s\n",
            self.tally.summary().trim_end(),
            self.monitor.active_entities(),
            self.monitor.engine.active().count(),
            w1.pdu_rate(),
            w10.pdu_rate(),
            w10.byte_rate() / 1000.0
        )
    }

    fn print_alerts(&mut self, events: &[AlertEvent]) {
        for e in events {
            let t = e.at - self.origin;
            let rule = format!("{}/{}", e.alert.pack, e.alert.rule_id);
            match e.state {
                AlertState::Firing => {
                    self.alerts_fired += 1;
                    let sev = match e.alert.severity {
                        Severity::Critical => "CRITICAL",
                        Severity::Warning => "WARNING",
                    };
                    println!("{t:>9.3}  ** ALERT {sev:<8} {rule} {}", e.reason);
                }
                AlertState::Resolved => println!(
                    "{t:>9.3}  ** RESOLVED         {rule} {} {} (open {:.1} s)",
                    e.alert.key.id,
                    e.reason,
                    e.at - e.alert.since
                ),
            }
        }
    }
}

fn show(p: &mut Pipeline, d: &Datagram, t: f64, common: &Common) {
    let (_, events) = p.monitor.ingest(d);
    let tally = &mut p.tally;
    for r in tally.ingest(d) {
        match r {
            Ok(p) if !common.quiet && common.filter.matches(&p) => {
                println!("{t:>9.3}  {:<21} {}", d.source.to_string(), describe(&p));
            }
            Ok(_) => {}
            Err(e) if !common.quiet => println!("{t:>9.3}  {:<21} DECODE ERROR {e}", d.source.to_string()),
            Err(_) => {}
        }
    }
    p.print_alerts(&events);
}

fn listen(cfg: &UdpConfig, duration: Option<f64>, common: &Common, packs: &Merged) -> Result<(), String> {
    let mut src = UdpSource::open(cfg).map_err(|e| format!("cannot open UDP {}:{}: {e}", cfg.bind, cfg.port))?;
    eprintln!("nn-server: listening on {} (receive-only)", src.local_addr());
    eprintln!("  rule packs: {}", packs.packs.join(" + "));
    for g in &cfg.multicast_groups {
        eprintln!("  joined multicast {g} on {}", cfg.multicast_interface);
    }
    let start = Instant::now();
    let mut p = Pipeline::new(packs);
    p.origin = secs(SystemTime::now());
    let mut next_summary = common.every;
    loop {
        let t = start.elapsed().as_secs_f64();
        if duration.is_some_and(|d| t >= d) {
            break;
        }
        if t >= next_summary {
            eprint!("--- {t:.0} s: {}", p.summary(secs(SystemTime::now())));
            next_summary += common.every;
        }
        match src.recv().map_err(|e| format!("receive failed: {e}"))? {
            Some(d) => show(&mut p, &d, start.elapsed().as_secs_f64(), common),
            None => {
                let events = p.monitor.tick(secs(SystemTime::now()));
                p.print_alerts(&events);
            }
        }
    }
    eprint!("=== final: {}", p.summary(secs(SystemTime::now())));
    eprintln!("  alerts fired: {}", p.alerts_fired);
    Ok(())
}

fn replay(path: &str, speed: Option<f64>, common: &Common, packs: &Merged) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut reader = PcapReader::new(BufReader::new(f)).map_err(|e| format!("{path}: {e}"))?;
    eprintln!(
        "nn-server: replaying {path}{}",
        speed.map(|s| format!(" at {s}x")).unwrap_or_default()
    );
    eprintln!("  rule packs: {}", packs.packs.join(" + "));
    let mut p = Pipeline::new(packs);
    let wall_start = Instant::now();
    let mut first: Option<SystemTime> = None;
    let mut next_summary = common.every;
    while let Some(d) = reader.next_datagram().map_err(|e| format!("{path}: {e}"))? {
        let t0 = *first.get_or_insert_with(|| {
            p.origin = secs(d.received_at);
            d.received_at
        });
        let t = d.received_at.duration_since(t0).unwrap_or_default().as_secs_f64();
        if let Some(s) = speed.filter(|s| *s > 0.0) {
            if let Some(due) = wall_start.checked_add(Duration::from_secs_f64(t / s)) {
                let now = Instant::now();
                if due > now {
                    std::thread::sleep(due - now);
                }
            }
        }
        if t >= next_summary {
            eprint!("--- {t:.0} s: {}", p.summary(secs(d.received_at)));
            next_summary += common.every;
        }
        show(&mut p, &d, t, common);
    }
    let st = reader.stats;
    eprint!("=== final: {}", p.summary(p.monitor.now));
    eprintln!("  alerts fired: {}", p.alerts_fired);
    eprintln!(
        "  pcap: {} records, {} UDP, {} non-UDP, {} fragments, {} truncated",
        st.records, st.udp_datagrams, st.not_ipv4_udp, st.fragments, st.truncated
    );
    Ok(())
}

/// Live capture plus the embedded dashboard: entity state once a second and
/// alerts the moment they fire, over WebSocket. Every alert, decode error
/// and server event lands in the event log (`/api/log`, `--log` on disk).
fn serve(
    cfg: &UdpConfig,
    http: std::net::SocketAddr,
    duration: Option<f64>,
    log_file: Option<&str>,
    packs: &Merged,
) -> Result<(), String> {
    let mut src = UdpSource::open(cfg).map_err(|e| format!("cannot open UDP {}:{}: {e}", cfg.bind, cfg.port))?;
    let (addr, hub) = Hub::listen(http).map_err(|e| format!("cannot bind dashboard on {http}: {e}"))?;
    eprintln!("nn-server: listening on {} (receive-only)", src.local_addr());
    eprintln!("  dashboard: http://{addr}");
    eprintln!("  rule packs: {}", packs.packs.join(" + "));
    for g in &cfg.multicast_groups {
        eprintln!("  joined multicast {g} on {}", cfg.multicast_interface);
    }
    if let Some(path) = log_file {
        let n = hub
            .open_log(std::path::Path::new(path))
            .map_err(|e| format!("cannot open log {path}: {e}"))?;
        eprintln!("  event log: {path} ({n} entries from past runs)");
    }
    hub.log(
        "info",
        &info_json(
            now_secs(),
            &format!(
                "capture started on {}; packs {}",
                src.local_addr(),
                packs.packs.join(" + ")
            ),
        ),
    );
    let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<String>(64);
    hub.set_command_sink(cmd_tx);
    let mut m = Monitor::with_packs(packs);
    let mut recent: VecDeque<String> = VecDeque::new();
    let start = Instant::now();
    let mut next_state = 0.0;
    loop {
        let t = start.elapsed().as_secs_f64();
        if duration.is_some_and(|d| t >= d) {
            break;
        }
        for _ in 0..32 {
            let Ok(c) = cmd_rx.try_recv() else { break };
            match nn_server::web::apply_command(&mut m, &c) {
                Ok((events, msg)) => {
                    for e in &events {
                        let j = hub.log("alert", &alert_json(e));
                        if recent.len() >= 100 {
                            recent.pop_front();
                        }
                        recent.push_back(j);
                    }
                    hub.log("info", &info_json(now_secs(), &msg));
                }
                Err(e) => {
                    hub.log("info", &info_json(now_secs(), &format!("command rejected: {e}")));
                }
            }
        }
        let errs_before = m.decode_errors;
        let events = match src.recv().map_err(|e| format!("receive failed: {e}"))? {
            Some(d) => {
                let (.., events) = m.ingest(&d);
                if m.decode_errors > errs_before {
                    hub.log(
                        "error",
                        &error_json(now_secs(), m.decode_errors - errs_before, &d.source.to_string()),
                    );
                }
                events
            }
            None => m.tick(now_secs()),
        };
        for e in &events {
            let j = hub.log("alert", &alert_json(e));
            if recent.len() >= 100 {
                recent.pop_front();
            }
            recent.push_back(j);
        }
        if t >= next_state {
            let snap = state_json(&m, t, hub.client_count(), &packs.packs, &recent);
            hub.set_snapshot(snap.clone());
            hub.broadcast(&snap);
            next_state = t + 1.0;
        }
    }
    eprintln!(
        "=== final: {} entities, {} dashboard clients",
        m.table.entities.len(),
        hub.client_count()
    );
    Ok(())
}
