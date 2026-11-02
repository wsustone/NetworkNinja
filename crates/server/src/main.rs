//! nn-server: milestone 1 console tool.
//!
//! `listen` decodes live DIS traffic from a receive-only UDP socket;
//! `replay` decodes a pcap file. Both print one line per PDU (unless
//! --quiet) and a running summary.

use nn_capture::{Datagram, Listeners, PcapReader, UdpConfig};
use nn_decode::{Pdu, PduBody};
use nn_rules::{AlertEvent, AlertState, Merged, Monitor, Severity};
use nn_server::web::{
    delta_json, entity_baseline, entity_details, error_json, info_json, now_secs, state_json, Hub, Switch,
};
use nn_server::{describe, Tally};
use nn_state::metrics::slot_of;
use nn_state::{secs, Metric};
use std::collections::VecDeque;
use std::fs::File;
use std::io::BufReader;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

const USAGE: &str = "\
nn-server: decode DIS traffic and raise alerts on the console (NetworkNinja)

USAGE:
    nn-server listen [OPTIONS]        Receive live traffic (receive-only)
    nn-server replay FILE [OPTIONS]   Decode a pcap file
    nn-server serve [OPTIONS]         Receive traffic and serve the dashboard
    nn-server --version               Print the version
    nn-server passwd FILE --user U --pass P   Create or update a user account
    nn-server cert OUT [--host NAME]...       Write a self-signed OUT.crt + OUT.key
                          (--host: DNS name or IP, repeatable; default
                          localhost, 127.0.0.1, ::1)
    nn-server interfaces                      List network interfaces (for --iface)

WHERE TO LISTEN (see docs/capture.md)
    --config FILE         Listeners ([[listen]]) and [serve] settings from FILE;
                          flags below override it
    --listen SPEC         A listener: PORT[:GROUP,GROUP...][@INTERFACE], e.g.
                          3000, or 3001:239.1.2.10@en0 (repeatable; replaces
                          the config file's listeners)
    --port N              One listener on UDP port N (default 3000)
    --bind IP             Local address (default 0.0.0.0, needed for broadcast/multicast)
    --multicast GROUP     Join an IPv4 multicast group (repeatable)
    --iface NAME|IP       Interface for multicast joins (repeatable; default: OS choice)
    --share               Share the port(s) with a simulator on this host (safe
                          for broadcast and multicast; unicast goes to only one
                          of the sharing programs)
    --receive-buffer MB   Kernel receive buffer per listener (default 8)

LISTEN / SERVE OPTIONS
    --duration SECS       Stop after this long (default: run until killed)
    --http ADDR           Dashboard bind (serve only; default 127.0.0.1:8080)
    --log FILE            Append the event log to FILE and show past runs
                          (serve only; JSON lines, loaded back at startup)
    --db FILE             Store the event log in SQLite FILE for indexed
                          search via /api/log, plus 10 s metric rollups
                          for /api/query (serve only)
    --metrics-retention DAYS  Keep metric rollups this long (default 7)
    --capture FILE        Persist PDUs to SQLite FILE by the rule packs'
                          [[capture]] tiers: every report from fast movers,
                          a thinned stream from slow and static entities
                          (serve only, live capture only; ADR 0009)
    --capture-budget MB   Size cap for --capture; oldest PDUs are evicted
                          first (default 1024)
    --record FILE         Record every datagram to FILE (native format)
    --replay FILE         Replay a --record file through the dashboard
                          instead of live capture (serve only)
    --speed N             Replay speed multiplier (default 1)
    --runs DIR            Directory of .nnrec files listed at /api/runs
    --users FILE          Require login for /api and /ws (see `passwd`)
                          and switchable from the dashboard (serve only)
    --cert FILE --key FILE  Serve the dashboard over HTTPS + WSS with this
                          PEM cert chain and key (serve only; see `cert`)

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
    --siso FILE           Check enumerated fields against SISO-REF-010 (the XML
                          SISO publishes, free from sisostandards.org); layered
                          between the base pack and --rulepack files
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
                PduBody::EntityStateUpdate(e) => Some(e.entity_id.site),
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

/// Write a new file (never clobbering an existing cert or key).
fn write_new(
    path: &str,
    contents: &str,
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
) -> Result<(), String> {
    use std::io::Write;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, mode);
    o.open(path)
        .and_then(|mut f| f.write_all(contents.as_bytes()))
        .map_err(|e| format!("{path}: {e}"))
}

/// This host's LAN address: the source the OS would route a packet from.
/// Connecting a UDP socket sends nothing; it only picks the route.
fn lan_ip() -> Option<std::net::IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("10.255.255.255:1").ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified() && !ip.is_loopback()).then_some(ip)
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
    if args[0] == "--version" || args[0] == "-V" {
        println!("nn-server {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let command = args.remove(0);
    let mut file = None;
    if command == "replay" || command == "passwd" || command == "cert" {
        if args.is_empty() || args[0].starts_with("--") {
            return Err(format!("{command} needs a FILE (see --help)"));
        }
        file = Some(args.remove(0));
    }

    // A config file seeds the settings; flags then override them.
    let mut config_path: Option<String> = None;
    let file_cfg = match args.iter().position(|a| a == "--config") {
        Some(i) => {
            let f = args.get(i + 1).ok_or("--config needs a value")?.clone();
            args.drain(i..i + 2);
            let c = nn_server::config::load(&f)?;
            config_path = Some(f);
            Some(c)
        }
        None => None,
    };
    let fc = file_cfg.clone().unwrap_or_default();
    let mut udp = UdpConfig {
        name: "dis".into(),
        ..Default::default()
    };
    let mut legacy_listener = false;
    let mut cli_listeners: Vec<UdpConfig> = Vec::new();
    let mut share = false;
    let mut recv_buffer_mb: Option<f64> = None;
    let mut duration = None;
    let mut speed = None;
    let mut http: std::net::SocketAddr = fc
        .http
        .as_deref()
        .unwrap_or("127.0.0.1:8080")
        .parse()
        .map_err(|e| format!("serve.http: {e}"))?;
    let mut log_file: Option<String> = fc.log.clone();
    let mut db_file: Option<String> = fc.db.clone();
    let mut retention_days = fc.metrics_retention_days.unwrap_or(7.0);
    let mut capture_file: Option<String> = fc.capture.clone();
    let mut capture_budget_mb = fc.capture_budget_mb.unwrap_or(1024.0);
    let mut record_file: Option<String> = fc.record.clone();
    let mut replay_file: Option<String> = None;
    let mut runs_dir: Option<String> = fc.runs.clone();
    let mut pack_files: Vec<String> = fc.rulepacks.clone();
    let mut siso_file: Option<String> = fc.siso.clone();
    let mut common = Common {
        filter: Filter::default(),
        quiet: false,
        every: 10.0,
    };
    let mut users_file = fc.users.clone();
    let mut passwd_user = None;
    let mut passwd_pass = None;
    let mut cert_file: Option<String> = fc.cert.clone();
    let mut key_file: Option<String> = fc.key.clone();
    let mut cert_hosts: Vec<String> = Vec::new();
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{a} needs a value"));
        let bad = |e: &dyn std::fmt::Display| format!("{a}: {e}");
        match a.as_str() {
            "--port" => {
                udp.port = val()?.parse().map_err(|e| bad(&e))?;
                legacy_listener = true;
            }
            "--bind" => {
                udp.bind = val()?.parse().map_err(|e| bad(&e))?;
                legacy_listener = true;
            }
            "--multicast" => {
                let g = nn_server::config::groups(&[val()?]).map_err(|e| bad(&e))?;
                udp.multicast_groups.extend(g);
                legacy_listener = true;
            }
            "--iface" => {
                let name = val()?;
                udp.multicast_interfaces
                    .push(nn_capture::iface::resolve(&name).map_err(|e| bad(&e))?);
                udp.interface_names.push(name);
                legacy_listener = true;
            }
            "--listen" => {
                let n = cli_listeners.len() + 1;
                cli_listeners.push(nn_server::config::listen_spec(&val()?, n)?);
            }
            "--share" => share = true,
            "--receive-buffer" => recv_buffer_mb = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--duration" => duration = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--speed" => speed = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--exercise" => common.filter.exercise = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--site" => common.filter.site = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--type" => common.filter.types.push(val()?),
            "--quiet" | "--alerts-only" => common.quiet = true,
            "--every" => common.every = val()?.parse().map_err(|e| bad(&e))?,
            "--rulepack" => pack_files.push(val()?),
            "--siso" => siso_file = Some(val()?),
            "--http" => http = val()?.parse().map_err(|e| bad(&e))?,
            "--log" => log_file = Some(val()?),
            "--db" => db_file = Some(val()?),
            "--metrics-retention" => retention_days = val()?.parse::<f64>().map_err(|e| bad(&e))?,
            "--capture" => capture_file = Some(val()?),
            "--capture-budget" => capture_budget_mb = val()?.parse::<f64>().map_err(|e| bad(&e))?,
            "--record" => record_file = Some(val()?),
            "--replay" => replay_file = Some(val()?),
            "--runs" => runs_dir = Some(val()?),
            "--users" => users_file = Some(val()?),
            "--user" => passwd_user = Some(val()?),
            "--pass" => passwd_pass = Some(val()?),
            "--cert" => cert_file = Some(val()?),
            "--key" => key_file = Some(val()?),
            "--host" => cert_hosts.push(val()?),
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }

    // Listeners: the command line's, else the config file's, else one on
    // --port (3000). --share and --receive-buffer apply to the command line's.
    let from_cli = !cli_listeners.is_empty() || legacy_listener || fc.listeners.is_empty();
    let mut listeners = if !cli_listeners.is_empty() {
        if legacy_listener {
            return Err("use either --listen or --port/--bind/--multicast/--iface, not both".into());
        }
        cli_listeners
    } else if legacy_listener || fc.listeners.is_empty() {
        vec![udp]
    } else {
        fc.listeners.clone()
    };
    if from_cli {
        for l in &mut listeners {
            l.share |= share;
            if let Some(mb) = recv_buffer_mb {
                l.recv_buffer = (mb.max(0.1) * 1024.0 * 1024.0) as usize;
            }
        }
    } else if share || recv_buffer_mb.is_some() {
        return Err("--share and --receive-buffer apply to command-line listeners; set share / receive_buffer_mb per [[listen]] in the config file".into());
    }

    let tls = match (cert_file.as_deref(), key_file.as_deref()) {
        (Some(c), Some(k)) => Some(nn_server::tls::load(c.as_ref(), k.as_ref())?),
        (None, None) => None,
        _ => return Err("--cert and --key go together".into()),
    };
    let siso = siso_file
        .as_deref()
        .map(|f| nn_rules::Siso::load(f.as_ref()))
        .transpose()?;
    if let Some(s) = &siso {
        eprintln!(
            "nn-server: enumerations from {} ({}): {} enumerations",
            s.title,
            s.date,
            s.enums.len()
        );
    }
    let packs = Merged::load_with(siso.as_ref(), &pack_files).map_err(|e| e.to_string())?;
    match command.as_str() {
        "listen" => listen(&listeners, duration, &common, &packs),
        "interfaces" => interfaces(),
        "replay" => replay(file.as_deref().unwrap(), speed, &common, &packs),
        "serve" => serve(
            &listeners,
            config_path.as_deref(),
            http,
            duration,
            log_file.as_deref(),
            db_file.as_deref(),
            retention_days * 86_400.0,
            capture_file
                .as_deref()
                .map(|f| (f, (capture_budget_mb.max(1.0) * 1024.0 * 1024.0) as u64)),
            record_file.as_deref(),
            replay_file.as_deref(),
            speed.unwrap_or(1.0),
            runs_dir.as_deref(),
            users_file.as_deref(),
            tls,
            &packs,
        ),
        "cert" => {
            if cert_hosts.is_empty() {
                cert_hosts = vec!["localhost".into(), "127.0.0.1".into(), "::1".into()];
            }
            let out = file.unwrap();
            let (cert, key) = nn_server::tls::self_signed(&cert_hosts)?;
            let (cert_path, key_path) = (format!("{out}.crt"), format!("{out}.key"));
            write_new(&cert_path, &cert, 0o644)?;
            write_new(&key_path, &key, 0o600)?;
            println!("cert: {cert_path} + {key_path} for {}", cert_hosts.join(", "));
            println!("serve with: nn-server serve --cert {cert_path} --key {key_path}");
            Ok(())
        }
        "passwd" => {
            let (Some(f), Some(u), Some(p)) = (file.as_deref(), passwd_user.as_deref(), passwd_pass.as_deref()) else {
                return Err("usage: nn-server passwd FILE --user NAME --pass PASS".into());
            };
            let path = std::path::Path::new(f);
            let mut a = nn_server::auth::Auth::load(path).unwrap_or_else(|_| nn_server::auth::Auth::empty());
            a.set_user(u, p);
            a.save(path).map_err(|e| format!("{f}: {e}"))?;
            println!("users: {f} ({} users)", a.len());
            Ok(())
        }
        other => Err(format!(
            "unknown command '{other}' (expected listen, replay, serve, interfaces, cert or passwd)"
        )),
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

/// One line per listener at startup: where it listens, what it joined,
/// and a warning when the kernel granted less receive buffer than asked.
fn describe_listeners(l: &Listeners) {
    for st in l.stats() {
        describe_listener(&st);
    }
}

fn describe_listener(st: &nn_capture::ListenerStats) {
    let c = &st.config;
    let groups = if c.multicast_groups.is_empty() {
        "broadcast/unicast".to_string()
    } else {
        let on = if c.interface_names.is_empty() {
            "the OS's default interface".to_string()
        } else {
            c.interface_names.join(", ")
        };
        let g: Vec<String> = c.multicast_groups.iter().map(|g| g.to_string()).collect();
        format!("multicast {} on {on}", g.join(", "))
    };
    let shared = if c.share { ", shared" } else { "" };
    eprintln!(
        "  listener '{}': {} ({groups}{shared}), receive buffer {} KB",
        c.name,
        st.local,
        st.recv_buffer / 1024
    );
    // Linux reports twice what it reserves for data; anything below the
    // request means the system limit capped it.
    if st.recv_buffer < c.recv_buffer {
        eprintln!(
            "    warning: asked for {} KB; raise the system limit to avoid drops at high rates \
             (Linux: sysctl net.core.rmem_max; macOS: sysctl kern.ipc.maxsockbuf)",
            c.recv_buffer / 1024
        );
    }
}

fn interfaces() -> Result<(), String> {
    let all = nn_capture::iface::list().map_err(|e| format!("cannot list interfaces: {e}"))?;
    println!(
        "{:<12} {:<16} {:<16} {:<16} state",
        "interface", "IPv4", "netmask", "broadcast"
    );
    for i in all {
        let state = match (i.loopback, i.up) {
            (true, _) => "loopback",
            (false, true) => "up",
            (false, false) => "down",
        };
        println!(
            "{:<12} {:<16} {:<16} {:<16} {state}",
            i.name,
            i.ip.to_string(),
            i.netmask.to_string(),
            i.broadcast.map_or("-".to_string(), |b| b.to_string())
        );
    }
    println!("\nJoin multicast on one with --iface NAME (or interface = \"NAME\" in a [[listen]] block).");
    Ok(())
}

fn listen(cfgs: &[UdpConfig], duration: Option<f64>, common: &Common, packs: &Merged) -> Result<(), String> {
    let src = Listeners::open(cfgs)?;
    eprintln!("nn-server: listening (receive-only)");
    describe_listeners(&src);
    eprintln!("  rule packs: {}", packs.packs.join(" + "));
    let start = Instant::now();
    let mut p = Pipeline::new(packs);
    p.origin = nn_capture::steady_now();
    let mut next_summary = common.every;
    loop {
        let t = start.elapsed().as_secs_f64();
        if duration.is_some_and(|d| t >= d) {
            break;
        }
        if t >= next_summary {
            eprint!("--- {t:.0} s: {}", p.summary(nn_capture::steady_now()));
            next_summary += common.every;
        }
        match src.recv(std::time::Duration::from_millis(250)) {
            Some(d) => show(&mut p, &d, start.elapsed().as_secs_f64(), common),
            None => {
                let events = p.monitor.tick(nn_capture::steady_now());
                p.print_alerts(&events);
            }
        }
    }
    eprint!("=== final: {}", p.summary(nn_capture::steady_now()));
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
enum Src {
    Udp(Listeners),
    Rec(nn_recorder::Reader),
}

/// One change to the live listeners; the message for the log on success.
fn apply_input_change(
    l: &mut Listeners,
    change: &nn_server::web::InputChange,
    config_file: Option<&str>,
) -> Result<String, String> {
    use nn_server::web::InputChange;
    match change {
        InputChange::Add(c) => {
            l.add(c.clone())?;
            Ok(format!("listener '{}' added on port {}", c.name, c.port))
        }
        InputChange::Replace(old, c) => {
            l.replace(old, c.clone())?;
            Ok(format!(
                "listener '{old}' changed (now '{}' on port {})",
                c.name, c.port
            ))
        }
        InputChange::Remove(name) => {
            if !l.remove(name) {
                return Err(format!("no listener named '{name}'"));
            }
            Ok(format!("listener '{name}' removed"))
        }
        InputChange::Save => {
            let path =
                config_file.ok_or("the server wasn't started with --config FILE, so there's no file to save to")?;
            nn_server::config::save_listeners(path, &l.configs())?;
            Ok(format!("listeners saved to {path} (previous version in {path}.bak)"))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn serve(
    cfg: &[UdpConfig],
    config_file: Option<&str>,
    http: std::net::SocketAddr,
    duration: Option<f64>,
    log_file: Option<&str>,
    db_file: Option<&str>,
    retention: f64,
    capture_file: Option<(&str, u64)>,
    record_file: Option<&str>,
    replay_file: Option<&str>,
    speed: f64,
    runs_dir: Option<&str>,
    users_file: Option<&str>,
    tls: Option<std::sync::Arc<rustls::ServerConfig>>,
    packs: &Merged,
) -> Result<(), String> {
    let mut src: Src = match replay_file {
        Some(path) => {
            let r = nn_recorder::Reader::open(std::path::Path::new(path))
                .map_err(|e| format!("cannot open recording {path}: {e}"))?;
            Src::Rec(r)
        }
        None => Src::Udp(Listeners::open(cfg)?),
    };
    let mut rec_w = record_file
        .map(|p| {
            nn_recorder::Writer::create(std::path::Path::new(p))
                .map_err(|e| format!("cannot create recording {p}: {e}"))
        })
        .transpose()?;
    let scheme = if tls.is_some() { "https" } else { "http" };
    let (addr, hub) = match tls {
        Some(cfg) => Hub::listen_tls(http, cfg),
        None => Hub::listen(http),
    }
    .map_err(|e| format!("cannot bind dashboard on {http}: {e}"))?;
    if let Some(path) = config_file {
        hub.set_names(nn_server::config::load(path)?.senders);
    }
    let desc = match &src {
        Src::Udp(l) => format!(
            "live on {}",
            l.stats()
                .iter()
                .map(|s| s.local.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Src::Rec(_) => format!("replaying {} at {}x", replay_file.unwrap(), speed),
    };
    eprintln!("nn-server: {desc} (receive-only)");
    // Listeners as last configured: a return from replay reopens these.
    let mut live_cfgs = cfg.to_vec();
    hub.set_config_file(config_file.map(str::to_string));
    match &src {
        Src::Udp(l) => {
            describe_listeners(l);
            hub.set_inputs(l.stats(), true);
        }
        Src::Rec(_) => hub.set_inputs(Vec::new(), false),
    }
    if addr.ip().is_unspecified() {
        // Bound on every interface: print addresses a browser can actually use.
        eprintln!("  dashboard: {scheme}://localhost:{}", addr.port());
        if let Some(ip) = lan_ip() {
            eprintln!("             {scheme}://{ip}:{}", addr.port());
        }
    } else {
        eprintln!("  dashboard: {scheme}://{addr}");
    }
    eprintln!("  rule packs: {}", packs.packs.join(" + "));
    if let Some(path) = log_file {
        let n = hub
            .open_log(std::path::Path::new(path))
            .map_err(|e| format!("cannot open log {path}: {e}"))?;
        eprintln!("  event log: {path} ({n} entries from past runs)");
    }
    if let Some(path) = db_file {
        hub.open_db(std::path::Path::new(path), &packs.packs.join(" + "))
            .map_err(|e| format!("cannot open db {path}: {e}"))?;
        let swept = hub.sweep_metrics(now_secs() - retention);
        eprintln!(
            "  event store: {path} (metric rollups kept {:.0} days{})",
            retention / 86_400.0,
            if swept > 0 {
                format!(", {swept} old samples swept")
            } else {
                String::new()
            }
        );
    }
    if let Some(dir) = runs_dir {
        hub.set_runs_dir(std::path::PathBuf::from(dir));
        eprintln!("  recordings: {dir}");
    }
    hub.log(
        "info",
        &info_json(
            now_secs(),
            &format!("capture started {desc}; packs {}", packs.packs.join(" + ")),
        ),
    );
    let (cmd_tx, cmd_rx) = std::sync::mpsc::sync_channel::<(String, String)>(64);
    hub.set_command_sink(cmd_tx);
    let (query_tx, query_rx) = std::sync::mpsc::sync_channel::<nn_server::web::QueryReq>(16);
    hub.set_query_sink(query_tx);
    if let Some(f) = users_file {
        let a = nn_server::auth::Auth::load(std::path::Path::new(f)).map_err(|e| format!("--users {f}: {e}"))?;
        eprintln!("  users: {f} ({} accounts)", a.len());
        hub.set_auth(std::sync::Arc::new(a));
    }
    let pdu_store = match capture_file {
        Some((path, budget)) => {
            let st = nn_server::pdustore::PduStore::open(std::path::Path::new(path), budget)
                .map_err(|e| format!("cannot open capture {path}: {e}"))?;
            hub.set_capture(st.path.clone(), std::sync::Arc::clone(&st.stats));
            eprintln!(
                "  pdu capture: {path} (budget {} MB, {} rows stored)",
                budget / (1024 * 1024),
                st.stats.rows.load(std::sync::atomic::Ordering::Relaxed)
            );
            Some(st)
        }
        None => None,
    };
    // PDU capture follows live traffic only, like metric rollups.
    let new_monitor = |live: bool| {
        let mut m = Monitor::with_packs(packs);
        if live && pdu_store.is_some() {
            m.capture = Some(nn_rules::Capture::new(packs.capture.clone()));
        }
        m
    };
    let mut m = new_monitor(matches!(src, Src::Udp(_)));
    let mut recent: VecDeque<String> = VecDeque::new();
    let mut prev_ents = std::collections::BTreeMap::new();
    let mut speed = speed;
    let mut epoch = Instant::now();
    let mut cur_replay: Option<std::path::PathBuf> = replay_file.map(std::path::PathBuf::from);
    let mut skip_to: Option<f64> = None;
    let mut replay_pos: Option<(f64, f64)> = None;
    let start = Instant::now();
    let mut next_state = 0.0;
    let mut next_full = 0.0;
    // Metric rollups reach the store every 10 s, live capture only: a
    // replay's timestamps are the recording's, not today's (ADR 0008).
    let mut flushed: Option<i64> = None;
    let mut next_sweep = 3600.0;
    loop {
        let t = start.elapsed().as_secs_f64();
        if duration.is_some_and(|d| t >= d) {
            break;
        }
        for _ in 0..32 {
            let Ok((user, c)) = cmd_rx.try_recv() else { break };
            match nn_server::web::apply_command_by(&mut m, &c, &user) {
                Ok(out) => {
                    for e in &out.events {
                        let j = hub.log_alert(e);
                        if recent.len() >= 100 {
                            recent.pop_front();
                        }
                        recent.push_back(j);
                    }
                    if let Some(sw) = &out.switch {
                        let switched = match sw {
                            Switch::Live if matches!(src, Src::Udp(_)) => false,
                            Switch::Live => match Listeners::open(&live_cfgs) {
                                Ok(l) => {
                                    hub.set_inputs(l.stats(), true);
                                    src = Src::Udp(l);
                                    cur_replay = None;
                                    replay_pos = None;
                                    true
                                }
                                Err(e) => {
                                    hub.log("error", &info_json(now_secs(), &format!("cannot reopen listener: {e}")));
                                    false
                                }
                            },
                            Switch::Replay(f) => {
                                let Some(dir) = runs_dir else {
                                    hub.log("error", &info_json(now_secs(), "no --runs dir configured"));
                                    continue;
                                };
                                let path = std::path::Path::new(dir).join(f);
                                match nn_recorder::Reader::open(&path) {
                                    Ok(r) => {
                                        hub.set_inputs(Vec::new(), false);
                                        src = Src::Rec(r);
                                        cur_replay = Some(path);
                                        skip_to = None;
                                        true
                                    }
                                    Err(e) => {
                                        hub.log("error", &info_json(now_secs(), &format!("cannot open {f}: {e}")));
                                        false
                                    }
                                }
                            }
                            Switch::Speed(x) => {
                                speed = *x;
                                false
                            }
                            Switch::Inputs(change) => {
                                let result = match &mut src {
                                    Src::Rec(_) => Err("listeners can only change during live capture".to_string()),
                                    Src::Udp(l) => apply_input_change(l, change, config_file),
                                };
                                match result {
                                    Ok(msg) => {
                                        if let Src::Udp(l) = &src {
                                            live_cfgs = l.configs();
                                            hub.set_inputs(l.stats(), true);
                                            if let nn_server::web::InputChange::Add(c)
                                            | nn_server::web::InputChange::Replace(_, c) = change
                                            {
                                                if let Some(st) =
                                                    l.stats().into_iter().find(|s| s.config.name == c.name)
                                                {
                                                    describe_listener(&st);
                                                }
                                            }
                                        }
                                        eprintln!("nn-server: {msg} (by {user})");
                                        hub.log("info", &info_json(now_secs(), &format!("{msg} (by {user})")));
                                        hub.set_input_result(true, msg);
                                    }
                                    Err(e) => {
                                        hub.log(
                                            "error",
                                            &info_json(now_secs(), &format!("listener change failed: {e}")),
                                        );
                                        hub.set_input_result(false, e);
                                    }
                                }
                                false
                            }
                            Switch::Seek(to) => {
                                let Some(path) = &cur_replay else {
                                    hub.log("error", &info_json(now_secs(), "not replaying"));
                                    continue;
                                };
                                match nn_recorder::Reader::open(path) {
                                    Ok(r) => {
                                        src = Src::Rec(r);
                                        skip_to = Some(to.max(0.0));
                                        true
                                    }
                                    Err(e) => {
                                        hub.log(
                                            "error",
                                            &info_json(now_secs(), &format!("cannot reopen recording: {e}")),
                                        );
                                        false
                                    }
                                }
                            }
                        };
                        if switched {
                            m = new_monitor(matches!(src, Src::Udp(_)));
                            prev_ents.clear();
                            recent.clear();
                            next_full = 0.0;
                            flushed = None;
                            hub.reset_metrics_flush();
                            epoch = Instant::now();
                        }
                    }
                    hub.log("info", &info_json(now_secs(), &out.note));
                }
                Err(e) => {
                    hub.log("info", &info_json(now_secs(), &format!("command rejected: {e}")));
                    // A listener change that didn't validate: tell the editor.
                    if c.contains("\"cmd\":\"input") {
                        hub.set_input_result(false, e);
                    }
                }
            }
        }
        while let Ok((q, reply)) = query_rx.try_recv() {
            let _ = reply.send(nn_server::web::memory_cells(&m.metrics, &q));
        }
        let errs_before = m.decode_errors;
        let next = match &mut src {
            Src::Udp(l) => l.recv(std::time::Duration::from_millis(250)),
            Src::Rec(r) => {
                let d = r.next_datagram().map_err(|e| format!("replay failed: {e}"))?;
                if let Some(d) = &d {
                    let first = r.first_at.unwrap_or(d.received_at);
                    let recorded = d.received_at.duration_since(first).unwrap_or_default().as_secs_f64();
                    replay_pos = Some((recorded, r.duration));
                    if let Some(to) = skip_to {
                        if recorded < to {
                            // Fast-forward through the monitor without pacing.
                        } else {
                            skip_to = None;
                            epoch = Instant::now() - std::time::Duration::from_secs_f64(recorded / speed);
                        }
                    } else {
                        let target = std::time::Duration::from_secs_f64(recorded / speed);
                        if target > epoch.elapsed() {
                            std::thread::sleep(target - epoch.elapsed());
                        }
                    }
                }
                d
            }
        };
        let events = match next {
            Some(d) => {
                if let Some(w) = rec_w.as_mut() {
                    let _ = w.record(&d);
                }
                let (.., events) = m.ingest(&d);
                if let (Some(st), Some(c)) = (&pdu_store, m.capture.as_mut()) {
                    st.submit(c.drain());
                    st.stats.skipped.store(c.skipped, std::sync::atomic::Ordering::Relaxed);
                }
                if m.decode_errors > errs_before {
                    hub.log(
                        "error",
                        &error_json(now_secs(), m.decode_errors - errs_before, &d.source.to_string()),
                    );
                }
                events
            }
            None => {
                if matches!(src, Src::Rec(_)) {
                    break; // end of recording
                }
                m.tick(nn_capture::steady_now())
            }
        };
        for e in &events {
            let j = hub.log_alert(e);
            if recent.len() >= 100 {
                recent.pop_front();
            }
            recent.push_back(j);
        }
        if t >= next_state {
            if t >= next_full {
                // Full frame every 30 s resyncs WebSocket clients.
                let snap = state_json(&m, t, hub.client_count(), &packs.packs, &recent, replay_pos);
                hub.set_snapshot(snap.clone());
                hub.broadcast(&snap);
                entity_baseline(&m, &mut prev_ents);
                next_full = t + 30.0;
            } else {
                hub.broadcast(&delta_json(
                    &m,
                    t,
                    hub.client_count(),
                    &packs.packs,
                    &mut prev_ents,
                    replay_pos,
                ));
                // Snapshot (/api/state, new clients) stays current every tick.
                hub.set_snapshot(state_json(&m, t, hub.client_count(), &packs.packs, &recent, replay_pos));
            }
            hub.set_details(entity_details(&m));
            let (open, senders) = nn_server::web::conformance_state(&m);
            hub.set_conformance(open, senders);
            if db_file.is_some() && matches!(src, Src::Udp(_)) {
                let upto = slot_of(m.now.floor() as i64);
                let from = flushed.or(m.metrics.oldest(Metric::PduCount).map(slot_of));
                if let Some(from) = from.filter(|f| upto > *f) {
                    hub.write_rollup(&m.metrics.rollup(from, upto), upto);
                    flushed = Some(upto);
                }
            }
            if t >= next_sweep {
                hub.sweep_metrics(now_secs() - retention);
                next_sweep = t + 3600.0;
            }
            next_state = t + 1.0;
        }
    }
    // The last, partial slot too, so a clean exit loses nothing.
    if let (true, Some(from)) = (
        db_file.is_some() && matches!(src, Src::Udp(_)),
        flushed.or(m.metrics.oldest(Metric::PduCount).map(slot_of)),
    ) {
        let upto = slot_of(m.now.floor() as i64) + nn_state::metrics::SLOT_SECS;
        hub.write_rollup(&m.metrics.rollup(from, upto), upto);
    }
    if let Some(st) = pdu_store {
        st.close();
    }
    if let Some(w) = rec_w.as_mut() {
        let _ = w.flush();
        eprintln!("  recorded {} datagrams", w.records);
    }
    eprintln!(
        "=== final: {} entities, {} dashboard clients",
        m.table.entities.len(),
        hub.client_count()
    );
    Ok(())
}
