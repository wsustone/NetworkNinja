//! nn-server: milestone 1 console tool.
//!
//! `listen` decodes live DIS traffic from a receive-only UDP socket;
//! `replay` decodes a pcap file. Both print one line per PDU (unless
//! --quiet) and a running summary.

use nn_capture::{Datagram, PcapReader, UdpConfig, UdpSource};
use nn_decode::{Pdu, PduBody};
use nn_rules::{AlertEvent, AlertState, Merged, Monitor, Severity};
use nn_server::web::{
    alert_json, delta_json, entity_baseline, error_json, info_json, now_secs, state_json, Hub, Switch,
};
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
    nn-server passwd FILE --user U --pass P   Create or update a user account

LISTEN / SERVE OPTIONS
    --port N              UDP port (default 3000)
    --bind IP             Local address (default 0.0.0.0, needed for broadcast/multicast)
    --multicast GROUP     Join an IPv4 multicast group (repeatable)
    --iface IP            Interface address for multicast joins (default: OS choice)
    --duration SECS       Stop after this long (default: run until killed)
    --http ADDR           Dashboard bind (serve only; default 127.0.0.1:8080)
    --log FILE            Append the event log to FILE and show past runs
                          (serve only; JSON lines, loaded back at startup)
    --db FILE             Store the event log in SQLite FILE for indexed
                          search via /api/log (serve only)
    --record FILE         Record every datagram to FILE (native format)
    --replay FILE         Replay a --record file through the dashboard
                          instead of live capture (serve only)
    --speed N             Replay speed multiplier (default 1)
    --runs DIR            Directory of .nnrec files listed at /api/runs
    --users FILE          Require login for /api and /ws (see `passwd`)
                          and switchable from the dashboard (serve only)

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
    if command == "replay" || command == "passwd" {
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
    let mut db_file: Option<String> = None;
    let mut record_file: Option<String> = None;
    let mut replay_file: Option<String> = None;
    let mut runs_dir: Option<String> = None;
    let mut pack_files: Vec<String> = Vec::new();
    let mut common = Common {
        filter: Filter::default(),
        quiet: false,
        every: 10.0,
    };
    let mut users_file = None;
    let mut passwd_user = None;
    let mut passwd_pass = None;
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
            "--db" => db_file = Some(val()?),
            "--record" => record_file = Some(val()?),
            "--replay" => replay_file = Some(val()?),
            "--runs" => runs_dir = Some(val()?),
            "--users" => users_file = Some(val()?),
            "--user" => passwd_user = Some(val()?),
            "--pass" => passwd_pass = Some(val()?),
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }

    let packs = Merged::load(&pack_files).map_err(|e| e.to_string())?;
    match command.as_str() {
        "listen" => listen(&udp, duration, &common, &packs),
        "replay" => replay(file.as_deref().unwrap(), speed, &common, &packs),
        "serve" => serve(
            &udp,
            http,
            duration,
            log_file.as_deref(),
            db_file.as_deref(),
            record_file.as_deref(),
            replay_file.as_deref(),
            speed.unwrap_or(1.0),
            runs_dir.as_deref(),
            users_file.as_deref(),
            &packs,
        ),
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
            "unknown command '{other}' (expected listen, replay, serve or passwd)"
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
enum Src {
    Udp(UdpSource),
    Rec(nn_recorder::Reader),
}

#[allow(clippy::too_many_arguments)]
fn serve(
    cfg: &UdpConfig,
    http: std::net::SocketAddr,
    duration: Option<f64>,
    log_file: Option<&str>,
    db_file: Option<&str>,
    record_file: Option<&str>,
    replay_file: Option<&str>,
    speed: f64,
    runs_dir: Option<&str>,
    users_file: Option<&str>,
    packs: &Merged,
) -> Result<(), String> {
    let mut src: Src = match replay_file {
        Some(path) => {
            let r = nn_recorder::Reader::open(std::path::Path::new(path))
                .map_err(|e| format!("cannot open recording {path}: {e}"))?;
            Src::Rec(r)
        }
        None => Src::Udp(UdpSource::open(cfg).map_err(|e| format!("cannot open UDP {}:{}: {e}", cfg.bind, cfg.port))?),
    };
    let mut rec_w = record_file
        .map(|p| {
            nn_recorder::Writer::create(std::path::Path::new(p))
                .map_err(|e| format!("cannot create recording {p}: {e}"))
        })
        .transpose()?;
    let (addr, hub) = Hub::listen(http).map_err(|e| format!("cannot bind dashboard on {http}: {e}"))?;
    let desc = match &src {
        Src::Udp(s) => format!("live on {}", s.local_addr()),
        Src::Rec(_) => format!("replaying {} at {}x", replay_file.unwrap(), speed),
    };
    eprintln!("nn-server: {desc} (receive-only)");
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
    if let Some(path) = db_file {
        hub.open_db(std::path::Path::new(path), &packs.packs.join(" + "))
            .map_err(|e| format!("cannot open db {path}: {e}"))?;
        eprintln!("  event store: {path}");
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
    if let Some(f) = users_file {
        let a = nn_server::auth::Auth::load(std::path::Path::new(f)).map_err(|e| format!("--users {f}: {e}"))?;
        eprintln!("  users: {f} ({} accounts)", a.len());
        hub.set_auth(std::sync::Arc::new(a));
    }
    let mut m = Monitor::with_packs(packs);
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
                        let j = hub.log("alert", &alert_json(e));
                        if recent.len() >= 100 {
                            recent.pop_front();
                        }
                        recent.push_back(j);
                    }
                    if let Some(sw) = &out.switch {
                        let switched = match sw {
                            Switch::Live => match UdpSource::open(cfg) {
                                Ok(s) => {
                                    src = Src::Udp(s);
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
                            m = Monitor::with_packs(packs);
                            prev_ents.clear();
                            recent.clear();
                            next_full = 0.0;
                            epoch = Instant::now();
                        }
                    }
                    hub.log("info", &info_json(now_secs(), &out.note));
                }
                Err(e) => {
                    hub.log("info", &info_json(now_secs(), &format!("command rejected: {e}")));
                }
            }
        }
        let errs_before = m.decode_errors;
        let next = match &mut src {
            Src::Udp(s) => s.recv().map_err(|e| format!("receive failed: {e}"))?,
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
                m.tick(now_secs())
            }
        };
        for e in &events {
            let j = hub.log("alert", &alert_json(e));
            if recent.len() >= 100 {
                recent.pop_front();
            }
            recent.push_back(j);
        }
        if t >= next_state {
            if t >= next_full {
                // Full frame every 30 s: also the snapshot new clients get.
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
            }
            next_state = t + 1.0;
        }
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
