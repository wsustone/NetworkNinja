//! nn-server: milestone 1 console tool.
//!
//! `listen` decodes live DIS traffic from a receive-only UDP socket;
//! `replay` decodes a pcap file. Both print one line per PDU (unless
//! --quiet) and a running summary.

use nn_capture::{Datagram, PcapReader, UdpConfig, UdpSource};
use nn_decode::{Pdu, PduBody};
use nn_server::{describe, Tally};
use std::fs::File;
use std::io::BufReader;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

const USAGE: &str = "\
nn-server: decode DIS traffic to the console (NetworkNinja milestone 1)

USAGE:
    nn-server listen [OPTIONS]        Receive live traffic (receive-only)
    nn-server replay FILE [OPTIONS]   Decode a pcap file

LISTEN OPTIONS
    --port N              UDP port (default 3000)
    --bind IP             Local address (default 0.0.0.0, needed for broadcast/multicast)
    --multicast GROUP     Join an IPv4 multicast group (repeatable)
    --iface IP            Interface address for multicast joins (default: OS choice)
    --duration SECS       Stop after this long (default: run until killed)

REPLAY OPTIONS
    --speed X             Replay at X times real time (default: as fast as possible)

COMMON OPTIONS (display filters; totals always count everything)
    --exercise N          Only show PDUs from this exercise
    --site N              Only show PDUs whose entity/originator is on this site
    --type NAME           Only show this PDU type, e.g. EntityState (repeatable)
    --quiet               No per-PDU lines, summaries only
    --every SECS          Print a summary every N seconds (default 10)
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
    let mut common = Common { filter: Filter::default(), quiet: false, every: 10.0 };
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or_else(|| format!("{a} needs a value"));
        let bad = |e: &dyn std::fmt::Display| format!("{a}: {e}");
        match a.as_str() {
            "--port" => udp.port = val()?.parse().map_err(|e| bad(&e))?,
            "--bind" => udp.bind = val()?.parse().map_err(|e| bad(&e))?,
            "--multicast" => udp.multicast_groups.push(val()?.parse::<Ipv4Addr>().map_err(|e| bad(&e))?),
            "--iface" => udp.multicast_interface = val()?.parse().map_err(|e| bad(&e))?,
            "--duration" => duration = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--speed" => speed = Some(val()?.parse::<f64>().map_err(|e| bad(&e))?),
            "--exercise" => common.filter.exercise = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--site" => common.filter.site = Some(val()?.parse().map_err(|e| bad(&e))?),
            "--type" => common.filter.types.push(val()?),
            "--quiet" => common.quiet = true,
            "--every" => common.every = val()?.parse().map_err(|e| bad(&e))?,
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }

    match command.as_str() {
        "listen" => listen(&udp, duration, &common),
        "replay" => replay(file.as_deref().unwrap(), speed, &common),
        other => Err(format!("unknown command '{other}' (expected listen or replay)")),
    }
}

fn show(tally: &mut Tally, d: &Datagram, t: f64, common: &Common) {
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
}

fn listen(cfg: &UdpConfig, duration: Option<f64>, common: &Common) -> Result<(), String> {
    let mut src = UdpSource::open(cfg).map_err(|e| format!("cannot open UDP {}:{}: {e}", cfg.bind, cfg.port))?;
    eprintln!("nn-server: listening on {} (receive-only)", src.local_addr());
    for g in &cfg.multicast_groups {
        eprintln!("  joined multicast {g} on {}", cfg.multicast_interface);
    }
    let start = Instant::now();
    let mut tally = Tally::default();
    let mut next_summary = common.every;
    loop {
        let t = start.elapsed().as_secs_f64();
        if duration.is_some_and(|d| t >= d) {
            break;
        }
        if t >= next_summary {
            eprint!("--- {t:.0} s: {}", tally.summary());
            next_summary += common.every;
        }
        if let Some(d) = src.recv().map_err(|e| format!("receive failed: {e}"))? {
            show(&mut tally, &d, start.elapsed().as_secs_f64(), common);
        }
    }
    eprint!("=== final: {}", tally.summary());
    Ok(())
}

fn replay(path: &str, speed: Option<f64>, common: &Common) -> Result<(), String> {
    let f = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut reader = PcapReader::new(BufReader::new(f)).map_err(|e| format!("{path}: {e}"))?;
    eprintln!("nn-server: replaying {path}{}", speed.map(|s| format!(" at {s}x")).unwrap_or_default());
    let mut tally = Tally::default();
    let wall_start = Instant::now();
    let mut first: Option<SystemTime> = None;
    let mut next_summary = common.every;
    while let Some(d) = reader.next_datagram().map_err(|e| format!("{path}: {e}"))? {
        let t0 = *first.get_or_insert(d.received_at);
        let t = d.received_at.duration_since(t0).unwrap_or_default().as_secs_f64();
        if let Some(s) = speed.filter(|s| *s > 0.0) {
            let due = wall_start + Duration::from_secs_f64(t / s);
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
        if t >= next_summary {
            eprint!("--- {t:.0} s: {}", tally.summary());
            next_summary += common.every;
        }
        show(&mut tally, &d, t, common);
    }
    let st = reader.stats;
    eprint!("=== final: {}", tally.summary());
    eprintln!(
        "  pcap: {} records, {} UDP, {} non-UDP, {} fragments, {} truncated",
        st.records, st.udp_datagrams, st.not_ipv4_udp, st.fragments, st.truncated
    );
    Ok(())
}
