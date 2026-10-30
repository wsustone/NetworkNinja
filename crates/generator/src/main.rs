//! nn-generator: synthetic DIS traffic with fault injection.

use nn_capture::PcapWriter;
use nn_decode::EntityId;
use nn_generator::{profile, run, Config, Event, EventKind, Sender, Sink, Target, PROFILES};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufWriter};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime};

const USAGE: &str = "\
nn-generator: synthetic DIS traffic with fault injection

USAGE:
    nn-generator [OPTIONS]

OUTPUT
    --target IP:PORT        Destination (default 127.0.0.1:3000)
    --broadcast             Allow a broadcast destination address
    --pcap FILE             Write a pcap file instead of sending; runs as fast as possible
    --truth FILE            Write ground-truth JSON here (default: print to stdout at the end)

VENDOR PROFILE (legitimate variation; applied first, other flags override)
    --profile NAME          standard (default), legacy, body-axis or gateway; see
                            --list-profiles. Run several generators with different
                            profiles and site ranges to mimic a multi-vendor exercise
    --list-profiles         Print the profiles and exit

EXERCISE
    --duration SECS         Length of the run (default 60)
    --version 6|7           DIS protocol version (default 7)
    --exercise N            Exercise ID (default 1)
    --sites N               Number of sites, one simulator each (default 2)
    --site-base N           First site number (default 1). Run several generators
                            side by side with non-overlapping ranges, e.g.
                            --site-base 1 --sites 3 and --site-base 4 --sites 3
    --application N         Simulation application number (default 1)
    --entities N            Entities per site (default 10)
    --heartbeat SECS        Entity State heartbeat (default 5)
    --dr-threshold M        Dead-reckoning error that triggers an update (default 1.0)
    --fire-every SECS       Fire + Detonation every N seconds (default off)
    --all-types SECS        Every SECS, one minimal valid PDU of each of the other
                            66 PDU types, from the first site (default off)
    --bundle                Pack several PDUs per datagram
    --silent-when-frozen    Simulators stop sending while frozen (default: heartbeat with frozen bit)
    --seed N                RNG seed (default 1)

FAULTS (alerts must fire)          T defaults to a third of the duration
    --drop-heartbeat ID[@T] Entity goes silent without Remove Entity
    --clone-id ID[@T]       A second sender reuses the Entity ID
    --teleport ID[@T]       Entity jumps 20 km off its dead-reckoned path

STRUCTURAL FAULTS (ADR 0010 tier S; a PDU of TYPE from the first site)
    --defect KIND:TYPE[@T]  KIND is short-pdu, count-overrun, padded-pdu,
                            wrong-family or truncated-pdu; TYPE a PDU type number
                            (count-overrun needs a type with a count field)

CONTROLS (alerts must stay quiet)
    --remove ID[@T]         Clean Remove Entity, then silence
    --restart-port SITE[@T] Site's simulator restarts on a new source port
    --freeze-at T           Stop/Freeze the exercise
    --resume-at T           Start/Resume after a freeze

PRESETS
    --all-faults            One of each fault on site 1
    --all-controls          One of each control on site 2 / the exercise
    --all-defects           One of each structural fault on site 1

ID is site:application:entity, e.g. 1:1:3. Synthetic simulators use application 1.
";

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nn-generator: {e}");
            ExitCode::FAILURE
        }
    }
}

struct Options {
    cfg: Config,
    target: SocketAddrV4,
    broadcast: bool,
    pcap: Option<String>,
    truth: Option<String>,
}

fn parse_args() -> Result<Options, String> {
    let mut cfg = Config {
        start_time: SystemTime::now(),
        ..Default::default()
    };
    let mut target = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3000);
    let (mut broadcast, mut pcap, mut truth) = (false, None, None);
    let mut pending: Vec<(EventKind, String)> = Vec::new();
    let (mut all_faults, mut all_controls, mut all_defects) = (false, false, false);
    let mut defects: Vec<String> = Vec::new();

    // The profile sets defaults that explicit flags then override, wherever
    // it appears on the command line.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if let Some(i) = argv.iter().position(|a| a == "--profile") {
        let name = argv.get(i + 1).ok_or("--profile needs a value")?;
        let p = profile(name).ok_or_else(|| format!("unknown profile '{name}' (see --list-profiles)"))?;
        p.apply(&mut cfg);
    }
    let mut args = argv.into_iter();
    while let Some(a) = args.next() {
        let mut val = || args.next().ok_or_else(|| format!("{a} needs a value"));
        let num = |v: String| v.parse::<f64>().map_err(|e| format!("{a}: {e}"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "--profile" => {
                val()?; // applied above
            }
            "--list-profiles" => {
                for p in &PROFILES {
                    println!("{:<10} {}", p.name, p.description);
                }
                std::process::exit(0);
            }
            "--target" => target = val()?.parse().map_err(|e| format!("--target: {e}"))?,
            "--broadcast" => broadcast = true,
            "--pcap" => pcap = Some(val()?),
            "--truth" => truth = Some(val()?),
            "--duration" => cfg.duration = num(val()?)?,
            "--version" => {
                cfg.version = val()?.parse().map_err(|e| format!("--version: {e}"))?;
                if !matches!(cfg.version, 6 | 7) {
                    return Err("--version must be 6 or 7".into());
                }
            }
            "--exercise" => cfg.exercise = val()?.parse().map_err(|e| format!("--exercise: {e}"))?,
            "--sites" => cfg.sites = val()?.parse().map_err(|e| format!("--sites: {e}"))?,
            "--site-base" => cfg.site_base = val()?.parse().map_err(|e| format!("--site-base: {e}"))?,
            "--application" => cfg.application = val()?.parse().map_err(|e| format!("--application: {e}"))?,
            "--entities" => cfg.entities_per_site = val()?.parse().map_err(|e| format!("--entities: {e}"))?,
            "--heartbeat" => cfg.heartbeat = num(val()?)?,
            "--dr-threshold" => cfg.dr_threshold = num(val()?)?,
            "--fire-every" => cfg.fire_every = Some(num(val()?)?),
            "--all-types" => cfg.all_types = Some(num(val()?)?),
            "--bundle" => cfg.bundle = true,
            "--silent-when-frozen" => cfg.silent_when_frozen = true,
            "--seed" => cfg.seed = val()?.parse().map_err(|e| format!("--seed: {e}"))?,
            "--drop-heartbeat" => pending.push((EventKind::DropHeartbeat, val()?)),
            "--clone-id" => pending.push((EventKind::CloneId, val()?)),
            "--teleport" => pending.push((EventKind::Teleport, val()?)),
            "--remove" => pending.push((EventKind::Remove, val()?)),
            "--restart-port" => pending.push((EventKind::RestartPort, val()?)),
            "--freeze-at" => pending.push((EventKind::Freeze, format!("@{}", val()?))),
            "--resume-at" => pending.push((EventKind::Resume, format!("@{}", val()?))),
            "--all-faults" => all_faults = true,
            "--all-controls" => all_controls = true,
            "--defect" => defects.push(val()?),
            "--all-defects" => all_defects = true,
            other => return Err(format!("unknown option '{other}' (see --help)")),
        }
    }

    let d = cfg.duration;
    // Real site and application numbers: 0 and 65535 are DIS wildcards.
    if cfg.site_base == 0 || cfg.application == 0 || cfg.application == 0xffff {
        return Err("--site-base and --application must be 1..65534".into());
    }
    let last_site = cfg.site_base as u32 + cfg.sites as u32 - 1;
    if cfg.sites == 0 || last_site >= 0xffff {
        return Err(format!("sites {}..={last_site} run past 65534", cfg.site_base));
    }
    // Presets: faults on the first site, controls on the second.
    let (first, second, app) = (cfg.site_base, cfg.site_base + 1, cfg.application);
    if all_faults {
        pending.push((EventKind::DropHeartbeat, format!("{first}:{app}:1@{}", d * 0.25)));
        pending.push((EventKind::CloneId, format!("{first}:{app}:2@{}", d * 0.35)));
        pending.push((EventKind::Teleport, format!("{first}:{app}:3@{}", d * 0.45)));
    }
    if all_controls {
        if cfg.sites < 2 {
            return Err("--all-controls needs at least 2 sites".into());
        }
        pending.push((EventKind::Remove, format!("{second}:{app}:1@{}", d * 0.25)));
        pending.push((EventKind::RestartPort, format!("{second}@{}", d * 0.35)));
        pending.push((EventKind::Freeze, format!("@{}", d * 0.55)));
        pending.push((EventKind::Resume, format!("@{}", d * 0.70)));
    }

    if all_defects {
        // One type each, so no fault hides behind another's repeat window.
        let types = [4, 25, 24, 26, 23]; // Collision, Transmitter, Designator, Signal, EE
        for (i, (kind, t)) in EventKind::STRUCTURAL.iter().zip(types).enumerate() {
            defects.push(format!("{}:{t}@{}", kind.name(), d * (0.20 + 0.05 * i as f64)));
        }
    }
    for spec in defects {
        let (what, at) = match spec.split_once('@') {
            Some((w, t)) => (w, t.parse::<f64>().map_err(|e| format!("bad time in '{spec}': {e}"))?),
            None => (spec.as_str(), d / 3.0),
        };
        let (name, t) = what
            .split_once(':')
            .ok_or_else(|| format!("--defect '{spec}': expected KIND:TYPE[@T]"))?;
        let kind = EventKind::structural(name).ok_or_else(|| format!("--defect: unknown kind '{name}'"))?;
        let pdu_type: u8 = t.parse().map_err(|e| format!("--defect: bad PDU type '{t}': {e}"))?;
        let layout = nn_decode::structure::layout(pdu_type)
            .ok_or_else(|| format!("--defect: {pdu_type} is not a PDU type (1-72)"))?;
        if kind == EventKind::CountOverrun && layout.counts.is_empty() {
            return Err(format!("--defect: {} has no count field to overrun", layout.name));
        }
        if !(0.0..=d).contains(&at) {
            return Err(format!("time {at} for {} is outside the run (0..{d})", kind.name()));
        }
        cfg.events.push(Event {
            kind,
            target: Target::Pdu { site: first, pdu_type },
            at,
        });
    }

    for (kind, spec) in pending {
        let (what, at) = match spec.split_once('@') {
            Some((w, t)) => (w, t.parse::<f64>().map_err(|e| format!("bad time in '{spec}': {e}"))?),
            None => (spec.as_str(), d / 3.0),
        };
        let target = match kind {
            EventKind::Freeze | EventKind::Resume => Target::Exercise,
            EventKind::RestartPort => Target::Site(what.parse().map_err(|e| format!("bad site '{what}': {e}"))?),
            _ => {
                let id: EntityId = what.parse()?;
                if !(cfg.site_base as u32..=last_site).contains(&(id.site as u32))
                    || id.application != cfg.application
                    || id.entity == 0
                    || id.entity > cfg.entities_per_site
                {
                    return Err(format!(
                        "{id} is not a generated entity (sites {}..={last_site}, app {}, entities 1..={})",
                        cfg.site_base, cfg.application, cfg.entities_per_site
                    ));
                }
                Target::Entity(id)
            }
        };
        if !(0.0..=d).contains(&at) {
            return Err(format!("time {at} for {} is outside the run (0..{d})", kind.name()));
        }
        cfg.events.push(Event { kind, target, at });
    }
    Ok(Options {
        cfg,
        target,
        broadcast,
        pcap,
        truth,
    })
}

/// Sends datagrams in real time, one UDP socket per simulated sender.
struct LiveSink {
    target: SocketAddrV4,
    broadcast: bool,
    start: Instant,
    sockets: HashMap<Sender, UdpSocket>,
    last_report: f64,
    sent: u64,
}

impl Sink for LiveSink {
    fn emit(&mut self, t: f64, sender: Sender, datagram: &[u8]) -> io::Result<()> {
        let due = self.start + Duration::from_secs_f64(t);
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
        if !self.sockets.contains_key(&sender) {
            let s = UdpSocket::bind("0.0.0.0:0")?;
            s.set_broadcast(self.broadcast)?;
            eprintln!(
                "  sender site {}{} → source port {}",
                sender.site,
                if sender.rogue {
                    " (rogue clone)"
                } else if sender.relay {
                    " (gateway copy)"
                } else if sender.generation > 0 {
                    " (restarted)"
                } else {
                    ""
                },
                s.local_addr()?.port()
            );
            self.sockets.insert(sender, s);
        }
        self.sockets[&sender].send_to(datagram, self.target)?;
        self.sent += 1;
        if t - self.last_report >= 10.0 {
            self.last_report = t;
            eprintln!("  t={t:>5.0}s  datagrams sent: {}", self.sent);
        }
        Ok(())
    }
}

/// Writes datagrams to a pcap with synthetic per-sender source addresses.
struct PcapSink {
    writer: PcapWriter<BufWriter<File>>,
    target: SocketAddrV4,
    start: SystemTime,
}

impl PcapSink {
    fn source(sender: Sender) -> SocketAddrV4 {
        let host = sender.host();
        let ip = Ipv4Addr::new(10, (sender.site >> 8) as u8, sender.site as u8, host);
        SocketAddrV4::new(ip, 40_000 + sender.generation)
    }
}

impl Sink for PcapSink {
    fn emit(&mut self, t: f64, sender: Sender, datagram: &[u8]) -> io::Result<()> {
        let at = self.start + Duration::from_secs_f64(t);
        self.writer.write_udp(at, Self::source(sender), self.target, datagram)
    }
}

fn real_main() -> Result<(), String> {
    let opts = parse_args()?;
    let cfg = &opts.cfg;
    if opts.target.ip().is_broadcast() && !opts.broadcast && opts.pcap.is_none() {
        return Err("target is a broadcast address; add --broadcast".into());
    }
    eprintln!(
        "nn-generator: DIS v{}, exercise {}, {} sites × {} entities, {} s{}",
        cfg.version,
        cfg.exercise,
        cfg.sites,
        cfg.entities_per_site,
        cfg.duration,
        if cfg.bundle { ", bundled" } else { "" }
    );
    for e in &cfg.events {
        eprintln!(
            "  scheduled {:<14} {:<12} at {:>6.1} s",
            e.kind.name(),
            e.target.to_string(),
            e.at
        );
    }

    let truth = match &opts.pcap {
        Some(path) => {
            let file = File::create(path).map_err(|e| format!("{path}: {e}"))?;
            let writer = PcapWriter::new(BufWriter::new(file)).map_err(|e| e.to_string())?;
            let mut sink = PcapSink {
                writer,
                target: opts.target,
                start: cfg.start_time,
            };
            let truth = run(cfg, &mut sink).map_err(|e| e.to_string())?;
            sink.writer.flush().map_err(|e| e.to_string())?;
            eprintln!("  wrote {} datagrams to {path}", truth.datagrams);
            truth
        }
        None => {
            eprintln!("  sending to {} in real time (Ctrl-C to stop)", opts.target);
            let mut sink = LiveSink {
                target: opts.target,
                broadcast: opts.broadcast,
                start: Instant::now(),
                sockets: HashMap::new(),
                last_report: 0.0,
                sent: 0,
            };
            run(cfg, &mut sink).map_err(|e| format!("send failed: {e}"))?
        }
    };

    let json = truth.to_json();
    match &opts.truth {
        Some(path) => std::fs::write(path, json).map_err(|e| format!("{path}: {e}"))?,
        None => print!("{json}"),
    }
    Ok(())
}
