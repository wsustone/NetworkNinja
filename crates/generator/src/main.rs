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
    --broadcast             Allow a broadcast destination address (255.255.255.255 or
                            a subnet's, e.g. 10.0.0.255; see nn-server interfaces)
    --iface NAME|IP         Send multicast out of this interface (default: OS choice)
    --ttl N                 Multicast TTL (default 1: stay on the local subnet)
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
    --siman-every SECS      Every SECS, the first site (as simulation manager) sends
                            the second a Create Entity, Action Request, Data Query
                            or Set Data in turn, and it answers (default off)
    --radio-every SECS      Every SECS, the next site's first vehicle talks for 2 s
                            on its radio (Transmitter, PCM Signals); every such
                            radio heartbeats Transmitter and Receiver (default off)
    --collision-every SECS  Two entities collide; both report it (default off)
    --damage-every SECS     An entity is damaged, then repaired 30 s later (default off)
    --de-every SECS         A 3 s directed-energy shot (default off)
    --bundle                Pack several PDUs per datagram
    --silent-when-frozen    Simulators stop sending while frozen (default: heartbeat with frozen bit)
    --seed N                RNG seed (default 1)

FAULTS (alerts must fire)          T defaults to a third of the duration
    --drop-heartbeat ID[@T] Entity goes silent without Remove Entity
    --clone-id ID[@T]       A second sender reuses the Entity ID
    --teleport ID[@T]       Entity jumps 20 km off its dead-reckoned path

PDU DEFECTS (ADR 0010 tiers S and E; a PDU of TYPE from the first site)
    --defect KIND:TYPE[@T]  KIND is short-pdu, count-overrun, padded-pdu,
                            wrong-family, truncated-pdu, bad-enum or
                            stop-heartbeat; TYPE a PDU type number
                            (count-overrun needs a count field, bad-enum an
                            enumerated one and is caught by serve --siso;
                            stop-heartbeat a type with a heartbeat, and
                            --all-types)

HANDSHAKE FAULTS (on the answering site; need --siman-every and 2+ sites)
    --no-response SITE[@T]  Site stops answering Simulation Management requests
    --wrong-ack SITE[@T]    Site's next Acknowledge carries the wrong flag
    --orphan-response SITE[@T]  Site sends an Action Response nobody asked for

RADIO FAULTS (by site; need --radio-every)
    --hot-mic SITE[@T]      Site's radio keys up and never sends a Signal
    --orphan-signal SITE[@T]  Site sends a Signal for a radio with no Transmitter
    --bad-signal SITE[@T]   Site's next Signal has the wrong Data Length
    --drop-transmitter SITE[@T]  Site's radio stops sending Transmitter PDUs
                            but keeps transmitting

LIFECYCLE FAULTS (ID is site:application:entity)
    --no-final-report ID[@T]  Remove Entity, then silence: no final Deactivated report
    --zombie ID[@T]         Remove Entity and a final report, then it keeps reporting
    --static-moving ID[@T]  Entity reports DR algorithm Static while it drives
    --type-change ID[@T]    Entity's type changes mid-life
    --orphan-update ID[@T]  Entity State Updates for ID+1000, never described in full

WARFARE FAULTS (on the next engagement; need --fire-every)
    --no-detonation T       The next Fire's Detonation never comes
    --detonation-mismatch T The next Detonation names another munition type
    --wrong-fire-type T     The next Fire's PDU Status says expendable (v7)
    --orphan-detonation T   A Detonation for an Event ID never fired, at T
    --all-warfare-faults    One of each (turns on --fire-every 10 if not set)

INTERACTION FAULTS (on the next interaction)
    --one-sided-collision T Only one party reports the next collision
    --duplicate-collision T One party reports the next collision twice
    --stale-appearance T    The next repair leaves the appearance damaged
    --eds-after-remove ID[@T]  An Entity Damage Status for a removed entity
    --de-dropout T          The next DE shot's DE Fires stop after the first
    --de-no-fire T          The next DE shot has no Fire PDU
    --all-interaction-faults  The above, but eds-after-remove (turns on the
                            three interactions every 10/40/20 s if not set)

CONTROLS (alerts must stay quiet)
    --remove ID[@T]         Clean Remove Entity, then silence
    --restart-port SITE[@T] Site's simulator restarts on a new source port
    --freeze-at T           Stop/Freeze the exercise
    --resume-at T           Start/Resume after a freeze

PRESETS
    --all-faults            One of each fault on site 1
    --all-controls          One of each control on site 2 / the exercise
    --all-defects           One of each PDU defect on site 1
    --all-handshake-faults  One of each handshake fault on site 2 (turns on
                            --siman-every 2 if it isn't set)
    --all-lifecycle-faults  One of each lifecycle fault on site 1, entities 4-8
    --all-radio-faults      One of each radio fault, one site each (needs 4
                            sites; turns on --radio-every 5 if it isn't set)

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
    multicast_if: Option<std::net::Ipv4Addr>,
    ttl: u32,
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
    let (mut multicast_if, mut ttl) = (None, 1u32);
    let mut pending: Vec<(EventKind, String)> = Vec::new();
    let (mut all_faults, mut all_controls, mut all_defects) = (false, false, false);
    let (mut all_handshake, mut all_radio, mut all_lifecycle) = (false, false, false);
    let (mut all_warfare, mut all_interaction) = (false, false);
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
            "--iface" => multicast_if = Some(nn_capture::iface::resolve(&val()?).map_err(|e| format!("--iface: {e}"))?),
            "--ttl" => ttl = val()?.parse().map_err(|e| format!("--ttl: {e}"))?,
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
            "--siman-every" => cfg.siman_every = Some(num(val()?)?),
            "--no-response" => pending.push((EventKind::NoResponse, val()?)),
            "--wrong-ack" => pending.push((EventKind::WrongAck, val()?)),
            "--orphan-response" => pending.push((EventKind::OrphanResponse, val()?)),
            "--all-handshake-faults" => all_handshake = true,
            "--radio-every" => cfg.radio_every = Some(num(val()?)?),
            "--hot-mic" => pending.push((EventKind::HotMic, val()?)),
            "--orphan-signal" => pending.push((EventKind::OrphanSignal, val()?)),
            "--bad-signal" => pending.push((EventKind::BadSignal, val()?)),
            "--drop-transmitter" => pending.push((EventKind::DropTransmitter, val()?)),
            "--all-radio-faults" => all_radio = true,
            "--no-final-report" => pending.push((EventKind::NoFinalReport, val()?)),
            "--zombie" => pending.push((EventKind::Zombie, val()?)),
            "--static-moving" => pending.push((EventKind::StaticMoving, val()?)),
            "--type-change" => pending.push((EventKind::TypeChange, val()?)),
            "--orphan-update" => pending.push((EventKind::OrphanUpdate, val()?)),
            "--all-lifecycle-faults" => all_lifecycle = true,
            "--no-detonation" => pending.push((EventKind::NoDetonation, format!("@{}", val()?))),
            "--detonation-mismatch" => pending.push((EventKind::DetonationMismatch, format!("@{}", val()?))),
            "--wrong-fire-type" => pending.push((EventKind::WrongFireType, format!("@{}", val()?))),
            "--orphan-detonation" => pending.push((EventKind::OrphanDetonation, format!("@{}", val()?))),
            "--all-warfare-faults" => all_warfare = true,
            "--collision-every" => cfg.collision_every = Some(num(val()?)?),
            "--damage-every" => cfg.damage_every = Some(num(val()?)?),
            "--de-every" => cfg.de_every = Some(num(val()?)?),
            "--one-sided-collision" => pending.push((EventKind::OneSidedCollision, format!("@{}", val()?))),
            "--duplicate-collision" => pending.push((EventKind::DuplicateCollision, format!("@{}", val()?))),
            "--stale-appearance" => pending.push((EventKind::StaleAppearance, format!("@{}", val()?))),
            "--eds-after-remove" => pending.push((EventKind::EdsAfterRemove, val()?)),
            "--de-dropout" => pending.push((EventKind::DeDropout, format!("@{}", val()?))),
            "--de-no-fire" => pending.push((EventKind::DeNoFire, format!("@{}", val()?))),
            "--all-interaction-faults" => all_interaction = true,
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

    if all_handshake {
        if cfg.sites < 2 {
            return Err("--all-handshake-faults needs at least 2 sites".into());
        }
        cfg.siman_every.get_or_insert(2.0);
        // Spread out so each fault's alert stands on its own.
        pending.push((EventKind::WrongAck, format!("{second}@{}", d * 0.15)));
        pending.push((EventKind::OrphanResponse, format!("{second}@{}", d * 0.30)));
        pending.push((EventKind::NoResponse, format!("{second}@{}", d * 0.60)));
    }
    if all_interaction {
        cfg.collision_every.get_or_insert(10.0);
        cfg.damage_every.get_or_insert(40.0);
        cfg.de_every.get_or_insert(20.0);
        for (i, kind) in [
            EventKind::OneSidedCollision,
            EventKind::DuplicateCollision,
            EventKind::StaleAppearance,
            EventKind::DeDropout,
            EventKind::DeNoFire,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.15 + 0.12 * i as f64))));
        }
    }
    if all_warfare {
        cfg.fire_every.get_or_insert(10.0);
        for (i, kind) in [
            EventKind::NoDetonation,
            EventKind::DetonationMismatch,
            EventKind::WrongFireType,
            EventKind::OrphanDetonation,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.2 + 0.15 * i as f64))));
        }
    }
    if all_lifecycle {
        if cfg.entities_per_site < 8 {
            return Err("--all-lifecycle-faults needs at least 8 entities per site".into());
        }
        for (n, kind) in [
            (4, EventKind::NoFinalReport),
            (5, EventKind::Zombie),
            (6, EventKind::StaticMoving),
            (7, EventKind::TypeChange),
            (8, EventKind::OrphanUpdate),
        ] {
            pending.push((kind, format!("{first}:{app}:{n}@{}", d * (0.15 + 0.05 * n as f64))));
        }
    }
    if all_radio {
        if cfg.sites < 4 {
            return Err("--all-radio-faults needs at least 4 sites".into());
        }
        cfg.radio_every.get_or_insert(5.0);
        let site = |n: u16| cfg.site_base + n;
        pending.push((EventKind::BadSignal, format!("{}@{}", site(0), d * 0.10)));
        pending.push((EventKind::HotMic, format!("{}@{}", site(1), d * 0.15)));
        pending.push((EventKind::DropTransmitter, format!("{}@{}", site(2), d * 0.20)));
        // Late, so the monitor has watched a full stationary timeout first.
        pending.push((EventKind::OrphanSignal, format!("{}@{}", site(3), d * 0.90)));
    }
    if all_defects {
        // One type each, so no fault hides behind another's repeat window.
        // Collision, Transmitter, Designator, Signal, EE, Receiver, IFF
        let types = [4, 25, 24, 26, 23, 27, 28];
        for (i, (kind, t)) in EventKind::DEFECTS.iter().zip(types).enumerate() {
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
        let kind = EventKind::defect(name).ok_or_else(|| format!("--defect: unknown kind '{name}'"))?;
        let pdu_type: u8 = t.parse().map_err(|e| format!("--defect: bad PDU type '{t}': {e}"))?;
        let layout = nn_decode::structure::layout(pdu_type)
            .ok_or_else(|| format!("--defect: {pdu_type} is not a PDU type (1-72)"))?;
        if kind == EventKind::CountOverrun && layout.counts.is_empty() {
            return Err(format!("--defect: {} has no count field to overrun", layout.name));
        }
        if kind == EventKind::StopHeartbeat && !nn_decode::heartbeat::of(pdu_type).is_some_and(|h| !h.own_rule) {
            return Err(format!("--defect: {} has no heartbeat to stop", layout.name));
        }
        if kind == EventKind::BadEnum && nn_decode::fields::enum_fields_of(pdu_type).next().is_none() {
            return Err(format!(
                "--defect: {} has no enumerated field in the table",
                layout.name
            ));
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
            EventKind::Freeze
            | EventKind::Resume
            | EventKind::NoDetonation
            | EventKind::DetonationMismatch
            | EventKind::WrongFireType
            | EventKind::OrphanDetonation
            | EventKind::OneSidedCollision
            | EventKind::DuplicateCollision
            | EventKind::StaleAppearance
            | EventKind::DeDropout
            | EventKind::DeNoFire => Target::Exercise,
            EventKind::RestartPort
            | EventKind::NoResponse
            | EventKind::WrongAck
            | EventKind::OrphanResponse
            | EventKind::HotMic
            | EventKind::OrphanSignal
            | EventKind::BadSignal
            | EventKind::DropTransmitter => {
                let site: u16 = what.parse().map_err(|e| format!("bad site '{what}': {e}"))?;
                if !(cfg.site_base as u32..=last_site).contains(&(site as u32)) {
                    return Err(format!(
                        "site {site} is not generated (sites {}..={last_site})",
                        cfg.site_base
                    ));
                }
                Target::Site(site)
            }
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
        multicast_if,
        ttl,
        pcap,
        truth,
    })
}

/// Sends datagrams in real time, one UDP socket per simulated sender.
struct LiveSink {
    target: SocketAddrV4,
    broadcast: bool,
    multicast_if: Option<std::net::Ipv4Addr>,
    ttl: u32,
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
            let s = nn_capture::sender_socket(self.broadcast, self.multicast_if, self.ttl)?;
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
                multicast_if: opts.multicast_if,
                ttl: opts.ttl,
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
