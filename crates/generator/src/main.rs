//! nn-generator: synthetic DIS traffic with fault injection.

use nn_capture::PcapWriter;
use nn_generator::{profile, run, Config, EventKind, Sender, Sink, PROFILES};
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
    --emission-every SECS   An entity's radar emits for 30 s, tracking another (default off)
    --designator-every SECS An entity lases another for 30 s (default off)
    --logistics-every SECS  A resupply or repair between site 1 and another site
                            (alternating; default off)
    --aggregate-every SECS  A platoon aggregate on site 1 (Aggregate State every
                            30 s), and an IsPartOf every SECS (default off)
    --transfer-every SECS   An entity's owner pushes it to another site's simulator
                            (Transfer Ownership; needs 2 sites; default off)
    --iff-every SECS        Site 1's first entity carries a Mark XIIA transponder
                            whose Mode 3/A code changes every SECS (default off)
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
    --mine-fired T          The next Fire fires a mine (munition category Fixed)
    --impact-miss T         The next Detonation claims an entity impact 2 km off
    --all-warfare-faults    One of each (turns on --fire-every 10 if not set)

INTERACTION FAULTS (on the next interaction)
    --one-sided-collision T Only one party reports the next collision
    --duplicate-collision T One party reports the next collision twice
    --stale-appearance T    The next repair leaves the appearance damaged
    --eds-after-remove ID[@T]  An Entity Damage Status for a removed entity
    --de-dropout T          The next DE shot's DE Fires stop after the first
    --de-no-fire T          The next DE shot has no Fire PDU
    --still-collision T     The next collision is between two parked entities
                            (adds one parked entity per site if there are none)
    --bad-de-record T       The next DE shot's DE Fire carries a damage record
    --bad-attribute T       An Attribute PDU whose records don't match its master type
    --missing-extension T   A Comment PDU flagged as coupled, with no Attribute PDU (v7)
    --all-interaction-faults  The above, but eds-after-remove (turns on the
                            three interactions every 10/40/20 s if not set)

EMISSION FAULTS (on the next emitter; need --emission-every)
    --emitter-dropout T     Its EE PDUs stop with the beam still on
    --emitter-rename T      Its Emitter Name changes after the first report
    --bad-emitter-enums T   Its Emitter Name and Beam Function aren't SISO values (serve --siso)
    --reserved-beam T       Its beam is numbered NO_BEAM (0)
    --dense-targets T       High Density Track/Jam selected, target still listed
    --half-pulsed T         A PRF with no pulse width
    --no-site-target T      Its Track/Jam target has site 0
    --repeat-deactivated T  Its beam is reported Deactivated twice
    --destroyed-emitting T  Its entity is destroyed and keeps emitting
    --all-emission-faults   One of each (turns on --emission-every 40 if not set)

DESIGNATOR FAULTS (on the next designation; need --designator-every)
    --spot-offset T         Its spot is on no entity but has an offset
    --unknown-designated T  It designates an entity that doesn't exist
    --target-gone T         Its target is deactivated; it stays on
    --designator-gone T     Its entity is deactivated; it stops without Power 0
    --all-designator-faults One of each (turns on --designator-every 30 if not set)

IFF FAULTS (on the transponder; need --iff-every)
    --iff-missing-layer T   The next PDU leaves out Layer 3 (Mode 5)
    --iff-layer-bits T      The next PDU's Information Layers also claim Layer 5
    --iff-layer-order T     The next PDU sends Layer 4 before Layer 3
    --iff-empty-layer2 T    The next Layer 2 has no Fundamental Parameter record
    --iff-unflagged-change T
                            The Mode 3/A code changes, Change Indicator clear
    --iff-heartbeat-unflagged T
                            A change, then a heartbeat that clears the flag
    --iff-mode-mismatch T   The next PDU says System On with System Mode Off
    --iff-destroyed-on T    Its entity is destroyed; the transponder stays on
    --all-iff-faults        One of each (turns on --iff-every 60 if not set)

LOGISTICS FAULTS (script the next conversation; need --logistics-every)
    --logistics-no-offer T  The next resupply request gets no offer (or cancel) from its supplier
    --logistics-no-receipt T
                            The next resupply offer is never taken or cancelled
    --received-more T       The next resupply receipt takes more than was offered
    --no-repair-response T  The next completed repair gets no Repair Response
    --repair-cancel-result T
                            The next repair is cancelled by its supplier, answered as finished
    --supplies-on-repair T  The next repair request lists supplies
    --unsolicited-offer T   Supplies offered to an entity that didn't ask
    --orphan-received T     Supplies received with no offer
    --unrequested-repair T  A repair reported that nobody requested
    --orphan-repair-response T
                            A Repair Response to no Repair Complete
    --unknown-supplier T    A service request to an entity that doesn't exist
    --all-logistics-faults  One of each (turns on --logistics-every 20 if not set)

TRANSFER FAULTS (script the next transfer; need --transfer-every)
    --transfer-lingering T  The old owner keeps reporting the next transferred entity
    --transfer-reliability T
                            The next TO PDU asks for Acknowledged service
    --transfer-indicator T  The next new owner leaves the Transferred Entity Indicator clear
    --transfer-attributes T The next new owner changes the entity's marking
    --transfer-no-report T  The next new owner sends no ownership Event Report
    --transfer-concurrent T A second TO for the next entity, to another simulation, while the first is open
    --transfer-inactive T   The next transfer is of an entity just deactivated
    --transfer-stalled T    The next transfer gets no answer and nobody cancels it
    --all-transfer-faults   One of each (turns on --transfer-every 25 if not set)

HEADER FAULTS (a site's simulator)
    --timestamp-flip SITE[@T]
                            It switches between absolute and relative timestamps
    --timestamp-backwards SITE[@T]
                            Its clock steps back 10 s
    --clock-skew SITE[@T]   Its clock runs 30 s ahead
    --status-bits SITE[@T]  Its next Entity State sets an undefined PDU Status bit
    --exercise-switch SITE[@T]
                            It sends one PDU (a Comment) with the next exercise ID
    --all-header-faults     One of each, on the first site

ENTITY MANAGEMENT FAULTS (need --aggregate-every)
    --aggregate-stale-member T
                            The aggregate's first member is removed and stays listed
    --aggregate-unknown-member T
                            The next Aggregate State lists an entity that doesn't exist
    --aggregate-stale-subaggregate T
                            The aggregate lists a subaggregate that never reports
    --aggregate-appearances T
                            The next Aggregate State has more appearance records than entities
    --part-of-unknown T     The next IsPartOf names a part that doesn't exist
    --part-of-range-bearing T
                            The next IsPartOf gives range and bearing with a third component
    --part-of-type T        The next IsPartOf gives the wrong Part Type
    --all-aggregate-faults  One of each (turns on --aggregate-every 45 if not set)

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
    let (mut all_warfare, mut all_interaction, mut all_emission) = (false, false, false);
    let mut all_designator = false;
    let mut all_iff = false;
    let mut all_logistics = false;
    let mut all_transfer = false;
    let mut all_header = false;
    let mut all_aggregate = false;
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
            "--mine-fired" => pending.push((EventKind::MineFired, format!("@{}", val()?))),
            "--impact-miss" => pending.push((EventKind::ImpactMiss, format!("@{}", val()?))),
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
            "--still-collision" => {
                cfg.parked_per_site = cfg.parked_per_site.max(1);
                pending.push((EventKind::StillCollision, format!("@{}", val()?)))
            }
            "--bad-de-record" => pending.push((EventKind::BadDeRecord, format!("@{}", val()?))),
            "--bad-attribute" => pending.push((EventKind::BadAttribute, format!("@{}", val()?))),
            "--missing-extension" => pending.push((EventKind::MissingExtension, format!("@{}", val()?))),
            "--all-interaction-faults" => all_interaction = true,
            "--emission-every" => cfg.emission_every = Some(num(val()?)?),
            "--emitter-dropout" => pending.push((EventKind::EmitterDropout, format!("@{}", val()?))),
            "--emitter-rename" => pending.push((EventKind::EmitterRename, format!("@{}", val()?))),
            "--bad-emitter-enums" => pending.push((EventKind::BadEmitterEnums, format!("@{}", val()?))),
            "--reserved-beam" => pending.push((EventKind::ReservedBeam, format!("@{}", val()?))),
            "--dense-targets" => pending.push((EventKind::DenseTargets, format!("@{}", val()?))),
            "--half-pulsed" => pending.push((EventKind::HalfPulsed, format!("@{}", val()?))),
            "--no-site-target" => pending.push((EventKind::NoSiteTarget, format!("@{}", val()?))),
            "--repeat-deactivated" => pending.push((EventKind::RepeatDeactivated, format!("@{}", val()?))),
            "--destroyed-emitting" => pending.push((EventKind::DestroyedEmitting, format!("@{}", val()?))),
            "--all-emission-faults" => all_emission = true,
            "--designator-every" => cfg.designator_every = Some(num(val()?)?),
            "--spot-offset" => pending.push((EventKind::SpotOffset, format!("@{}", val()?))),
            "--unknown-designated" => pending.push((EventKind::UnknownDesignated, format!("@{}", val()?))),
            "--target-gone" => pending.push((EventKind::TargetGone, format!("@{}", val()?))),
            "--designator-gone" => pending.push((EventKind::DesignatorGone, format!("@{}", val()?))),
            "--all-designator-faults" => all_designator = true,
            "--iff-every" => cfg.iff_every = Some(num(val()?)?),
            "--iff-missing-layer" => pending.push((EventKind::IffMissingLayer, format!("@{}", val()?))),
            "--iff-layer-bits" => pending.push((EventKind::IffLayerBits, format!("@{}", val()?))),
            "--iff-layer-order" => pending.push((EventKind::IffLayerOrder, format!("@{}", val()?))),
            "--iff-empty-layer2" => pending.push((EventKind::IffEmptyLayer2, format!("@{}", val()?))),
            "--iff-unflagged-change" => pending.push((EventKind::IffUnflaggedChange, format!("@{}", val()?))),
            "--iff-heartbeat-unflagged" => pending.push((EventKind::IffHeartbeatUnflagged, format!("@{}", val()?))),
            "--iff-mode-mismatch" => pending.push((EventKind::IffModeMismatch, format!("@{}", val()?))),
            "--iff-destroyed-on" => pending.push((EventKind::IffDestroyedOn, format!("@{}", val()?))),
            "--all-iff-faults" => all_iff = true,
            "--logistics-every" => cfg.logistics_every = Some(num(val()?)?),
            "--logistics-no-offer" => pending.push((EventKind::LogisticsNoOffer, format!("@{}", val()?))),
            "--logistics-no-receipt" => pending.push((EventKind::LogisticsNoReceipt, format!("@{}", val()?))),
            "--received-more" => pending.push((EventKind::ReceivedMore, format!("@{}", val()?))),
            "--no-repair-response" => pending.push((EventKind::NoRepairResponse, format!("@{}", val()?))),
            "--repair-cancel-result" => pending.push((EventKind::RepairCancelResult, format!("@{}", val()?))),
            "--supplies-on-repair" => pending.push((EventKind::SuppliesOnRepair, format!("@{}", val()?))),
            "--unsolicited-offer" => pending.push((EventKind::UnsolicitedOffer, format!("@{}", val()?))),
            "--orphan-received" => pending.push((EventKind::OrphanReceived, format!("@{}", val()?))),
            "--unrequested-repair" => pending.push((EventKind::UnrequestedRepair, format!("@{}", val()?))),
            "--orphan-repair-response" => pending.push((EventKind::OrphanRepairResponse, format!("@{}", val()?))),
            "--unknown-supplier" => pending.push((EventKind::UnknownSupplier, format!("@{}", val()?))),
            "--all-logistics-faults" => all_logistics = true,
            "--transfer-every" => cfg.transfer_every = Some(num(val()?)?),
            "--transfer-lingering" => pending.push((EventKind::TransferLingering, format!("@{}", val()?))),
            "--transfer-reliability" => pending.push((EventKind::TransferReliability, format!("@{}", val()?))),
            "--transfer-indicator" => pending.push((EventKind::TransferIndicator, format!("@{}", val()?))),
            "--transfer-attributes" => pending.push((EventKind::TransferAttributes, format!("@{}", val()?))),
            "--transfer-no-report" => pending.push((EventKind::TransferNoReport, format!("@{}", val()?))),
            "--transfer-concurrent" => pending.push((EventKind::TransferConcurrent, format!("@{}", val()?))),
            "--transfer-inactive" => pending.push((EventKind::TransferInactive, format!("@{}", val()?))),
            "--transfer-stalled" => pending.push((EventKind::TransferStalled, format!("@{}", val()?))),
            "--all-transfer-faults" => all_transfer = true,
            "--timestamp-flip" => pending.push((EventKind::TimestampFlip, val()?)),
            "--timestamp-backwards" => pending.push((EventKind::TimestampBackwards, val()?)),
            "--clock-skew" => pending.push((EventKind::ClockSkew, val()?)),
            "--status-bits" => pending.push((EventKind::StatusBits, val()?)),
            "--exercise-switch" => pending.push((EventKind::ExerciseSwitch, val()?)),
            "--all-header-faults" => all_header = true,
            "--aggregate-every" => cfg.aggregate_every = Some(num(val()?)?),
            "--aggregate-stale-member" => pending.push((EventKind::AggregateStaleMember, format!("@{}", val()?))),
            "--aggregate-unknown-member" => pending.push((EventKind::AggregateUnknownMember, format!("@{}", val()?))),
            "--aggregate-stale-subaggregate" => {
                pending.push((EventKind::AggregateStaleSubaggregate, format!("@{}", val()?)))
            }
            "--aggregate-appearances" => pending.push((EventKind::AggregateAppearances, format!("@{}", val()?))),
            "--part-of-unknown" => pending.push((EventKind::PartOfUnknown, format!("@{}", val()?))),
            "--part-of-range-bearing" => pending.push((EventKind::PartOfRangeBearing, format!("@{}", val()?))),
            "--part-of-type" => pending.push((EventKind::PartOfType, format!("@{}", val()?))),
            "--all-aggregate-faults" => all_aggregate = true,
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

    let presets = nn_generator::presets::Presets {
        faults: all_faults,
        controls: all_controls,
        defects: all_defects,
        handshake: all_handshake,
        radio: all_radio,
        lifecycle: all_lifecycle,
        warfare: all_warfare,
        interaction: all_interaction,
        emission: all_emission,
        designator: all_designator,
        iff: all_iff,
        logistics: all_logistics,
        transfer: all_transfer,
        header: all_header,
        aggregate: all_aggregate,
    };
    nn_generator::presets::schedule(&mut cfg, &presets, pending, defects)?;
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
