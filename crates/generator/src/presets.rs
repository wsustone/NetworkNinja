//! The generator's fault presets and event specs (`--all-faults`,
//! `--defect KIND:TYPE@T`, `--zombie ID@T`...) turned into scheduled events:
//! what `nn-generator` does with its command line, here so tests can build
//! the same runs.

use crate::{Config, Event, EventKind, Target};
use nn_decode::EntityId;

/// Which `--all-*` presets to schedule.
#[derive(Debug, Clone, Copy, Default)]
pub struct Presets {
    pub faults: bool,
    pub controls: bool,
    pub defects: bool,
    pub handshake: bool,
    pub radio: bool,
    pub lifecycle: bool,
    pub warfare: bool,
    pub interaction: bool,
    pub emission: bool,
    pub designator: bool,
    pub iff: bool,
    pub logistics: bool,
    pub transfer: bool,
    pub header: bool,
}

impl Presets {
    /// Every preset, as the `demo` scenario's faulty vendor runs them.
    pub fn all() -> Presets {
        Presets {
            faults: true,
            controls: true,
            defects: true,
            handshake: true,
            radio: true,
            lifecycle: true,
            warfare: true,
            interaction: true,
            emission: true,
            designator: true,
            iff: true,
            logistics: true,
            transfer: true,
            header: true,
        }
    }
}

/// Add `p`'s presets, then the `pending` event specs (`ID[@T]`, `SITE[@T]`
/// or `@T` by kind) and `defects` (`KIND:TYPE[@T]`), to `cfg.events`.
/// Presets turn on the schedules their faults need, if unset.
pub fn schedule(
    cfg: &mut Config,
    p: &Presets,
    mut pending: Vec<(EventKind, String)>,
    mut defects: Vec<String>,
) -> Result<(), String> {
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
    if p.faults {
        pending.push((EventKind::DropHeartbeat, format!("{first}:{app}:1@{}", d * 0.25)));
        pending.push((EventKind::CloneId, format!("{first}:{app}:2@{}", d * 0.35)));
        pending.push((EventKind::Teleport, format!("{first}:{app}:3@{}", d * 0.45)));
    }
    if p.controls {
        if cfg.sites < 2 {
            return Err("--all-controls needs at least 2 sites".into());
        }
        pending.push((EventKind::Remove, format!("{second}:{app}:1@{}", d * 0.25)));
        pending.push((EventKind::RestartPort, format!("{second}@{}", d * 0.35)));
        pending.push((EventKind::Freeze, format!("@{}", d * 0.55)));
        pending.push((EventKind::Resume, format!("@{}", d * 0.70)));
    }

    if p.handshake {
        if cfg.sites < 2 {
            return Err("--all-handshake-faults needs at least 2 sites".into());
        }
        cfg.siman_every.get_or_insert(2.0);
        // Spread out so each fault's alert stands on its own.
        pending.push((EventKind::WrongAck, format!("{second}@{}", d * 0.15)));
        pending.push((EventKind::OrphanResponse, format!("{second}@{}", d * 0.30)));
        pending.push((EventKind::NoResponse, format!("{second}@{}", d * 0.60)));
    }
    if p.interaction {
        cfg.collision_every.get_or_insert(10.0);
        cfg.damage_every.get_or_insert(40.0);
        cfg.de_every.get_or_insert(20.0);
        cfg.parked_per_site = cfg.parked_per_site.max(1);
        for (i, kind) in [
            EventKind::OneSidedCollision,
            EventKind::DuplicateCollision,
            EventKind::StaleAppearance,
            EventKind::DeDropout,
            EventKind::DeNoFire,
            EventKind::StillCollision,
            EventKind::BadDeRecord,
            EventKind::BadAttribute,
            EventKind::MissingExtension,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.1 + 0.08 * i as f64))));
        }
    }
    if p.emission {
        cfg.emission_every.get_or_insert(40.0);
        for (i, kind) in [
            EventKind::EmitterDropout,
            EventKind::EmitterRename,
            EventKind::ReservedBeam,
            EventKind::DenseTargets,
            EventKind::HalfPulsed,
            EventKind::NoSiteTarget,
            EventKind::RepeatDeactivated,
            EventKind::DestroyedEmitting,
            EventKind::BadEmitterEnums,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.05 + 0.1 * i as f64))));
        }
    }
    if p.iff {
        cfg.iff_every.get_or_insert(60.0);
        for (i, kind) in [
            EventKind::IffMissingLayer,
            EventKind::IffLayerBits,
            EventKind::IffLayerOrder,
            EventKind::IffEmptyLayer2,
            EventKind::IffUnflaggedChange,
            EventKind::IffHeartbeatUnflagged,
            EventKind::IffModeMismatch,
            // Last: the transponder's entity doesn't come back.
            EventKind::IffDestroyedOn,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.08 + 0.1 * i as f64))));
        }
    }
    if p.logistics {
        cfg.logistics_every.get_or_insert(20.0);
        // Each fault scripts the next conversation. The answers to nothing
        // come late, after the monitor's startup grace (144 s).
        let early = [
            EventKind::LogisticsNoOffer,
            EventKind::LogisticsNoReceipt,
            EventKind::ReceivedMore,
            EventKind::NoRepairResponse,
            EventKind::RepairCancelResult,
            EventKind::SuppliesOnRepair,
        ];
        let late = [
            EventKind::UnsolicitedOffer,
            EventKind::OrphanReceived,
            EventKind::UnrequestedRepair,
            EventKind::OrphanRepairResponse,
            EventKind::UnknownSupplier,
        ];
        for (i, kind) in early.into_iter().enumerate() {
            pending.push((kind, format!("@{}", d * (0.05 + 0.08 * i as f64))));
        }
        for (i, kind) in late.into_iter().enumerate() {
            pending.push((kind, format!("@{}", d * (0.62 + 0.07 * i as f64))));
        }
    }
    if p.header {
        // On the first site. The flip last: after it the site's timestamps
        // are relative, which aren't compared with the clock.
        let first = cfg.site_base;
        for (kind, at) in [
            (EventKind::TimestampBackwards, 0.2),
            (EventKind::StatusBits, 0.4),
            (EventKind::ClockSkew, 0.6),
            (EventKind::ExerciseSwitch, 0.7),
            (EventKind::TimestampFlip, 0.8),
        ] {
            pending.push((kind, format!("{first}@{}", d * at)));
        }
    }
    if p.transfer {
        cfg.transfer_every.get_or_insert(25.0);
        // Stalled first: its 120 s wait has to end inside the run.
        for (i, kind) in [
            EventKind::TransferStalled,
            EventKind::TransferReliability,
            EventKind::TransferIndicator,
            EventKind::TransferAttributes,
            EventKind::TransferNoReport,
            EventKind::TransferConcurrent,
            EventKind::TransferInactive,
            EventKind::TransferLingering,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.05 + 0.1 * i as f64))));
        }
    }
    if p.designator {
        cfg.designator_every.get_or_insert(30.0);
        // Late, so the monitor has watched a stationary timeout before
        // judging the unknown target.
        for (kind, at) in [
            (EventKind::SpotOffset, 0.10),
            (EventKind::TargetGone, 0.25),
            (EventKind::DesignatorGone, 0.40),
            (EventKind::UnknownDesignated, 0.60),
        ] {
            pending.push((kind, format!("@{}", d * at)));
        }
    }
    if p.warfare {
        cfg.fire_every.get_or_insert(10.0);
        for (i, kind) in [
            EventKind::NoDetonation,
            EventKind::DetonationMismatch,
            EventKind::WrongFireType,
            EventKind::OrphanDetonation,
            EventKind::MineFired,
            EventKind::ImpactMiss,
        ]
        .into_iter()
        .enumerate()
        {
            pending.push((kind, format!("@{}", d * (0.15 + 0.12 * i as f64))));
        }
    }
    if p.lifecycle {
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
    if p.radio {
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
    if p.defects {
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
            | EventKind::MineFired
            | EventKind::ImpactMiss
            | EventKind::StillCollision
            | EventKind::BadDeRecord
            | EventKind::BadAttribute
            | EventKind::MissingExtension
            | EventKind::EmitterDropout
            | EventKind::EmitterRename
            | EventKind::BadEmitterEnums
            | EventKind::ReservedBeam
            | EventKind::DenseTargets
            | EventKind::HalfPulsed
            | EventKind::NoSiteTarget
            | EventKind::RepeatDeactivated
            | EventKind::DestroyedEmitting
            | EventKind::SpotOffset
            | EventKind::UnknownDesignated
            | EventKind::TargetGone
            | EventKind::DesignatorGone
            | EventKind::IffMissingLayer
            | EventKind::IffLayerBits
            | EventKind::IffLayerOrder
            | EventKind::IffEmptyLayer2
            | EventKind::IffUnflaggedChange
            | EventKind::IffHeartbeatUnflagged
            | EventKind::IffModeMismatch
            | EventKind::IffDestroyedOn
            | EventKind::LogisticsNoOffer
            | EventKind::LogisticsNoReceipt
            | EventKind::ReceivedMore
            | EventKind::NoRepairResponse
            | EventKind::RepairCancelResult
            | EventKind::SuppliesOnRepair
            | EventKind::UnsolicitedOffer
            | EventKind::OrphanReceived
            | EventKind::UnrequestedRepair
            | EventKind::OrphanRepairResponse
            | EventKind::UnknownSupplier
            | EventKind::TransferLingering
            | EventKind::TransferReliability
            | EventKind::TransferIndicator
            | EventKind::TransferAttributes
            | EventKind::TransferNoReport
            | EventKind::TransferConcurrent
            | EventKind::TransferInactive
            | EventKind::TransferStalled
            | EventKind::OneSidedCollision
            | EventKind::DuplicateCollision
            | EventKind::StaleAppearance
            | EventKind::DeDropout
            | EventKind::DeNoFire => Target::Exercise,
            EventKind::RestartPort
            | EventKind::TimestampFlip
            | EventKind::TimestampBackwards
            | EventKind::ClockSkew
            | EventKind::ExerciseSwitch
            | EventKind::StatusBits
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
    Ok(())
}
