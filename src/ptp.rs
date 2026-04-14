use crate::clock::AcceptAllMasters;
use crate::PtpClockConfig;
use rand::Rng;
use statime::config::AcceptableMasterList;
use statime::filters::BasicFilter;
use statime::port::{
    ForwardedTLV, ForwardedTLVProvider, InBmca, NoForwardedTLVs, Port, PortAction,
    PortActionIterator, Running, TimestampContext,
};
use statime::time::Time;
use statime::{Clock, PtpInstance};
use std::sync::RwLock;
use std::time::{Duration, Instant};

pub const PTP_EVENT_PORT: u16 = 319;
pub const PTP_GENERAL_PORT: u16 = 320;
pub const DEFAULT_PTP_BASIC_FILTER_GAIN: f64 = 0.2;

pub type DefaultPtpInstance = PtpInstance<BasicFilter, RwLock<statime::PtpInstanceState>>;
pub type DefaultPtpBmcaPort<'a, C, R> =
    Port<'a, InBmca, AcceptAllMasters, R, C, BasicFilter, RwLock<statime::PtpInstanceState>>;
pub type DefaultPtpRunningPort<'a, C, R> =
    Port<'a, Running, AcceptAllMasters, R, C, BasicFilter, RwLock<statime::PtpInstanceState>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PtpTimerKind {
    Announce,
    Sync,
    DelayRequest,
    AnnounceReceipt,
    FilterUpdate,
}

#[derive(Debug, Clone, Default)]
pub struct PtpPortTimers {
    announce: Option<Instant>,
    sync: Option<Instant>,
    delay_request: Option<Instant>,
    announce_receipt: Option<Instant>,
    filter_update: Option<Instant>,
}

impl PtpPortTimers {
    pub fn set_from_now(&mut self, timer: PtpTimerKind, duration: Duration) {
        self.set_deadline(timer, Instant::now() + duration);
    }

    pub fn set_deadline(&mut self, timer: PtpTimerKind, deadline: Instant) {
        *self.deadline_mut(timer) = Some(deadline);
    }

    pub fn clear(&mut self, timer: PtpTimerKind) {
        *self.deadline_mut(timer) = None;
    }

    pub fn deadline(&self, timer: PtpTimerKind) -> Option<Instant> {
        match timer {
            PtpTimerKind::Announce => self.announce,
            PtpTimerKind::Sync => self.sync,
            PtpTimerKind::DelayRequest => self.delay_request,
            PtpTimerKind::AnnounceReceipt => self.announce_receipt,
            PtpTimerKind::FilterUpdate => self.filter_update,
        }
    }

    pub fn next_deadline(&self) -> Option<(PtpTimerKind, Instant)> {
        self.iter_deadlines().min_by_key(|(_, deadline)| *deadline)
    }

    pub fn expired(&self, now: Instant) -> Vec<PtpTimerKind> {
        self.iter_deadlines()
            .filter_map(|(timer, deadline)| (deadline <= now).then_some(timer))
            .collect()
    }

    fn iter_deadlines(&self) -> impl Iterator<Item = (PtpTimerKind, Instant)> + '_ {
        [
            (PtpTimerKind::Announce, self.announce),
            (PtpTimerKind::Sync, self.sync),
            (PtpTimerKind::DelayRequest, self.delay_request),
            (PtpTimerKind::AnnounceReceipt, self.announce_receipt),
            (PtpTimerKind::FilterUpdate, self.filter_update),
        ]
        .into_iter()
        .filter_map(|(timer, deadline)| deadline.map(|instant| (timer, instant)))
    }

    fn deadline_mut(&mut self, timer: PtpTimerKind) -> &mut Option<Instant> {
        match timer {
            PtpTimerKind::Announce => &mut self.announce,
            PtpTimerKind::Sync => &mut self.sync,
            PtpTimerKind::DelayRequest => &mut self.delay_request,
            PtpTimerKind::AnnounceReceipt => &mut self.announce_receipt,
            PtpTimerKind::FilterUpdate => &mut self.filter_update,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtpPacketKind {
    Event,
    General,
}

#[derive(Debug)]
pub struct PtpOutboundPacket {
    pub kind: PtpPacketKind,
    pub data: Vec<u8>,
    pub link_local: bool,
    pub context: Option<TimestampContext>,
}

#[derive(Debug)]
pub enum PtpRuntimeAction {
    Send(PtpOutboundPacket),
    ResetTimer { timer: PtpTimerKind, duration: Duration },
    ForwardTlv { tlv: ForwardedTLV<'static> },
}

#[derive(Debug)]
pub enum PtpEvent {
    AnnounceTimerFired,
    SyncTimerFired,
    DelayRequestTimerFired,
    AnnounceReceiptTimerFired,
    FilterUpdateTimerFired,
    EventPacketReceived { data: Vec<u8>, timestamp: Time },
    GeneralPacketReceived { data: Vec<u8> },
    SendTimestamp { context: TimestampContext, timestamp: Time },
}

pub fn default_ptp_instance(config: &PtpClockConfig) -> DefaultPtpInstance {
    PtpInstance::new(config.instance, config.time_properties)
}

pub fn add_default_ptp_port<'a, C, R>(
    instance: &'a DefaultPtpInstance,
    config: &PtpClockConfig,
    clock: C,
    rng: R,
) -> DefaultPtpBmcaPort<'a, C, R>
where
    C: Clock,
    R: Rng,
{
    instance.add_port(
        config.port.clone(),
        DEFAULT_PTP_BASIC_FILTER_GAIN,
        clock,
        rng,
    )
}

pub fn activate_ptp_port<'a, A, C, F, R, S>(
    port: Port<'a, InBmca, A, R, C, F, S>,
) -> (Port<'a, Running, A, R, C, F, S>, Vec<PtpRuntimeAction>)
where
    F: statime::filters::Filter,
{
    let (port, actions) = port.end_bmca();
    (port, collect_ptp_actions(actions))
}

pub fn handle_ptp_event_without_forward_tlvs<'a, A, C, F, R, S>(
    port: &mut Port<'a, Running, A, R, C, F, S>,
    event: PtpEvent,
) -> Vec<PtpRuntimeAction>
where
    A: AcceptableMasterList,
    C: Clock,
    F: statime::filters::Filter,
    R: Rng,
    S: statime::PtpInstanceStateMutex,
{
    let mut no_tlvs = NoForwardedTLVs;
    handle_ptp_event(port, event, &mut no_tlvs)
}

pub fn handle_ptp_event<'a, A, C, F, R, S>(
    port: &mut Port<'a, Running, A, R, C, F, S>,
    event: PtpEvent,
    forwarded_tlvs: &mut impl ForwardedTLVProvider,
) -> Vec<PtpRuntimeAction>
where
    A: AcceptableMasterList,
    C: Clock,
    F: statime::filters::Filter,
    R: Rng,
    S: statime::PtpInstanceStateMutex,
{
    match event {
        PtpEvent::AnnounceTimerFired => collect_ptp_actions(port.handle_announce_timer(forwarded_tlvs)),
        PtpEvent::SyncTimerFired => collect_ptp_actions(port.handle_sync_timer()),
        PtpEvent::DelayRequestTimerFired => collect_ptp_actions(port.handle_delay_request_timer()),
        PtpEvent::AnnounceReceiptTimerFired => {
            collect_ptp_actions(port.handle_announce_receipt_timer())
        }
        PtpEvent::FilterUpdateTimerFired => collect_ptp_actions(port.handle_filter_update_timer()),
        PtpEvent::EventPacketReceived { data, timestamp } => {
            collect_ptp_actions(port.handle_event_receive(&data, timestamp))
        }
        PtpEvent::GeneralPacketReceived { data } => {
            collect_ptp_actions(port.handle_general_receive(&data))
        }
        PtpEvent::SendTimestamp { context, timestamp } => {
            collect_ptp_actions(port.handle_send_timestamp(context, timestamp))
        }
    }
}

pub fn apply_ptp_actions_to_timers(timers: &mut PtpPortTimers, actions: &[PtpRuntimeAction]) {
    for action in actions {
        if let PtpRuntimeAction::ResetTimer { timer, duration } = action {
            timers.set_from_now(*timer, *duration);
        }
    }
}

pub fn collect_ptp_actions(actions: PortActionIterator<'_>) -> Vec<PtpRuntimeAction> {
    actions
        .map(|action| match action {
            PortAction::SendEvent {
                context,
                data,
                link_local,
            } => PtpRuntimeAction::Send(PtpOutboundPacket {
                kind: PtpPacketKind::Event,
                data: data.to_vec(),
                link_local,
                context: Some(context),
            }),
            PortAction::SendGeneral { data, link_local } => {
                PtpRuntimeAction::Send(PtpOutboundPacket {
                    kind: PtpPacketKind::General,
                    data: data.to_vec(),
                    link_local,
                    context: None,
                })
            }
            PortAction::ResetAnnounceTimer { duration } => PtpRuntimeAction::ResetTimer {
                timer: PtpTimerKind::Announce,
                duration,
            },
            PortAction::ResetSyncTimer { duration } => PtpRuntimeAction::ResetTimer {
                timer: PtpTimerKind::Sync,
                duration,
            },
            PortAction::ResetDelayRequestTimer { duration } => PtpRuntimeAction::ResetTimer {
                timer: PtpTimerKind::DelayRequest,
                duration,
            },
            PortAction::ResetAnnounceReceiptTimer { duration } => PtpRuntimeAction::ResetTimer {
                timer: PtpTimerKind::AnnounceReceipt,
                duration,
            },
            PortAction::ResetFilterUpdateTimer { duration } => PtpRuntimeAction::ResetTimer {
                timer: PtpTimerKind::FilterUpdate,
                duration,
            },
            PortAction::ForwardTLV { tlv } => PtpRuntimeAction::ForwardTlv {
                tlv: tlv.into_owned(),
            },
        })
        .collect()
}