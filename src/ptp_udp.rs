use crate::ptp::{
    add_default_ptp_port, activate_ptp_port, handle_ptp_event, PtpEvent,
    PtpOutboundPacket, PtpPacketKind, PtpPortTimers, PtpRuntimeAction, PtpTimerKind,
};
use crate::{DefaultPtpInstance, DefaultPtpRunningPort, PtpClockConfig};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use statime::port::{ForwardedTLV, ForwardedTLVProvider};
use statime::time::Time;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::collections::VecDeque;
use std::time::Instant;
use tokio::net::UdpSocket;

pub const DEFAULT_PTP_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 129);
pub const DEFAULT_PTP_PEER_DELAY_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 107);
const MAX_PTP_PACKET_SIZE: usize = 2048;

#[derive(Debug, Clone)]
pub struct PtpUdpConfig {
    pub interface: Ipv4Addr,
    pub event_bind_addr: SocketAddrV4,
    pub general_bind_addr: SocketAddrV4,
    pub event_destination: SocketAddrV4,
    pub general_destination: SocketAddrV4,
    pub link_local_event_destination: SocketAddrV4,
    pub link_local_general_destination: SocketAddrV4,
    pub ttl: u32,
    pub multicast_loopback: bool,
    pub reuse_address: bool,
    pub join_multicast_groups: bool,
}

impl Default for PtpUdpConfig {
    fn default() -> Self {
        Self {
            interface: Ipv4Addr::UNSPECIFIED,
            event_bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, crate::PTP_EVENT_PORT),
            general_bind_addr: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, crate::PTP_GENERAL_PORT),
            event_destination: SocketAddrV4::new(DEFAULT_PTP_MULTICAST_ADDR, crate::PTP_EVENT_PORT),
            general_destination: SocketAddrV4::new(DEFAULT_PTP_MULTICAST_ADDR, crate::PTP_GENERAL_PORT),
            link_local_event_destination: SocketAddrV4::new(
                DEFAULT_PTP_PEER_DELAY_MULTICAST_ADDR,
                crate::PTP_EVENT_PORT,
            ),
            link_local_general_destination: SocketAddrV4::new(
                DEFAULT_PTP_PEER_DELAY_MULTICAST_ADDR,
                crate::PTP_GENERAL_PORT,
            ),
            ttl: 1,
            multicast_loopback: true,
            reuse_address: true,
            join_multicast_groups: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct PtpActionEffects {
    pub events: Vec<PtpEvent>,
    pub forwarded_tlvs: Vec<ForwardedTLV<'static>>,
}

#[derive(Debug, Default)]
pub struct ForwardedTlvQueue {
    queue: VecDeque<ForwardedTLV<'static>>,
}

impl ForwardedTlvQueue {
    pub fn push(&mut self, tlv: ForwardedTLV<'static>) {
        self.queue.push_back(tlv);
    }

    pub fn extend<I>(&mut self, tlvs: I)
    where
        I: IntoIterator<Item = ForwardedTLV<'static>>,
    {
        self.queue.extend(tlvs);
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

impl ForwardedTLVProvider for ForwardedTlvQueue {
    fn next_if_smaller(&mut self, max_size: usize) -> Option<ForwardedTLV<'_>> {
        match self.queue.front() {
            Some(tlv) if tlv.size() <= max_size => self.queue.pop_front(),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct PtpUdpSockets {
    event_socket: UdpSocket,
    general_socket: UdpSocket,
    config: PtpUdpConfig,
}

pub struct PtpSinglePortRuntime<'a, C, R> {
    instance: &'a DefaultPtpInstance,
    port: Option<DefaultPtpRunningPort<'a, C, R>>,
    sockets: PtpUdpSockets,
    timers: PtpPortTimers,
    forwarded_tlvs: ForwardedTlvQueue,
    next_bmca: Instant,
}

#[derive(Debug)]
enum RuntimeWake {
    Bmca,
    PortEvent(PtpEvent),
}

impl PtpUdpSockets {
    pub fn bind_ipv4(config: PtpUdpConfig) -> io::Result<Self> {
        let multicast_groups = if config.join_multicast_groups {
            let mut groups = vec![
                *config.event_destination.ip(),
                *config.general_destination.ip(),
                *config.link_local_event_destination.ip(),
                *config.link_local_general_destination.ip(),
            ];
            groups.sort();
            groups.dedup();
            groups
        } else {
            Vec::new()
        };

        let event_socket = bind_udp_socket(
            config.event_bind_addr,
            config.interface,
            &multicast_groups,
            config.ttl,
            config.multicast_loopback,
            config.reuse_address,
        )?;
        let general_socket = bind_udp_socket(
            config.general_bind_addr,
            config.interface,
            &multicast_groups,
            config.ttl,
            config.multicast_loopback,
            config.reuse_address,
        )?;

        Ok(Self {
            event_socket,
            general_socket,
            config,
        })
    }

    pub fn config(&self) -> &PtpUdpConfig {
        &self.config
    }

    pub async fn send_packet<T>(&self, packet: PtpOutboundPacket, timestamp_source: &T) -> io::Result<Option<PtpEvent>>
    where
        T: Fn() -> Time,
    {
        let destination = self.destination_for(&packet);
        let socket = self.socket_for(packet.kind);
        socket.send_to(&packet.data, destination).await?;

        Ok(packet.context.map(|context| PtpEvent::SendTimestamp {
            context,
            timestamp: timestamp_source(),
        }))
    }

    pub async fn execute_actions<T>(
        &self,
        actions: Vec<PtpRuntimeAction>,
        timers: &mut PtpPortTimers,
        timestamp_source: &T,
    ) -> io::Result<PtpActionEffects>
    where
        T: Fn() -> Time,
    {
        let mut effects = PtpActionEffects::default();

        for action in actions {
            match action {
                PtpRuntimeAction::Send(packet) => {
                    if let Some(event) = self.send_packet(packet, timestamp_source).await? {
                        effects.events.push(event);
                    }
                }
                PtpRuntimeAction::ResetTimer { timer, duration } => {
                    timers.set_from_now(timer, duration);
                }
                PtpRuntimeAction::ForwardTlv { tlv } => effects.forwarded_tlvs.push(tlv),
            }
        }

        Ok(effects)
    }

    pub fn drain_expired_timer_events(&self, timers: &mut PtpPortTimers) -> Vec<PtpEvent> {
        let expired = timers.expired(Instant::now());
        for timer in &expired {
            timers.clear(*timer);
        }

        expired.into_iter().map(timer_to_event).collect()
    }

    pub async fn recv_event_packet<T>(&self, timestamp_source: &T) -> io::Result<PtpEvent>
    where
        T: Fn() -> Time,
    {
        let mut buffer = vec![0_u8; MAX_PTP_PACKET_SIZE];
        let (len, _) = self.event_socket.recv_from(&mut buffer).await?;
        buffer.truncate(len);
        Ok(PtpEvent::EventPacketReceived {
            data: buffer,
            timestamp: timestamp_source(),
        })
    }

    pub async fn recv_general_packet(&self) -> io::Result<PtpEvent> {
        let mut buffer = vec![0_u8; MAX_PTP_PACKET_SIZE];
        let (len, _) = self.general_socket.recv_from(&mut buffer).await?;
        buffer.truncate(len);
        Ok(PtpEvent::GeneralPacketReceived { data: buffer })
    }

    pub async fn wait_for_event<T>(&self, timers: &mut PtpPortTimers, timestamp_source: &T) -> io::Result<PtpEvent>
    where
        T: Fn() -> Time,
    {
        if let Some(event) = self.drain_expired_timer_events(timers).into_iter().next() {
            return Ok(event);
        }

        match timers.next_deadline() {
            Some((timer, deadline)) => {
                tokio::select! {
                    event = self.recv_event_packet(timestamp_source) => event,
                    general = self.recv_general_packet() => general,
                    _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => {
                        timers.clear(timer);
                        Ok(timer_to_event(timer))
                    }
                }
            }
            None => {
                tokio::select! {
                    event = self.recv_event_packet(timestamp_source) => event,
                    general = self.recv_general_packet() => general,
                }
            }
        }
    }

    fn destination_for(&self, packet: &PtpOutboundPacket) -> SocketAddr {
        let destination = match (packet.kind, packet.link_local) {
            (PtpPacketKind::Event, false) => self.config.event_destination,
            (PtpPacketKind::General, false) => self.config.general_destination,
            (PtpPacketKind::Event, true) => self.config.link_local_event_destination,
            (PtpPacketKind::General, true) => self.config.link_local_general_destination,
        };

        SocketAddr::V4(destination)
    }

    fn socket_for(&self, kind: PtpPacketKind) -> &UdpSocket {
        match kind {
            PtpPacketKind::Event => &self.event_socket,
            PtpPacketKind::General => &self.general_socket,
        }
    }
}

impl<'a, C, R> PtpSinglePortRuntime<'a, C, R>
where
    C: statime::Clock,
    R: Rng,
{
    pub async fn bind_ipv4<T>(
        instance: &'a DefaultPtpInstance,
        ptp_config: &PtpClockConfig,
        udp_config: PtpUdpConfig,
        clock: C,
        rng: R,
        timestamp_source: &T,
    ) -> io::Result<Self>
    where
        T: Fn() -> Time,
    {
        let sockets = PtpUdpSockets::bind_ipv4(udp_config)?;
        let mut bmca_port = add_default_ptp_port(instance, ptp_config, clock, rng);
        instance.bmca(&mut [&mut bmca_port]);
        let (port, initial_actions) = activate_ptp_port(bmca_port);

        let mut runtime = Self {
            instance,
            port: Some(port),
            sockets,
            timers: PtpPortTimers::default(),
            forwarded_tlvs: ForwardedTlvQueue::default(),
            next_bmca: Instant::now() + instance.bmca_interval(),
        };

        runtime.drive_actions(initial_actions, timestamp_source).await?;
        Ok(runtime)
    }

    pub fn instance(&self) -> &DefaultPtpInstance {
        self.instance
    }

    pub fn port(&self) -> &DefaultPtpRunningPort<'a, C, R> {
        self.port.as_ref().expect("ptp runtime port missing")
    }

    pub fn port_mut(&mut self) -> &mut DefaultPtpRunningPort<'a, C, R> {
        self.port.as_mut().expect("ptp runtime port missing")
    }

    pub fn timers(&self) -> &PtpPortTimers {
        &self.timers
    }

    pub fn forwarded_tlvs(&self) -> &ForwardedTlvQueue {
        &self.forwarded_tlvs
    }

    pub fn sockets(&self) -> &PtpUdpSockets {
        &self.sockets
    }

    pub async fn handle_event<T>(&mut self, event: PtpEvent, timestamp_source: &T) -> io::Result<()>
    where
        T: Fn() -> Time,
    {
        let actions = {
            let port = self.port.as_mut().expect("ptp runtime port missing");
            let forwarded_tlvs = &mut self.forwarded_tlvs;
            handle_ptp_event(port, event, forwarded_tlvs)
        };
        self.drive_actions(actions, timestamp_source).await
    }

    pub async fn step<T>(&mut self, timestamp_source: &T) -> io::Result<()>
    where
        T: Fn() -> Time,
    {
        if Instant::now() >= self.next_bmca {
            return self.run_bmca(timestamp_source).await;
        }

        if let Some(event) = self.sockets.drain_expired_timer_events(&mut self.timers).into_iter().next() {
            return self.handle_event(event, timestamp_source).await;
        }

        match self.wait_for_runtime_event(timestamp_source).await? {
            RuntimeWake::Bmca => self.run_bmca(timestamp_source).await,
            RuntimeWake::PortEvent(event) => self.handle_event(event, timestamp_source).await,
        }
    }

    pub async fn run_bmca<T>(&mut self, timestamp_source: &T) -> io::Result<()>
    where
        T: Fn() -> Time,
    {
        let running_port = self.port.take().expect("ptp runtime port missing");
        let mut bmca_port = running_port.start_bmca();
        self.instance.bmca(&mut [&mut bmca_port]);
        let (port, actions) = activate_ptp_port(bmca_port);
        self.port = Some(port);
        self.next_bmca = Instant::now() + self.instance.bmca_interval();
        self.drive_actions(actions, timestamp_source).await
    }

    async fn drive_actions<T>(&mut self, mut actions: Vec<PtpRuntimeAction>, timestamp_source: &T) -> io::Result<()>
    where
        T: Fn() -> Time,
    {
        let mut pending_events = VecDeque::new();

        loop {
            let effects = self
                .sockets
                .execute_actions(actions, &mut self.timers, timestamp_source)
                .await?;
            self.forwarded_tlvs.extend(effects.forwarded_tlvs);
            pending_events.extend(effects.events);

            let Some(event) = pending_events.pop_front() else {
                break;
            };

            actions = {
                let port = self.port.as_mut().expect("ptp runtime port missing");
                let forwarded_tlvs = &mut self.forwarded_tlvs;
                handle_ptp_event(port, event, forwarded_tlvs)
            };
        }

        Ok(())
    }

    async fn wait_for_runtime_event<T>(&mut self, timestamp_source: &T) -> io::Result<RuntimeWake>
    where
        T: Fn() -> Time,
    {
        let next_timer_deadline = self.timers.next_deadline().map(|(_, deadline)| deadline);
        let next_deadline = next_timer_deadline
            .map(|deadline| deadline.min(self.next_bmca))
            .unwrap_or(self.next_bmca);

        tokio::select! {
            event = self.sockets.recv_event_packet(timestamp_source) => event.map(RuntimeWake::PortEvent),
            general = self.sockets.recv_general_packet() => general.map(RuntimeWake::PortEvent),
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(next_deadline)) => {
                let now = Instant::now();
                if now >= self.next_bmca {
                    self.next_bmca = now;
                    return Ok(RuntimeWake::Bmca);
                }

                if let Some(event) = self.sockets.drain_expired_timer_events(&mut self.timers).into_iter().next() {
                    Ok(RuntimeWake::PortEvent(event))
                } else {
                    self.next_bmca = now;
                    Ok(RuntimeWake::Bmca)
                }
            }
        }
    }
}

fn bind_udp_socket(
    bind_addr: SocketAddrV4,
    interface: Ipv4Addr,
    multicast_groups: &[Ipv4Addr],
    ttl: u32,
    multicast_loopback: bool,
    reuse_address: bool,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    if reuse_address {
        socket.set_reuse_address(true)?;
        #[cfg(not(windows))]
        socket.set_reuse_port(true)?;
    }
    socket.set_multicast_if_v4(&interface)?;
    socket.set_multicast_ttl_v4(ttl)?;
    socket.set_multicast_loop_v4(multicast_loopback)?;
    socket.bind(&SocketAddr::V4(bind_addr).into())?;

    for multicast_group in multicast_groups {
        if multicast_group.is_multicast() {
            socket.join_multicast_v4(multicast_group, &interface)?;
        }
    }

    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket)
}

fn timer_to_event(timer: PtpTimerKind) -> PtpEvent {
    match timer {
        PtpTimerKind::Announce => PtpEvent::AnnounceTimerFired,
        PtpTimerKind::Sync => PtpEvent::SyncTimerFired,
        PtpTimerKind::DelayRequest => PtpEvent::DelayRequestTimerFired,
        PtpTimerKind::AnnounceReceipt => PtpEvent::AnnounceReceiptTimerFired,
        PtpTimerKind::FilterUpdate => PtpEvent::FilterUpdateTimerFired,
    }
}