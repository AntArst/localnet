#[cfg(feature = "admission")]
pub mod admission;
pub mod clock;
pub mod discovery;
pub mod media;
pub mod ptp;
pub mod ptp_udp;
pub mod protocol;
pub mod session;
pub mod socket;
pub mod transport;

pub use clock::{
    ClockDiscipline, ClockSnapshot, PtpClockConfig, PtpPortProfile, SoftwareClock,
};
pub use discovery::{DiscoveryEvent, PeerDiscovery, PeerInfo};
pub use media::{MediaDatagram, MediaFrame, MediaStreamType, RtcpPacket, RtpHeader, RtpPacket};
pub use ptp::{
    add_default_ptp_port, apply_ptp_actions_to_timers, default_ptp_instance, handle_ptp_event,
    handle_ptp_event_without_forward_tlvs, activate_ptp_port, DefaultPtpBmcaPort,
    DefaultPtpInstance, DefaultPtpRunningPort, PtpEvent, PtpOutboundPacket, PtpPacketKind,
    PtpPortTimers, PtpRuntimeAction, PtpTimerKind, DEFAULT_PTP_BASIC_FILTER_GAIN,
    PTP_EVENT_PORT, PTP_GENERAL_PORT,
};
pub use ptp_udp::{
    ForwardedTlvQueue, PtpActionEffects, PtpSinglePortRuntime, PtpUdpConfig, PtpUdpSockets,
    DEFAULT_PTP_MULTICAST_ADDR, DEFAULT_PTP_PEER_DELAY_MULTICAST_ADDR,
};
pub use protocol::{FlowDatagram, FlowId, FlowKind};
pub use session::{
    ConnectionQuality, Session, SessionEvent, SessionHandle, SessionStatus,
};
pub use socket::{LocalnetSocket, PeerAddr};
pub use transport::{
    ControlMessage, QuinnCongestionController, QuinnDatagram, QuinnPeer, QuinnTransport,
    QuinnTransportConfig,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SERVICE_TYPE: &str = "_localnet._udp.local.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}
