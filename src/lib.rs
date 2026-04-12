pub mod discovery;
pub mod session;
pub mod socket;
pub mod transport;

pub use discovery::{DiscoveryEvent, PeerDiscovery, PeerInfo};
pub use session::{
    ConnectionQuality, Session, SessionEvent, SessionHandle, SessionMode, SessionStatus,
};
pub use socket::{LocalnetSocket, PeerAddr};
pub use transport::{ControlMessage, QuinnDatagram, QuinnPeer, QuinnTransport};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const SERVICE_TYPE: &str = "_localnet._udp.local.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
