use crate::{
    ControlMessage, LocalnetSocket, PeerAddr, PeerDiscovery, PeerInfo, QuinnPeer, QuinnTransport,
    SessionId,
};
use anyhow::{anyhow, Context, Result};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionMode {
    Traditional,
    Icebreaker,
    Arcade,
}

impl SessionMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionMode::Traditional => "traditional",
            SessionMode::Icebreaker => "icebreaker",
            SessionMode::Arcade => "arcade",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SessionStatus {
    Created,
    Lobby,
    Starting,
    InProgress,
    Ended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionQuality {
    pub rtt_ms: u32,
    pub jitter_ms: u32,
    pub packet_loss: f32,
}

impl Default for ConnectionQuality {
    fn default() -> Self {
        Self {
            rtt_ms: 0,
            jitter_ms: 0,
            packet_loss: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SessionEvent {
    StatusChanged(SessionStatus),
    PeerJoined(PeerInfo),
    PeerLeft(PeerAddr),
    PeerReconnected(PeerAddr),
    QualityUpdated(PeerAddr, ConnectionQuality),
    Error(String),
}

pub struct SessionHandle {
    pub id: SessionId,
    pub local_peer: PeerAddr,
    pub event_rx: broadcast::Receiver<SessionEvent>,
}

pub struct Session {
    id: SessionId,
    mode: SessionMode,
    status: SessionStatus,
    local_peer: PeerAddr,
    socket: LocalnetSocket,
    transport: QuinnTransport,
    discovery: Option<PeerDiscovery>,
    connected: HashMap<PeerAddr, QuinnPeer>,
    quality: HashMap<PeerAddr, ConnectionQuality>,
    events_tx: broadcast::Sender<SessionEvent>,
}

impl Session {
    pub fn host(
        bind_addr: SocketAddr,
        local_peer: PeerAddr,
        mode: SessionMode,
        player_name: &str,
        metadata: HashMap<String, String>,
        capacity: u8,
    ) -> Result<Self> {
        let transport = QuinnTransport::bind(bind_addr)?;
        let mut discovery = PeerDiscovery::start()?;
        let session_id = SessionId::new();
        discovery.advertise(
            &local_peer.0,
            player_name,
            session_id.clone(),
            mode.as_str(),
            &metadata,
            capacity,
            1,
            transport.local_addr()?.port(),
            transport.certificate_der().as_ref(),
        )?;

        let (events_tx, _) = broadcast::channel(256);
        let mut session = Self {
            id: session_id,
            mode,
            status: SessionStatus::Created,
            local_peer,
            socket: LocalnetSocket::new(),
            transport,
            discovery: Some(discovery),
            connected: HashMap::new(),
            quality: HashMap::new(),
            events_tx,
        };
        session.transition(SessionStatus::Lobby);
        Ok(session)
    }

    pub fn join(bind_addr: SocketAddr, local_peer: PeerAddr, mode: SessionMode) -> Result<Self> {
        let transport = QuinnTransport::bind(bind_addr)?;
        let (events_tx, _) = broadcast::channel(256);

        Ok(Self {
            id: SessionId::new(),
            mode,
            status: SessionStatus::Created,
            local_peer,
            socket: LocalnetSocket::new(),
            transport,
            discovery: None,
            connected: HashMap::new(),
            quality: HashMap::new(),
            events_tx,
        })
    }

    pub fn mode(&self) -> SessionMode {
        self.mode
    }

    pub fn status(&self) -> SessionStatus {
        self.status
    }

    pub fn id(&self) -> SessionId {
        self.id.clone()
    }

    pub fn socket(&self) -> LocalnetSocket {
        self.socket.clone()
    }

    pub fn handle(&self) -> SessionHandle {
        SessionHandle {
            id: self.id(),
            local_peer: self.local_peer.clone(),
            event_rx: self.events_tx.subscribe(),
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn discovered_peers(&self) -> Vec<PeerInfo> {
        self.discovery
            .as_ref()
            .map(|d| d.peers())
            .unwrap_or_default()
    }

    pub fn connected_peer_count(&self) -> usize {
        self.connected.len()
    }

    pub fn connected_peers(&self) -> Vec<PeerAddr> {
        self.connected.keys().cloned().collect()
    }

    pub async fn accept_peer(&mut self) -> Result<PeerAddr> {
        let peer = self.transport.accept_peer().await?;
        let addr = PeerAddr(peer.addr.to_string());
        self.connected.insert(addr.clone(), peer);
        self.transition(SessionStatus::Lobby);
        Ok(addr)
    }

    pub async fn connect_to_host(
        &mut self,
        host_addr: SocketAddr,
        host_cert_der: Vec<u8>,
        server_name: &str,
    ) -> Result<PeerAddr> {
        let cert = rustls_pki_types::CertificateDer::from(host_cert_der);
        let peer = self
            .transport
            .connect_peer(host_addr, cert, server_name)
            .await
            .with_context(|| format!("failed connecting to host {host_addr}"))?;
        let addr = PeerAddr(peer.addr.to_string());
        self.connected.insert(addr.clone(), peer);
        self.transition(SessionStatus::Lobby);
        Ok(addr)
    }

    pub fn start_match(&mut self) {
        self.transition(SessionStatus::Starting);
        self.transition(SessionStatus::InProgress);
    }

    pub async fn accept_peer_with_timeout(&mut self, timeout_ms: u64) -> Result<Option<PeerAddr>> {
        match self.transport.accept_peer_waiting(timeout_ms).await? {
            Some(peer) => {
                let addr = PeerAddr(peer.addr.to_string());
                self.connected.insert(addr.clone(), peer);
                self.transition(SessionStatus::Lobby);
                Ok(Some(addr))
            }
            None => Ok(None),
        }
    }

    pub async fn broadcast_control(&self, message: &ControlMessage) -> Result<()> {
        let encoded = bincode::serde::encode_to_vec(message, bincode::config::standard())
            .context("failed to serialize control message")?;
        self.send_datagram_to_connected(&encoded).await
    }

    pub async fn send_datagram_to_connected(&self, bytes: &[u8]) -> Result<()> {
        for peer in self.connected.values() {
            peer.send_datagram(bytes.to_vec()).await?;
        }
        Ok(())
    }

    pub fn poll_datagrams(&self) -> Vec<(PeerAddr, Vec<u8>)> {
        let mut messages = Vec::new();
        for (peer_addr, peer) in &self.connected {
            loop {
                let Some(result) = peer.connection.read_datagram().now_or_never() else {
                    break;
                };
                let Ok(bytes) = result else {
                    break;
                };
                messages.push((peer_addr.clone(), bytes.to_vec()));
            }
        }
        messages
    }

    pub fn end_match(&mut self) {
        self.transition(SessionStatus::Ended);
    }

    pub fn update_quality(&mut self, peer: PeerAddr, quality: ConnectionQuality) {
        self.quality.insert(peer.clone(), quality.clone());
        let _ = self
            .events_tx
            .send(SessionEvent::QualityUpdated(peer, quality));
    }

    pub fn quality_for(&self, peer: &PeerAddr) -> Option<ConnectionQuality> {
        self.quality.get(peer).cloned()
    }

    pub async fn reconnect_peer(
        &mut self,
        peer_addr: SocketAddr,
        peer_cert_der: Vec<u8>,
        server_name: &str,
    ) -> Result<PeerAddr> {
        let addr = PeerAddr(peer_addr.to_string());
        let cert = rustls_pki_types::CertificateDer::from(peer_cert_der);
        let peer = self
            .transport
            .connect_with_timeout(peer_addr, cert, server_name, 4_000)
            .await
            .with_context(|| format!("reconnect failed: {}", addr.0))?;

        self.connected.insert(addr.clone(), peer);
        let _ = self
            .events_tx
            .send(SessionEvent::PeerReconnected(addr.clone()));
        Ok(addr)
    }

    pub async fn pump_datagrams(&mut self) -> Result<()> {
        let outgoing = self.socket.drain_outgoing();
        for (peer_addr, message) in outgoing {
            if let Some(peer) = self.connected.get(&peer_addr) {
                let encoded = bincode::serde::encode_to_vec(&message, bincode::config::standard())
                    .context("failed to serialize ggrs message")?;
                peer.send_datagram(encoded).await?;
            }
        }

        // Pull one datagram per peer each frame to keep latency predictable.
        for (peer_addr, peer) in &self.connected {
            if let Ok(bytes) = peer.receive_datagram().await {
                if let Ok((message, _)) =
                    bincode::serde::decode_from_slice(&bytes, bincode::config::standard())
                {
                    self.socket.enqueue_incoming(peer_addr.clone(), message);
                }
            }
        }
        Ok(())
    }

    pub fn disconnect_peer(&mut self, peer: &PeerAddr) -> Result<()> {
        if self.connected.remove(peer).is_none() {
            return Err(anyhow!("peer {} was not connected", peer.0));
        }
        self.quality.remove(peer);
        let _ = self.events_tx.send(SessionEvent::PeerLeft(peer.clone()));
        Ok(())
    }

    fn transition(&mut self, status: SessionStatus) {
        self.status = status;
        let _ = self.events_tx.send(SessionEvent::StatusChanged(status));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.stop();
        }
    }
}
