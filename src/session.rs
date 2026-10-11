use crate::{
    ControlMessage, FlowDatagram, LocalnetSocket, MediaDatagram, PeerAddr, PeerDiscovery,
    PeerInfo, QuinnPeer, QuinnTransport, QuinnTransportConfig, SessionId,
};
use anyhow::{anyhow, Context, Result};
use futures::FutureExt;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

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
    status: SessionStatus,
    local_peer: PeerAddr,
    socket: LocalnetSocket,
    transport: QuinnTransport,
    discovery: Option<PeerDiscovery>,
    connected: HashMap<PeerAddr, QuinnPeer>,
    quality: HashMap<PeerAddr, ConnectionQuality>,
    incoming_datagrams: VecDeque<(PeerAddr, Vec<u8>)>,
    incoming_flow_datagrams: VecDeque<(PeerAddr, FlowDatagram)>,
    events_tx: broadcast::Sender<SessionEvent>,
}

impl Session {
    pub fn host_with_transport_config(
        bind_addr: SocketAddr,
        local_peer: PeerAddr,
        app_id: &str,
        player_name: &str,
        metadata: HashMap<String, String>,
        capacity: u8,
        transport_config: QuinnTransportConfig,
    ) -> Result<Self> {
        let transport = QuinnTransport::bind_with_config(bind_addr, app_id, transport_config)?;
        let mut discovery = PeerDiscovery::start()?;
        let session_id = SessionId::new();
        discovery.advertise(
            &local_peer.0,
            player_name,
            session_id.clone(),
            app_id,
            &metadata,
            capacity,
            1,
            transport.local_addr()?.port(),
            transport.certificate_der().as_ref(),
        )?;

        let (events_tx, _) = broadcast::channel(256);
        let mut session = Self {
            id: session_id,
            status: SessionStatus::Created,
            local_peer,
            socket: LocalnetSocket::new(),
            transport,
            discovery: Some(discovery),
            connected: HashMap::new(),
            quality: HashMap::new(),
            incoming_datagrams: VecDeque::new(),
            incoming_flow_datagrams: VecDeque::new(),
            events_tx,
        };
        info!(app_id = %app_id, "hosting session");
        session.transition(SessionStatus::Lobby);
        Ok(session)
    }

    pub fn host(
        bind_addr: SocketAddr,
        local_peer: PeerAddr,
        app_id: &str,
        player_name: &str,
        metadata: HashMap<String, String>,
        capacity: u8,
    ) -> Result<Self> {
        Self::host_with_transport_config(
            bind_addr,
            local_peer,
            app_id,
            player_name,
            metadata,
            capacity,
            QuinnTransportConfig::default(),
        )
    }

    pub fn join_with_transport_config(
        bind_addr: SocketAddr,
        local_peer: PeerAddr,
        app_id: &str,
        transport_config: QuinnTransportConfig,
    ) -> Result<Self> {
        let transport = QuinnTransport::bind_with_config(bind_addr, app_id, transport_config)?;
        let (events_tx, _) = broadcast::channel(256);
        info!(app_id = %app_id, "joining session");

        Ok(Self {
            id: SessionId::new(),
            status: SessionStatus::Created,
            local_peer,
            socket: LocalnetSocket::new(),
            transport,
            discovery: None,
            connected: HashMap::new(),
            quality: HashMap::new(),
            incoming_datagrams: VecDeque::new(),
            incoming_flow_datagrams: VecDeque::new(),
            events_tx,
        })
    }

    pub fn join(bind_addr: SocketAddr, local_peer: PeerAddr, app_id: &str) -> Result<Self> {
        Self::join_with_transport_config(
            bind_addr,
            local_peer,
            app_id,
            QuinnTransportConfig::default(),
        )
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
        info!(peer = %addr.0, "peer accepted");
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
        info!(host = %host_addr, "connected to host");
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

    pub async fn send_flow_datagram_to_connected(&self, datagram: &FlowDatagram) -> Result<()> {
        let encoded = datagram.encode_wire()?;
        self.send_datagram_to_connected(&encoded).await
    }

    pub async fn send_media_datagram_to_connected(&self, datagram: &MediaDatagram) -> Result<()> {
        let flow_datagram = datagram.into_flow_datagram()?;
        self.send_flow_datagram_to_connected(&flow_datagram).await
    }

    pub fn poll_datagrams(&mut self) -> Vec<(PeerAddr, Vec<u8>)> {
        self.ingest_pending_datagrams();
        self.incoming_datagrams.drain(..).collect()
    }

    pub fn poll_flow_datagrams(&mut self) -> Vec<(PeerAddr, FlowDatagram)> {
        self.ingest_pending_datagrams();
        self.incoming_flow_datagrams.drain(..).collect()
    }

    pub fn poll_media_datagrams(&mut self) -> Result<Vec<(PeerAddr, MediaDatagram)>> {
        self.ingest_pending_datagrams();

        let mut media_datagrams = Vec::new();
        let mut remaining = VecDeque::new();

        while let Some((peer_addr, datagram)) = self.incoming_flow_datagrams.pop_front() {
            match MediaDatagram::from_flow_datagram(&datagram)? {
                Some(media) => media_datagrams.push((peer_addr, media)),
                None => remaining.push_back((peer_addr, datagram)),
            }
        }

        self.incoming_flow_datagrams = remaining;
        Ok(media_datagrams)
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

    pub fn all_quality(&self) -> HashMap<PeerAddr, ConnectionQuality> {
        self.quality.clone()
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

        info!(peer = %addr.0, "peer reconnected");
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

        // Update quality stats from Quinn for all connected peers
        for (addr, peer) in &self.connected {
            let stats = peer.stats();
            let rtt_ms = stats.path.rtt.as_millis() as u32;
            self.quality.insert(addr.clone(), ConnectionQuality {
                rtt_ms,
                jitter_ms: 0, // Quinn doesn't expose raw jitter easily
                packet_loss: 0.0, // Could calculate from stats.path.lost_packets if needed
            });
        }

        // Non-blocking ingest of all pending datagrams
        self.ingest_pending_datagrams();
        Ok(())
    }

    pub fn disconnect_peer(&mut self, peer: &PeerAddr) -> Result<()> {
        if self.connected.remove(peer).is_none() {
            return Err(anyhow!("peer {} was not connected", peer.0));
        }
        info!(peer = %peer.0, "peer disconnected");
        self.quality.remove(peer);
        let _ = self.events_tx.send(SessionEvent::PeerLeft(peer.clone()));
        Ok(())
    }

    fn transition(&mut self, status: SessionStatus) {
        debug!(from = ?self.status, to = ?status, "session status transition");
        self.status = status;
        let _ = self.events_tx.send(SessionEvent::StatusChanged(status));
    }

    fn ingest_pending_datagrams(&mut self) {
        for (peer_addr, peer) in &self.connected {
            loop {
                let Some(result) = peer.connection.read_datagram().now_or_never() else {
                    break;
                };

                let Ok(bytes) = result else {
                    break;
                };

                match FlowDatagram::decode_wire(&bytes) {
                    Ok(Some(flow_datagram)) => {
                        self.incoming_flow_datagrams
                            .push_back((peer_addr.clone(), flow_datagram));
                    }
                    Ok(None) => {
                        self.incoming_datagrams.push_back((peer_addr.clone(), bytes.to_vec()));
                    }
                    Err(err) => {
                        warn!(peer = %peer_addr.0, error = %err, "dropping malformed localnet flow datagram");
                    }
                }
            }
        }
    }
}

#[cfg(feature = "admission")]
impl Session {
    /// The certificate this session's endpoint presents, which clients pin. A host's
    /// own seat is bound to it.
    pub fn certificate_der(&self) -> Vec<u8> {
        self.transport.certificate_der().to_vec()
    }

    /// Accepts the next peer only if it proves a seat: a credential in the group and a
    /// nullifier no one in this match holds. A peer that fails is disconnected and never
    /// joins the session. Every admitted peer is then sent the updated roster.
    pub async fn accept_admitted_peer(
        &mut self,
        gate: &mut crate::admission::HostGate,
    ) -> Result<PeerAddr> {
        let peer = self.transport.accept_peer().await?;
        let addr = PeerAddr(peer.addr.to_string());
        if let Err(err) = gate.admit(&peer).await {
            warn!(peer = %addr.0, error = %err, "peer refused a seat");
            peer.connection.close(0u32.into(), b"admission refused");
            return Err(err);
        }
        info!(peer = %addr.0, "peer admitted");
        self.connected.insert(addr.clone(), peer);
        self.transition(SessionStatus::Lobby);
        for peer in self.connected.values() {
            crate::admission::send_roster(peer, gate.roster()).await?;
        }
        Ok(addr)
    }

    /// The client's side: proves a seat on the connection to the host, and on
    /// admission returns its nullifier and the first roster, already checked.
    pub async fn request_admission(
        &self,
        host: &PeerAddr,
        host_cert_der: &[u8],
        keys: &crate::admission::AdmissionKeys,
        credential: &crate::admission::Credential,
        root: crate::admission::Root,
        scope: crate::admission::Scope,
    ) -> Result<(crate::admission::Nullifier, crate::admission::Roster)> {
        let peer = self
            .connected
            .get(host)
            .ok_or_else(|| anyhow!("not connected to host {}", host.0))?;
        let (_, nullifier) =
            crate::admission::request_admission(peer, keys, credential, root, scope).await?;
        let roster = crate::admission::receive_roster(peer).await?;
        keys.verifier()
            .verify_roster(&root, &scope, host_cert_der, &nullifier, &roster)
            .map_err(|e| anyhow!("the host's roster does not check out: {e}"))?;
        Ok((nullifier, roster))
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(discovery) = self.discovery.as_mut() {
            discovery.stop();
        }
    }
}
