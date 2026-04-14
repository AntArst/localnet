use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{
    congestion, ClientConfig, Connection, ConnectionStats, Endpoint, RecvStream, SendStream,
    ServerConfig, TransportConfig, VarInt,
};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuinnDatagram {
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum QuinnCongestionController {
    Bbr,
    Cubic,
    NewReno,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuinnTransportConfig {
    pub congestion_controller: QuinnCongestionController,
    pub keep_alive_interval_ms: Option<u64>,
    pub datagram_receive_buffer_size: Option<usize>,
    pub datagram_send_buffer_size: usize,
    pub initial_mtu: Option<u16>,
    pub min_mtu: Option<u16>,
    pub max_concurrent_uni_streams: Option<u32>,
    pub max_concurrent_bidi_streams: Option<u32>,
    pub send_fairness: bool,
}

impl Default for QuinnTransportConfig {
    fn default() -> Self {
        Self {
            congestion_controller: QuinnCongestionController::Bbr,
            keep_alive_interval_ms: Some(5_000),
            datagram_receive_buffer_size: Some(512 * 1024),
            datagram_send_buffer_size: 512 * 1024,
            initial_mtu: None,
            min_mtu: None,
            max_concurrent_uni_streams: Some(128),
            max_concurrent_bidi_streams: Some(32),
            send_fairness: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    JoinRequest {
        peer_name: String,
        session_token: String,
    },
    JoinAccepted {
        assigned_slot: usize,
        session_seed: u64,
    },
    JoinRejected {
        reason: String,
    },
    Ready {
        peer_id: String,
    },
    StartMatch,
    KeepAlive,
    Disconnect {
        reason: String,
    },
}

#[derive(Clone)]
pub struct QuinnPeer {
    pub addr: SocketAddr,
    pub connection: Connection,
}

impl QuinnPeer {
    pub async fn send_datagram(&self, bytes: Vec<u8>) -> Result<()> {
        self.connection
            .send_datagram(Bytes::from(bytes))
            .context("failed to send datagram")?;
        Ok(())
    }

    pub async fn receive_datagram(&self) -> Result<Vec<u8>> {
        let data = self
            .connection
            .read_datagram()
            .await
            .context("failed to read datagram")?;
        Ok(data.to_vec())
    }

    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream)> {
        self.connection
            .open_bi()
            .await
            .context("failed to open control stream")
    }

    pub async fn open_uni(&self) -> Result<SendStream> {
        self.connection
            .open_uni()
            .await
            .context("failed to open unidirectional stream")
    }

    pub fn stats(&self) -> ConnectionStats {
        self.connection.stats()
    }
}

pub struct QuinnTransport {
    endpoint: Endpoint,
    cert: CertificateDer<'static>,
    config: QuinnTransportConfig,
}

impl QuinnTransport {
    pub fn bind(bind_addr: SocketAddr, app_id: &str) -> Result<Self> {
        Self::bind_with_config(bind_addr, app_id, QuinnTransportConfig::default())
    }

    pub fn bind_with_config(
        bind_addr: SocketAddr,
        app_id: &str,
        config: QuinnTransportConfig,
    ) -> Result<Self> {
        let (server_config, cert) = make_server_config(app_id, &config)?;
        let endpoint = Endpoint::server(server_config, bind_addr)
            .with_context(|| format!("failed to bind QUIC endpoint at {bind_addr}"))?;
        info!(addr = %bind_addr, app_id = %app_id, "QUIC endpoint bound");
        Ok(Self {
            endpoint,
            cert,
            config,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read local endpoint address")
    }

    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    pub fn config(&self) -> &QuinnTransportConfig {
        &self.config
    }

    pub async fn accept_peer(&self) -> Result<QuinnPeer> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .context("endpoint closed while waiting for peer")?;

        let connection = incoming.await.context("incoming peer handshake failed")?;
        let addr = connection.remote_address();
        debug!(remote = %addr, "QUIC peer accepted");
        Ok(QuinnPeer { addr, connection })
    }

    pub async fn accept_peer_waiting(&self, wait_timeout_ms: u64) -> Result<Option<QuinnPeer>> {
        let incoming = match timeout(
            Duration::from_millis(wait_timeout_ms),
            self.endpoint.accept(),
        )
        .await
        {
            Ok(Some(incoming)) => incoming,
            Ok(None) => return Ok(None),
            Err(_) => return Ok(None),
        };

        let connection = incoming.await.context("incoming peer handshake failed")?;
        let addr = connection.remote_address();
        Ok(Some(QuinnPeer { addr, connection }))
    }

    pub async fn connect_peer(
        &self,
        remote_addr: SocketAddr,
        remote_cert: CertificateDer<'static>,
        server_name: &str,
    ) -> Result<QuinnPeer> {
        let client_config = make_client_config(remote_cert, &self.config)?;

        let connecting = self
            .endpoint
            .connect_with(client_config, remote_addr, server_name)
            .with_context(|| format!("failed to start QUIC connection to {remote_addr}"))?;

        let connection = connecting.await.context("quinn connect failed")?;
        debug!(remote = %remote_addr, "QUIC connection established");
        Ok(QuinnPeer {
            addr: remote_addr,
            connection,
        })
    }

    pub async fn connect_with_timeout(
        &self,
        remote_addr: SocketAddr,
        remote_cert: CertificateDer<'static>,
        server_name: &str,
        timeout_ms: u64,
    ) -> Result<QuinnPeer> {
        timeout(
            Duration::from_millis(timeout_ms),
            self.connect_peer(remote_addr, remote_cert, server_name),
        )
        .await
        .context("connection attempt timed out")?
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"session closed");
    }
}

impl Drop for QuinnTransport {
    fn drop(&mut self) {
        self.close();
    }
}

fn make_server_config(
    app_id: &str,
    config: &QuinnTransportConfig,
) -> Result<(ServerConfig, CertificateDer<'static>)> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string(), app_id.to_string()])
            .context("failed to generate self-signed certificate")?;

    let cert_der = cert.der().clone();
    let pkcs8 = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let key_der = PrivateKeyDer::from(pkcs8);

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)
        .context("failed to create quinn server config")?;
    server_config.transport_config(Arc::new(make_transport_config(config)));
    Ok((server_config, cert_der))
}

fn make_client_config(
    remote_cert: CertificateDer<'static>,
    config: &QuinnTransportConfig,
) -> Result<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(remote_cert)
        .context("failed to add remote certificate to trust store")?;
    let mut client_config = ClientConfig::with_root_certificates(Arc::new(root_store))
        .context("failed to build QUIC client configuration")?;
    client_config.transport_config(Arc::new(make_transport_config(config)));
    Ok(client_config)
}

fn make_transport_config(config: &QuinnTransportConfig) -> TransportConfig {
    let mut transport = TransportConfig::default();

    if let Some(keep_alive_interval_ms) = config.keep_alive_interval_ms {
        transport.keep_alive_interval(Some(Duration::from_millis(keep_alive_interval_ms)));
    }

    if let Some(datagram_receive_buffer_size) = config.datagram_receive_buffer_size {
        transport.datagram_receive_buffer_size(Some(datagram_receive_buffer_size));
    }

    transport.datagram_send_buffer_size(config.datagram_send_buffer_size);
    transport.send_fairness(config.send_fairness);

    if let Some(initial_mtu) = config.initial_mtu {
        transport.initial_mtu(initial_mtu);
    }

    if let Some(min_mtu) = config.min_mtu {
        transport.min_mtu(min_mtu);
    }

    if let Some(max_concurrent_uni_streams) = config.max_concurrent_uni_streams {
        transport.max_concurrent_uni_streams(VarInt::from_u32(max_concurrent_uni_streams));
    }

    if let Some(max_concurrent_bidi_streams) = config.max_concurrent_bidi_streams {
        transport.max_concurrent_bidi_streams(VarInt::from_u32(max_concurrent_bidi_streams));
    }

    let congestion_factory: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
        match config.congestion_controller {
            QuinnCongestionController::Bbr => Arc::new(congestion::BbrConfig::default()),
            QuinnCongestionController::Cubic => Arc::new(congestion::CubicConfig::default()),
            QuinnCongestionController::NewReno => Arc::new(congestion::NewRenoConfig::default()),
        };
    transport.congestion_controller_factory(congestion_factory);

    transport
}
