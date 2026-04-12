use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuinnDatagram {
    pub payload: Vec<u8>,
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
}

pub struct QuinnTransport {
    endpoint: Endpoint,
    cert: CertificateDer<'static>,
}

impl QuinnTransport {
    pub fn bind(bind_addr: SocketAddr) -> Result<Self> {
        let (server_config, cert) = make_server_config()?;
        let endpoint = Endpoint::server(server_config, bind_addr)
            .with_context(|| format!("failed to bind QUIC endpoint at {bind_addr}"))?;
        Ok(Self { endpoint, cert })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("failed to read local endpoint address")
    }

    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.cert.clone()
    }

    pub async fn accept_peer(&self) -> Result<QuinnPeer> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .context("endpoint closed while waiting for peer")?;

        let connection = incoming.await.context("incoming peer handshake failed")?;
        let addr = connection.remote_address();
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
        let mut root_store = RootCertStore::empty();
        root_store
            .add(remote_cert)
            .context("failed to add remote certificate to trust store")?;
        let client_config = ClientConfig::with_root_certificates(Arc::new(root_store))
            .context("failed to build QUIC client configuration")?;

        let connecting = self
            .endpoint
            .connect_with(client_config, remote_addr, server_name)
            .with_context(|| format!("failed to start QUIC connection to {remote_addr}"))?;

        let connection = connecting.await.context("quinn connect failed")?;
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

fn make_server_config() -> Result<(ServerConfig, CertificateDer<'static>)> {
    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string(), "localpong".to_string()])
            .context("failed to generate self-signed certificate")?;

    let cert_der = cert.der().clone();
    let pkcs8 = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
    let key_der = PrivateKeyDer::from(pkcs8);

    let server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)
        .context("failed to create quinn server config")?;
    Ok((server_config, cert_der))
}
