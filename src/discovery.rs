use crate::{SessionId, SERVICE_TYPE};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use mdns_sd::{ResolvedService, ScopedIp, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub peer_id: String,
    pub display_name: String,
    pub session_id: SessionId,
    pub mode: String,
    pub metadata: HashMap<String, String>,
    pub capacity: u8,
    pub current_players: u8,
    pub addr: SocketAddr,
    pub cert_der: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    PeerFound(PeerInfo),
    PeerLost(String),
}

pub struct PeerDiscovery {
    daemon: ServiceDaemon,
    peers: Arc<Mutex<HashMap<String, PeerInfo>>>,
    events_tx: broadcast::Sender<DiscoveryEvent>,
    browse_thread: Option<JoinHandle<()>>,
    service_type: String,
    registered_fullname: Option<String>,
}

impl PeerDiscovery {
    pub fn start() -> Result<Self> {
        Self::start_with_service(SERVICE_TYPE)
    }

    pub fn start_with_service(service_type: &str) -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        let receiver = daemon.browse(service_type)?;
        let peers = Arc::new(Mutex::new(HashMap::new()));
        let (events_tx, _) = broadcast::channel(128);

        let peers_clone = Arc::clone(&peers);
        let events_clone = events_tx.clone();
        let browse_thread = thread::spawn(move || {
            while let Ok(event) = receiver.recv() {
                match event {
                    ServiceEvent::ServiceResolved(info) => {
                        if let Some(peer) = peer_from_service(&info) {
                            peers_clone
                                .lock()
                                .expect("discovery peers mutex poisoned")
                                .insert(peer.peer_id.clone(), peer.clone());
                            let _ = events_clone.send(DiscoveryEvent::PeerFound(peer));
                        }
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        let maybe_removed_peer = {
                            let mut peers =
                                peers_clone.lock().expect("discovery peers mutex poisoned");
                            let match_id = peers
                                .iter()
                                .find(|(_, peer)| {
                                    fullname.contains(&peer.peer_id)
                                        || fullname.contains(&peer.display_name)
                                })
                                .map(|(id, _)| id.clone());
                            match_id.and_then(|id| peers.remove(&id).map(|peer| peer.peer_id))
                        };
                        if let Some(peer_id) = maybe_removed_peer {
                            let _ = events_clone.send(DiscoveryEvent::PeerLost(peer_id));
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            daemon,
            peers,
            events_tx,
            browse_thread: Some(browse_thread),
            service_type: service_type.to_string(),
            registered_fullname: None,
        })
    }

    pub fn advertise(
        &mut self,
        peer_id: &str,
        display_name: &str,
        session_id: SessionId,
        mode: &str,
        metadata: &HashMap<String, String>,
        capacity: u8,
        current_players: u8,
        port: u16,
        cert_der: &[u8],
    ) -> Result<()> {
        let mut properties = HashMap::new();
        properties.insert("peer_id".to_string(), peer_id.to_string());
        properties.insert("display_name".to_string(), display_name.to_string());
        properties.insert("session_id".to_string(), session_id.0.to_string());
        properties.insert("mode".to_string(), mode.to_string());
        let mut meta_keys = Vec::new();
        for (key, value) in metadata {
            let normalized = key.replace(',', "_");
            meta_keys.push(normalized.clone());
            properties.insert(format!("meta_{normalized}"), value.clone());
        }
        properties.insert("_meta_keys".to_string(), meta_keys.join(","));
        properties.insert("capacity".to_string(), capacity.to_string());
        properties.insert("players".to_string(), current_players.to_string());
        let cert_b64 = STANDARD.encode(cert_der);
        let cert_chunks: Vec<String> = cert_b64
            .as_bytes()
            .chunks(200)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        properties.insert("cert_chunks".to_string(), cert_chunks.len().to_string());
        for (index, chunk) in cert_chunks.iter().enumerate() {
            properties.insert(format!("cert_{index}"), chunk.clone());
        }
        let host_name = format!("{peer_id}.local.");
        let instance_name = format!("localpong-{peer_id}");
        let service = ServiceInfo::new(
            &self.service_type,
            &instance_name,
            &host_name,
            "0.0.0.0",
            port,
            properties,
        )?
        .enable_addr_auto();
        self.registered_fullname = Some(service.get_fullname().to_string());
        self.daemon.register(service)?;
        Ok(())
    }

    pub fn events(&self) -> broadcast::Receiver<DiscoveryEvent> {
        self.events_tx.subscribe()
    }

    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers
            .lock()
            .expect("discovery peers mutex poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn stop(&mut self) {
        if let Some(fullname) = self.registered_fullname.take() {
            if let Ok(rx) = self.daemon.unregister(&fullname) {
                let _ = rx.recv();
            }
        }
        let _ = self.daemon.stop_browse(&self.service_type);
        if let Ok(status) = self.daemon.shutdown() {
            let _ = status.recv();
        }
        if let Some(handle) = self.browse_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PeerDiscovery {
    fn drop(&mut self) {
        self.stop();
    }
}

fn peer_from_service(service: &ResolvedService) -> Option<PeerInfo> {
    let ip = select_best_service_ip(service)
        .or_else(|| service.host.parse::<IpAddr>().ok())
        .filter(|ip| is_usable_remote_ip(*ip))?;

    let txt = &service.txt_properties;
    let peer_id = txt.get_property_val_str("peer_id")?.to_string();
    let display_name = txt
        .get_property_val_str("display_name")
        .unwrap_or("unknown")
        .to_string();
    let session_raw = txt.get_property_val_str("session_id")?;
    let session_id = SessionId(session_raw.parse().ok()?);
    let mode = txt
        .get_property_val_str("mode")
        .unwrap_or("traditional")
        .to_string();
    let metadata = txt
        .get_property_val_str("_meta_keys")
        .map(|raw_keys| {
            raw_keys
                .split(',')
                .filter(|key| !key.is_empty())
                .filter_map(|key| {
                    txt.get_property_val_str(&format!("meta_{key}"))
                        .map(|val| (key.to_string(), val.to_string()))
                })
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let capacity = txt
        .get_property_val_str("capacity")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(4);
    let current_players = txt
        .get_property_val_str("players")
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(1);
    let cert_der = decode_cert_from_txt(txt).unwrap_or_default();

    Some(PeerInfo {
        peer_id,
        display_name,
        session_id,
        mode,
        metadata,
        capacity,
        current_players,
        addr: SocketAddr::new(ip, service.port),
        cert_der,
    })
}

fn decode_cert_from_txt(txt: &mdns_sd::TxtProperties) -> Option<Vec<u8>> {
    if let Some(chunk_count_raw) = txt.get_property_val_str("cert_chunks") {
        let chunk_count = chunk_count_raw.parse::<usize>().ok()?;
        if chunk_count > 0 {
            let mut joined = String::new();
            for index in 0..chunk_count {
                let part = txt.get_property_val_str(&format!("cert_{index}"))?;
                joined.push_str(part);
            }
            if let Ok(bytes) = STANDARD.decode(joined.as_bytes()) {
                return Some(bytes);
            }
        }
    }

    txt.get_property_val_str("cert_der")
        .and_then(|v| STANDARD.decode(v).ok())
}

fn scoped_ip_to_ip(ip: &ScopedIp) -> Option<IpAddr> {
    match ip {
        ScopedIp::V4(v4) => Some(IpAddr::V4(*v4.addr())),
        ScopedIp::V6(v6) => Some(IpAddr::V6(*v6.addr())),
        _ => None,
    }
}

fn select_best_service_ip(service: &ResolvedService) -> Option<IpAddr> {
    let mut best_ip = None;
    let mut best_score = i32::MIN;
    for ip in service.addresses.iter().filter_map(scoped_ip_to_ip) {
        let score = ip_priority(ip);
        if score > best_score {
            best_score = score;
            best_ip = Some(ip);
        }
    }
    best_ip
}

fn is_usable_remote_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && !v4.is_loopback(),
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_loopback(),
    }
}

fn ip_priority(ip: IpAddr) -> i32 {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() || v4.is_unspecified() {
                0
            } else if v4.is_private() {
                100
            } else if v4.is_link_local() {
                60
            } else {
                80
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                0
            } else if v6.is_unicast_link_local() {
                40
            } else {
                70
            }
        }
    }
}
