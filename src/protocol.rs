use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

const LOCALNET_WIRE_MAGIC: &[u8; 4] = b"LNET";
const LOCALNET_WIRE_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowId(pub u64);

impl FlowId {
    pub const GAMEPLAY: Self = Self(0);
    pub const CONTROL: Self = Self(1);
    pub const MEDIA: Self = Self(2);
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FlowKind {
    Gameplay,
    Control,
    Media,
    Custom(u16),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FlowDatagram {
    pub flow_id: FlowId,
    pub kind: FlowKind,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WireDatagramEnvelope {
    version: u8,
    datagram: FlowDatagram,
}

impl FlowDatagram {
    pub fn gameplay(payload: Vec<u8>) -> Self {
        Self {
            flow_id: FlowId::GAMEPLAY,
            kind: FlowKind::Gameplay,
            payload,
        }
    }

    pub fn encode_wire(&self) -> Result<Vec<u8>> {
        let envelope = WireDatagramEnvelope {
            version: LOCALNET_WIRE_VERSION,
            datagram: self.clone(),
        };
        let encoded = bincode::serde::encode_to_vec(&envelope, bincode::config::standard())
            .context("failed to serialize localnet datagram envelope")?;

        let mut bytes = Vec::with_capacity(LOCALNET_WIRE_MAGIC.len() + encoded.len());
        bytes.extend_from_slice(LOCALNET_WIRE_MAGIC);
        bytes.extend_from_slice(&encoded);
        Ok(bytes)
    }

    pub fn decode_wire(bytes: &[u8]) -> Result<Option<Self>> {
        if !bytes.starts_with(LOCALNET_WIRE_MAGIC) {
            return Ok(None);
        }

        let payload = &bytes[LOCALNET_WIRE_MAGIC.len()..];
        let (envelope, _) = bincode::serde::decode_from_slice::<WireDatagramEnvelope, _>(
            payload,
            bincode::config::standard(),
        )
        .context("failed to decode localnet datagram envelope")?;

        if envelope.version != LOCALNET_WIRE_VERSION {
            return Err(anyhow!(
                "unsupported localnet datagram version {}",
                envelope.version
            ));
        }

        Ok(Some(envelope.datagram))
    }
}