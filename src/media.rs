use crate::{FlowDatagram, FlowId, FlowKind};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaStreamType {
    Audio,
    Video,
    Data,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl Default for RtpHeader {
    fn default() -> Self {
        Self {
            version: 2,
            marker: false,
            payload_type: 0,
            sequence_number: 0,
            timestamp: 0,
            ssrc: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport { ssrc: u32, ntp_timestamp_ns: u64, rtp_timestamp: u32 },
    ReceiverReport { ssrc: u32, fraction_lost: u8, packets_lost: u32, jitter: u32 },
    SourceDescription { ssrc: u32, cname: String },
    Goodbye { sources: Vec<u32>, reason: Option<String> },
    ApplicationDefined { subtype: u8, name: [u8; 4], data: Vec<u8> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaFrame {
    pub stream_id: FlowId,
    pub stream_type: MediaStreamType,
    pub rtp: RtpPacket,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaDatagram {
    Rtp(MediaFrame),
    Rtcp { stream_id: FlowId, packet: RtcpPacket },
}

impl MediaFrame {
    pub fn audio_opus(stream_id: FlowId, sequence_number: u16, timestamp: u32, ssrc: u32, payload: Vec<u8>) -> Self {
        Self {
            stream_id,
            stream_type: MediaStreamType::Audio,
            rtp: RtpPacket {
                header: RtpHeader {
                    payload_type: 111,
                    sequence_number,
                    timestamp,
                    ssrc,
                    ..RtpHeader::default()
                },
                payload,
            },
        }
    }
}

impl MediaDatagram {
    pub fn flow_id(&self) -> FlowId {
        match self {
            MediaDatagram::Rtp(frame) => frame.stream_id,
            MediaDatagram::Rtcp { stream_id, .. } => *stream_id,
        }
    }

    pub fn into_flow_datagram(&self) -> Result<FlowDatagram> {
        let payload = bincode::serde::encode_to_vec(self, bincode::config::standard())
            .context("failed to serialize media datagram")?;

        Ok(FlowDatagram {
            flow_id: self.flow_id(),
            kind: FlowKind::Media,
            payload,
        })
    }

    pub fn from_flow_datagram(datagram: &FlowDatagram) -> Result<Option<Self>> {
        if datagram.kind != FlowKind::Media {
            return Ok(None);
        }

        let (media, _) = bincode::serde::decode_from_slice::<MediaDatagram, _>(
            &datagram.payload,
            bincode::config::standard(),
        )
        .context("failed to decode media datagram")?;

        Ok(Some(media))
    }
}