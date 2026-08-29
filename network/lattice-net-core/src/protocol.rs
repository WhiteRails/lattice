use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{LNP_LINK_MTU, LNP_VERSION};

pub const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;
pub const CONTROL_HEADER_BYTES: usize = 4;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlFrame {
    ClientHello {
        version: u8,
        profile_id: Uuid,
        agent_lease: Option<String>,
    },
    ServerHello {
        version: u8,
        mtu: u16,
        policy_version: u64,
    },
    RouteVersion {
        version: u64,
        valid_until_unix: i64,
    },
    KeepAlive {
        unix_time: i64,
    },
    Error {
        code: String,
        message: String,
    },
}

impl ControlFrame {
    pub fn client_hello(profile_id: Uuid, agent_lease: Option<String>) -> Self {
        Self::ClientHello {
            version: LNP_VERSION,
            profile_id,
            agent_lease,
        }
    }

    pub fn server_hello(policy_version: u64) -> Self {
        Self::ServerHello {
            version: LNP_VERSION,
            mtu: LNP_LINK_MTU,
            policy_version,
        }
    }
}

#[derive(Debug, Error)]
pub enum ControlFrameError {
    #[error("control frame exceeds {MAX_CONTROL_FRAME_BYTES} bytes")]
    TooLarge,
    #[error("incomplete control frame")]
    Incomplete,
    #[error("invalid control frame: {0}")]
    Invalid(#[from] serde_json::Error),
}

pub fn encode_control(frame: &ControlFrame) -> Result<Vec<u8>, ControlFrameError> {
    let payload = serde_json::to_vec(frame)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::TooLarge);
    }
    let mut out = Vec::with_capacity(CONTROL_HEADER_BYTES + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

pub fn decode_control(input: &[u8]) -> Result<(ControlFrame, usize), ControlFrameError> {
    if input.len() < CONTROL_HEADER_BYTES {
        return Err(ControlFrameError::Incomplete);
    }
    let payload_len = u32::from_be_bytes(input[..4].try_into().unwrap()) as usize;
    if payload_len > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::TooLarge);
    }
    let consumed = CONTROL_HEADER_BYTES + payload_len;
    if input.len() < consumed {
        return Err(ControlFrameError::Incomplete);
    }
    let frame = serde_json::from_slice(&input[4..consumed])?;
    Ok((frame, consumed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_round_trip_is_length_delimited() {
        let frame = ControlFrame::client_hello(Uuid::nil(), None);
        let encoded = encode_control(&frame).unwrap();
        let (decoded, consumed) = decode_control(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn oversized_length_is_rejected_before_json_parsing() {
        let input = ((MAX_CONTROL_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert!(matches!(decode_control(&input), Err(ControlFrameError::TooLarge)));
    }
}

