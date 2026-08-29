use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentLeasePayload {
    pub agent_id: String,
    pub profile_id: Uuid,
    pub namespace_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentLease {
    pub payload: AgentLeasePayload,
    pub signature_b64: String,
}

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("agent lease is invalid or expired")]
    Invalid,
    #[error("agent lease signature is invalid")]
    InvalidSignature,
    #[error("agent lease serialization failed")]
    Serialization(#[from] serde_json::Error),
}

impl AgentLease {
    pub fn verify(&self, key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), LeaseError> {
        if self.payload.issued_at > now
            || self.payload.expires_at <= now
            || self.payload.expires_at - self.payload.issued_at > Duration::minutes(5)
            || self.payload.agent_id.is_empty()
            || self.payload.namespace_id.is_empty()
            || self.payload.nonce_b64.len() < 22
            || self.payload.nonce_b64.len() > 128
        {
            return Err(LeaseError::Invalid);
        }
        let raw = STANDARD
            .decode(&self.signature_b64)
            .map_err(|_| LeaseError::InvalidSignature)?;
        let signature = Signature::from_slice(&raw).map_err(|_| LeaseError::InvalidSignature)?;
        key.verify(&serde_json::to_vec(&self.payload)?, &signature)
            .map_err(|_| LeaseError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    #[test]
    fn lease_is_short_lived_profile_bound_and_signed() {
        let now = Utc::now();
        let key = SigningKey::generate(&mut OsRng);
        let payload = AgentLeasePayload {
            agent_id: "agent-a".into(),
            profile_id: Uuid::new_v4(),
            namespace_id: "lattice-agent-a".into(),
            issued_at: now,
            expires_at: now + Duration::minutes(4),
            nonce_b64: STANDARD.encode([7u8; 24]),
        };
        let signature_b64 =
            STANDARD.encode(key.sign(&serde_json::to_vec(&payload).unwrap()).to_bytes());
        let lease = AgentLease {
            payload,
            signature_b64,
        };
        assert!(lease.verify(&key.verifying_key(), now).is_ok());
        assert!(lease
            .verify(&SigningKey::generate(&mut OsRng).verifying_key(), now)
            .is_err());
    }
}
