use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::policy::NetworkPolicy;

pub const PROFILE_VERSION: u8 = 1;
pub const MAX_PROFILE_BYTES: usize = 1024 * 1024;
pub const MAX_ROUTES: usize = 4_096;
pub const MAX_SERVICES: usize = 16_384;
pub const DEFAULT_MAX_STALE_SECONDS: u32 = 24 * 60 * 60;
pub const MAX_CERTIFICATE_LIFETIME_DAYS: i64 = 90;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub address: SocketAddr,
    pub server_name: String,
    pub spki_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceBinding {
    pub fqdn: String,
    pub addresses: Vec<IpAddr>,
    pub gateway: SocketAddr,
    pub tls_spki_sha256: String,
    pub policy_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InterfaceConfig {
    pub ipv4: Option<ipnet::Ipv4Net>,
    pub ipv6: Option<ipnet::Ipv6Net>,
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPayload {
    pub version: u8,
    pub profile_id: Uuid,
    pub organization_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub max_stale_seconds: u32,
    pub enrollment_url: String,
    pub enrollment_token: String,
    pub signing_key_id: String,
    pub control_plane_key_b64: String,
    pub tls_root_pem: String,
    /// SHA-256 of the installed profile certificate's DER SPKI. The gateway
    /// checks this after TLS validation so one organization client cannot
    /// claim another profile id in ClientHello.
    pub client_spki_sha256: String,
    pub interface: InterfaceConfig,
    pub gateways: Vec<GatewayConfig>,
    pub routes: Vec<IpNet>,
    pub services: Vec<ServiceBinding>,
    pub policy: NetworkPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub payload: EnrollmentPayload,
    pub signature_b64: String,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile exceeds {MAX_PROFILE_BYTES} bytes")]
    TooLarge,
    #[error("invalid profile JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported profile version")]
    UnsupportedVersion,
    #[error("profile is not currently valid")]
    Expired,
    #[error("profile lifetime exceeds {MAX_CERTIFICATE_LIFETIME_DAYS} days")]
    Lifetime,
    #[error("profile exceeds route or service limits")]
    Capacity,
    #[error("invalid Lattice hostname")]
    InvalidHostname,
    #[error("duplicate Lattice hostname or IP address")]
    DuplicateBinding,
    #[error("invalid gateway pin")]
    InvalidPin,
    #[error("profile signature is invalid")]
    InvalidSignature,
    #[error("control-plane key is invalid")]
    InvalidControlKey,
    #[error("network policy is invalid")]
    InvalidPolicy,
}

impl EnrollmentBundle {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge);
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>, ProfileError> {
        Ok(serde_json::to_vec(&self.payload)?)
    }

    pub fn embedded_control_key(&self) -> Result<VerifyingKey, ProfileError> {
        let raw = STANDARD
            .decode(&self.payload.control_plane_key_b64)
            .map_err(|_| ProfileError::InvalidControlKey)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| ProfileError::InvalidControlKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ProfileError::InvalidControlKey)
    }

    /// `trusted_key` must come from an operator-managed trust store or an
    /// explicit first-use fingerprint. The key embedded in the bundle is never
    /// trusted merely because it appears in the bundle.
    pub fn verify(&self, trusted_key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ProfileError> {
        self.validate_semantics(now)?;
        if &self.embedded_control_key()? != trusted_key {
            return Err(ProfileError::InvalidControlKey);
        }
        let signature_bytes = STANDARD.decode(&self.signature_b64).map_err(|_| ProfileError::InvalidSignature)?;
        let signature = Signature::from_slice(&signature_bytes).map_err(|_| ProfileError::InvalidSignature)?;
        trusted_key
            .verify(&self.canonical_payload()?, &signature)
            .map_err(|_| ProfileError::InvalidSignature)
    }

    pub fn verify_fresh(&self, trusted_key: &VerifyingKey, now: DateTime<Utc>) -> Result<(), ProfileError> {
        self.verify(trusted_key, now)?;
        if now - self.payload.issued_at > Duration::seconds(self.payload.max_stale_seconds.into()) {
            return Err(ProfileError::Expired);
        }
        Ok(())
    }

    pub fn validate_semantics(&self, now: DateTime<Utc>) -> Result<(), ProfileError> {
        let payload = &self.payload;
        if payload.version != PROFILE_VERSION {
            return Err(ProfileError::UnsupportedVersion);
        }
        if payload.issued_at > now || payload.expires_at <= now || payload.expires_at <= payload.issued_at {
            return Err(ProfileError::Expired);
        }
        if payload.expires_at - payload.issued_at > Duration::days(MAX_CERTIFICATE_LIFETIME_DAYS) {
            return Err(ProfileError::Lifetime);
        }
        if payload.max_stale_seconds == 0 || payload.max_stale_seconds > DEFAULT_MAX_STALE_SECONDS {
            return Err(ProfileError::Expired);
        }
        if payload.interface.mtu != crate::LNP_LINK_MTU
            || payload.interface.ipv4.is_none() && payload.interface.ipv6.is_none()
        {
            return Err(ProfileError::InvalidPolicy);
        }
        if payload.routes.len() > MAX_ROUTES || payload.services.len() > MAX_SERVICES || payload.gateways.is_empty() {
            return Err(ProfileError::Capacity);
        }
        payload.policy.validate().map_err(|_| ProfileError::InvalidPolicy)?;
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for service in &payload.services {
            if !valid_lattice_fqdn(&service.fqdn) {
                return Err(ProfileError::InvalidHostname);
            }
            if !names.insert(service.fqdn.as_str()) {
                return Err(ProfileError::DuplicateBinding);
            }
            for address in &service.addresses {
                if !addresses.insert(*address) {
                    return Err(ProfileError::DuplicateBinding);
                }
            }
            validate_sha256_pin(&service.tls_spki_sha256)?;
        }
        for gateway in &payload.gateways {
            if gateway.server_name.is_empty() || gateway.server_name.len() > 253 {
                return Err(ProfileError::InvalidHostname);
            }
            validate_sha256_pin(&gateway.spki_sha256)?;
        }
        if !payload.tls_root_pem.contains("BEGIN CERTIFICATE") {
            return Err(ProfileError::InvalidPin);
        }
        validate_sha256_pin(&payload.client_spki_sha256)?;
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, ProfileError> {
        Ok(hex(&Sha256::digest(self.canonical_payload()?)))
    }
}

pub fn valid_lattice_fqdn(value: &str) -> bool {
    let Some(label) = value.strip_suffix(".lattice") else { return false; };
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn validate_sha256_pin(value: &str) -> Result<(), ProfileError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProfileError::InvalidPin);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lattice_fqdn_is_single_canonical_label() {
        assert!(valid_lattice_fqdn("echo.lattice"));
        assert!(valid_lattice_fqdn("my-service.lattice"));
        assert!(!valid_lattice_fqdn("A.lattice"));
        assert!(!valid_lattice_fqdn("a.b.lattice"));
        assert!(!valid_lattice_fqdn("-a.lattice"));
    }
}
