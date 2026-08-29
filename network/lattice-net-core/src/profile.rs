use std::collections::{BTreeMap, HashSet};
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
pub const ENROLLMENT_OFFER_VERSION: u8 = 1;
const SERVICE_IDENTITY_BYTES: usize = 32;
const SERVICE_IDENTITY_LABEL_BYTES: usize = 52;
const BASE32_LOWER: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

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
    /// Present only when this gateway explicitly terminates the inner HTTPS
    /// session. LNP/1 never infers HTTP actions from encrypted IP packets.
    #[serde(default)]
    pub http_policy: Option<HttpPolicy>,
}

/// Returns the self-authenticating Lattice hostname for a service TLS key.
///
/// The signed profile binds aliases to a SHA-256 SPKI pin already; encoding
/// that 32-byte commitment as unpadded RFC 4648 base32 gives a DNS label short
/// enough for `*.coral`. A peer proves ownership by presenting a certificate
/// with the pinned SPKI, so the virtual IP remains transport-only.
pub fn canonical_service_fqdn(spki_sha256: &str) -> Result<String, ProfileError> {
    validate_sha256_pin(spki_sha256)?;
    let mut commitment = [0u8; SERVICE_IDENTITY_BYTES];
    for (index, pair) in spki_sha256.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(ProfileError::InvalidPin)?;
        let low = hex_nibble(pair[1]).ok_or(ProfileError::InvalidPin)?;
        commitment[index] = high << 4 | low;
    }
    let label = base32_lower_no_padding(&commitment);
    debug_assert_eq!(label.len(), SERVICE_IDENTITY_LABEL_BYTES);
    let fqdn = format!("{label}.coral");
    if !valid_coral_name(&fqdn) {
        return Err(ProfileError::InvalidHostname);
    }
    Ok(fqdn)
}

/// Returns true only for the canonical, key-derived service hostname form.
///
/// A 32-byte commitment is 256 bits. Its unpadded base32 representation has
/// 52 characters, with the final character's low padding bit required to be
/// zero. Keeping that bit check prevents multiple spellings for one identity.
pub fn is_canonical_service_fqdn(value: &str) -> bool {
    let Some(label) = value.strip_suffix(".coral") else {
        return false;
    };
    if label.len() != SERVICE_IDENTITY_LABEL_BYTES
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    {
        return false;
    }
    BASE32_LOWER
        .iter()
        .position(|byte| *byte == label.as_bytes()[SERVICE_IDENTITY_LABEL_BYTES - 1])
        .is_some_and(|value| value & 1 == 0)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpPolicy {
    pub terminate_tls: bool,
    pub allowed_actions: Vec<String>,
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
    /// Profiles used by `lattice run` require a short-lived lease signed by
    /// the selected agent's existing Ed25519 identity key. Values are raw
    /// 32-byte Ed25519 public keys encoded as base64.
    #[serde(default)]
    pub require_agent_lease: bool,
    #[serde(default)]
    pub agent_lease_public_keys: BTreeMap<String, String>,
    /// A signed revocation update is represented by replacing the installed
    /// profile with the same identity and a populated timestamp. Endpoints
    /// reject it immediately; absence of updates is bounded by max_stale.
    #[serde(default)]
    pub revoked_at: Option<DateTime<Utc>>,
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

/// A signed, one-time offer used before a client possesses an mTLS
/// certificate. It carries only public trust material and the eventual
/// profile template; the private key is generated by the enrolling device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentOfferPayload {
    pub version: u8,
    pub profile_template: EnrollmentPayload,
    pub endpoint: SocketAddr,
    pub server_name: String,
    pub server_spki_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentOffer {
    pub payload: EnrollmentOfferPayload,
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
    #[error("profile is revoked")]
    Revoked,
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
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| ProfileError::InvalidControlKey)?;
        VerifyingKey::from_bytes(&bytes).map_err(|_| ProfileError::InvalidControlKey)
    }

    /// `trusted_key` must come from an operator-managed trust store or an
    /// explicit first-use fingerprint. The key embedded in the bundle is never
    /// trusted merely because it appears in the bundle.
    pub fn verify(
        &self,
        trusted_key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ProfileError> {
        self.validate_semantics(now)?;
        self.verify_signature(trusted_key)
    }

    pub fn verify_signature(&self, trusted_key: &VerifyingKey) -> Result<(), ProfileError> {
        if &self.embedded_control_key()? != trusted_key {
            return Err(ProfileError::InvalidControlKey);
        }
        let signature_bytes = STANDARD
            .decode(&self.signature_b64)
            .map_err(|_| ProfileError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ProfileError::InvalidSignature)?;
        trusted_key
            .verify(&self.canonical_payload()?, &signature)
            .map_err(|_| ProfileError::InvalidSignature)
    }

    pub fn verify_fresh(
        &self,
        trusted_key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ProfileError> {
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
        if payload.issued_at > now
            || payload.expires_at <= now
            || payload.expires_at <= payload.issued_at
        {
            return Err(ProfileError::Expired);
        }
        if payload.expires_at - payload.issued_at > Duration::days(MAX_CERTIFICATE_LIFETIME_DAYS) {
            return Err(ProfileError::Lifetime);
        }
        if payload.max_stale_seconds == 0 || payload.max_stale_seconds > DEFAULT_MAX_STALE_SECONDS {
            return Err(ProfileError::Expired);
        }
        if payload
            .revoked_at
            .is_some_and(|revoked_at| revoked_at <= now)
        {
            return Err(ProfileError::Revoked);
        }
        if payload.interface.mtu != crate::LNP_LINK_MTU
            || payload.interface.ipv4.is_none() && payload.interface.ipv6.is_none()
        {
            return Err(ProfileError::InvalidPolicy);
        }
        if payload.routes.len() > MAX_ROUTES
            || payload.services.len() > MAX_SERVICES
            || payload.gateways.is_empty()
        {
            return Err(ProfileError::Capacity);
        }
        payload
            .policy
            .validate()
            .map_err(|_| ProfileError::InvalidPolicy)?;
        let mut names = HashSet::new();
        let mut addresses = HashSet::new();
        for service in &payload.services {
            if !valid_service_fqdn(&service.fqdn) {
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
            canonical_service_fqdn(&service.tls_spki_sha256)?;
            if service.http_policy.as_ref().is_some_and(|policy| {
                !policy.terminate_tls
                    || policy.allowed_actions.len() > 256
                    || policy
                        .allowed_actions
                        .iter()
                        .any(|action| action.is_empty() || action.len() > 128)
            }) {
                return Err(ProfileError::InvalidPolicy);
            }
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
        if payload.require_agent_lease && payload.agent_lease_public_keys.is_empty() {
            return Err(ProfileError::InvalidPolicy);
        }
        for (agent_id, encoded_key) in &payload.agent_lease_public_keys {
            if agent_id.is_empty() || agent_id.len() > 128 {
                return Err(ProfileError::InvalidPolicy);
            }
            let raw = STANDARD
                .decode(encoded_key)
                .map_err(|_| ProfileError::InvalidPolicy)?;
            let bytes: [u8; 32] = raw.try_into().map_err(|_| ProfileError::InvalidPolicy)?;
            VerifyingKey::from_bytes(&bytes).map_err(|_| ProfileError::InvalidPolicy)?;
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String, ProfileError> {
        Ok(hex(&Sha256::digest(self.canonical_payload()?)))
    }
}

impl EnrollmentOffer {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProfileError> {
        if bytes.len() > MAX_PROFILE_BYTES {
            return Err(ProfileError::TooLarge);
        }
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>, ProfileError> {
        Ok(serde_json::to_vec(&self.payload)?)
    }

    pub fn verify(
        &self,
        trusted_key: &VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<(), ProfileError> {
        if self.payload.version != ENROLLMENT_OFFER_VERSION
            || self.payload.server_name.is_empty()
            || self.payload.server_name.len() > 253
        {
            return Err(ProfileError::UnsupportedVersion);
        }
        validate_sha256_pin(&self.payload.server_spki_sha256)?;
        let template = &self.payload.profile_template;
        let template_bundle = EnrollmentBundle {
            payload: template.clone(),
            signature_b64: String::new(),
        };
        if &template_bundle.embedded_control_key()? != trusted_key {
            return Err(ProfileError::InvalidControlKey);
        }
        template_bundle.validate_semantics(now)?;
        if now - template.issued_at > Duration::seconds(template.max_stale_seconds.into()) {
            return Err(ProfileError::Expired);
        }
        let signature_bytes = STANDARD
            .decode(&self.signature_b64)
            .map_err(|_| ProfileError::InvalidSignature)?;
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| ProfileError::InvalidSignature)?;
        trusted_key
            .verify(&self.canonical_payload()?, &signature)
            .map_err(|_| ProfileError::InvalidSignature)
    }

    /// The service produces the final bundle by replacing only the client
    /// certificate pin. Rejecting any other delta makes the signed offer the
    /// authority for routes, DNS, policy and Gateway identity.
    pub fn matches_issued_profile(&self, bundle: &EnrollmentBundle) -> bool {
        let mut expected = self.payload.profile_template.clone();
        expected.client_spki_sha256 = bundle.payload.client_spki_sha256.clone();
        expected == bundle.payload
    }
}

pub fn valid_lattice_fqdn(value: &str) -> bool {
    let Some(label) = value.strip_suffix(".lattice") else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Participant identity and delegated service names under `.coral`.
pub fn valid_coral_name(value: &str) -> bool {
    valid_dns_name_with_suffix(value, ".coral")
}

/// Registered names under `.reef`; ownership is anchored on-chain.
pub fn valid_reef_name(value: &str) -> bool {
    valid_dns_name_with_suffix(value, ".reef")
}

pub fn valid_service_fqdn(value: &str) -> bool {
    valid_lattice_fqdn(value) || valid_coral_name(value) || valid_reef_name(value)
}

fn valid_dns_name_with_suffix(value: &str, suffix: &str) -> bool {
    let Some(prefix) = value.strip_suffix(suffix) else {
        return false;
    };
    if prefix.is_empty() || prefix.len() > 253 {
        return false;
    }
    prefix.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}

fn validate_sha256_pin(value: &str) -> Result<(), ProfileError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ProfileError::InvalidPin);
    }
    Ok(())
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn base32_lower_no_padding(input: &[u8]) -> String {
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0u16;
    let mut bits = 0u8;
    for byte in input {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32_LOWER[((buffer >> bits) & 0x1f) as usize] as char);
        }
        buffer &= if bits == 0 { 0 } else { (1 << bits) - 1 };
    }
    if bits > 0 {
        output.push(BASE32_LOWER[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{NetworkPolicy, TunnelMode};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    fn signed_bundle(now: DateTime<Utc>, key: &SigningKey) -> EnrollmentBundle {
        let payload = EnrollmentPayload {
            version: 1,
            profile_id: Uuid::new_v4(),
            organization_id: "test".into(),
            issued_at: now,
            expires_at: now + Duration::days(30),
            max_stale_seconds: 3600,
            enrollment_url: "offline://test".into(),
            enrollment_token: STANDARD.encode([3u8; 32]),
            signing_key_id: "test-control".into(),
            control_plane_key_b64: STANDARD.encode(key.verifying_key().as_bytes()),
            tls_root_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".into(),
            client_spki_sha256: "00".repeat(32),
            require_agent_lease: false,
            agent_lease_public_keys: BTreeMap::new(),
            revoked_at: None,
            interface: InterfaceConfig {
                ipv4: Some("10.0.0.2/24".parse().unwrap()),
                ipv6: None,
                mtu: crate::LNP_LINK_MTU,
            },
            gateways: vec![GatewayConfig {
                address: "127.0.0.1:7443".parse().unwrap(),
                server_name: "gateway.test".into(),
                spki_sha256: "11".repeat(32),
            }],
            routes: vec![],
            services: vec![],
            policy: NetworkPolicy {
                version: 1,
                mode: TunnelMode::Split,
                allow: vec![],
                deny: vec![],
            },
        };
        let signature_b64 =
            STANDARD.encode(key.sign(&serde_json::to_vec(&payload).unwrap()).to_bytes());
        EnrollmentBundle {
            payload,
            signature_b64,
        }
    }

    #[test]
    fn lattice_fqdn_is_single_canonical_label() {
        assert!(valid_lattice_fqdn("echo.lattice"));
        assert!(valid_lattice_fqdn("my-service.lattice"));
        assert!(!valid_lattice_fqdn("A.lattice"));
        assert!(!valid_lattice_fqdn("a.b.lattice"));
        assert!(!valid_lattice_fqdn("-a.lattice"));
    }

    #[test]
    fn service_identity_is_a_stable_lattice_hostname() {
        assert_eq!(
            canonical_service_fqdn(&"00".repeat(32)).unwrap(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.coral"
        );
        assert_eq!(
            canonical_service_fqdn(&"ff".repeat(32)).unwrap(),
            "777777777777777777777777777777777777777777777777777q.coral"
        );
        assert!(is_canonical_service_fqdn(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.coral"
        ));
        assert!(!is_canonical_service_fqdn(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab.coral"
        ));
        assert!(valid_coral_name("alice.coral"));
        assert!(valid_coral_name("api.alice.coral"));
        assert!(valid_reef_name("clipma.reef"));
        assert!(!valid_coral_name("Alice.coral"));
        assert!(!valid_reef_name("a..reef"));
        assert!(canonical_service_fqdn("not-a-pin").is_err());
    }

    #[test]
    fn signatures_staleness_and_revocation_fail_closed() {
        let now = Utc::now();
        let key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let mut bundle = signed_bundle(now, &key);
        assert!(bundle.verify_fresh(&key.verifying_key(), now).is_ok());
        assert!(matches!(
            bundle.verify(&wrong_key.verifying_key(), now),
            Err(ProfileError::InvalidControlKey)
        ));
        assert!(matches!(
            bundle.verify_fresh(&key.verifying_key(), now + Duration::hours(2)),
            Err(ProfileError::Expired)
        ));
        bundle.payload.revoked_at = Some(now);
        bundle.signature_b64 = STANDARD.encode(
            key.sign(&serde_json::to_vec(&bundle.payload).unwrap())
                .to_bytes(),
        );
        assert!(bundle.verify_signature(&key.verifying_key()).is_ok());
        assert!(matches!(
            bundle.verify(&key.verifying_key(), now),
            Err(ProfileError::Revoked)
        ));
    }

    #[test]
    fn offer_binds_the_issued_profile_except_client_pin() {
        let now = Utc::now();
        let key = SigningKey::generate(&mut OsRng);
        let template = signed_bundle(now, &key).payload;
        let payload = EnrollmentOfferPayload {
            version: ENROLLMENT_OFFER_VERSION,
            profile_template: template.clone(),
            endpoint: "127.0.0.1:7442".parse().unwrap(),
            server_name: "enroll.test".into(),
            server_spki_sha256: "22".repeat(32),
        };
        let offer = EnrollmentOffer {
            signature_b64: STANDARD
                .encode(key.sign(&serde_json::to_vec(&payload).unwrap()).to_bytes()),
            payload,
        };
        assert!(offer.verify(&key.verifying_key(), now).is_ok());
        let mut issued = template;
        issued.client_spki_sha256 = "33".repeat(32);
        let bundle = EnrollmentBundle {
            signature_b64: STANDARD
                .encode(key.sign(&serde_json::to_vec(&issued).unwrap()).to_bytes()),
            payload: issued,
        };
        assert!(offer.matches_issued_profile(&bundle));
        let mut altered = bundle.clone();
        altered.payload.policy.version += 1;
        assert!(!offer.matches_issued_profile(&altered));
    }
}
