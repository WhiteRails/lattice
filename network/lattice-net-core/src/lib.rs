//! Shared implementation of the Lattice Network Protocol (LNP/1).
//!
//! LNP deliberately delegates encryption and congestion control to QUIC/TLS
//! 1.3. This crate implements bounded packet framing, signed enrollment
//! profiles, network policy evaluation, and canonical `lttc://` handling.

pub mod audit;
pub mod lease;
pub mod packet;
pub mod policy;
pub mod profile;
pub mod protocol;
pub mod tls;
pub mod uri;

pub const LNP_ALPN: &[u8] = b"lattice-lnp/1";
pub const LNP_ENROLLMENT_ALPN: &[u8] = b"lattice-lnp-enroll/1";
pub const LNP_VERSION: u8 = 1;
pub const LNP_LINK_MTU: u16 = 1280;
