use std::io::{BufReader, Cursor};
use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::prelude::parse_x509_certificate;

use crate::{LNP_ALPN, LNP_ENROLLMENT_ALPN};

#[derive(Debug, Error)]
pub enum TlsConfigError {
    #[error("certificate PEM is invalid")]
    InvalidCertificate,
    #[error("private key PEM is invalid")]
    InvalidPrivateKey,
    #[error("TLS configuration failed: {0}")]
    Config(String),
    #[error("peer certificate pin does not match the signed profile")]
    PinMismatch,
}

pub fn verify_connection_spki(
    connection: &quinn::Connection,
    expected_sha256: &str,
) -> Result<(), TlsConfigError> {
    let identity = connection
        .peer_identity()
        .ok_or(TlsConfigError::PinMismatch)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| TlsConfigError::PinMismatch)?;
    let leaf = certificates.first().ok_or(TlsConfigError::PinMismatch)?;
    parse_x509_certificate(leaf.as_ref()).map_err(|_| TlsConfigError::PinMismatch)?;
    let actual = spki_sha256_from_der(leaf.as_ref())?;
    if actual.eq_ignore_ascii_case(expected_sha256) {
        Ok(())
    } else {
        Err(TlsConfigError::PinMismatch)
    }
}

pub fn spki_sha256_from_der(certificate_der: &[u8]) -> Result<String, TlsConfigError> {
    let (_, certificate) =
        parse_x509_certificate(certificate_der).map_err(|_| TlsConfigError::InvalidCertificate)?;
    Ok(Sha256::digest(certificate.public_key().raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

pub fn certificates(pem: &[u8]) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|_| TlsConfigError::InvalidCertificate)?;
    if certs.is_empty() {
        return Err(TlsConfigError::InvalidCertificate);
    }
    Ok(certs)
}

pub fn private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    let mut reader = BufReader::new(Cursor::new(pem));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|_| TlsConfigError::InvalidPrivateKey)?
        .ok_or(TlsConfigError::InvalidPrivateKey)
}

pub fn root_store(root_pem: &[u8]) -> Result<RootCertStore, TlsConfigError> {
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certificates(root_pem)?);
    if added == 0 {
        return Err(TlsConfigError::InvalidCertificate);
    }
    Ok(roots)
}

pub fn quinn_client_config(
    root_pem: &[u8],
    client_cert_pem: &[u8],
    client_key_pem: &[u8],
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let mut tls = ClientConfig::builder()
        .with_root_certificates(root_store(root_pem)?)
        .with_client_auth_cert(certificates(client_cert_pem)?, private_key(client_key_pem)?)
        .map_err(|e| TlsConfigError::Config(e.to_string()))?;
    tls.alpn_protocols = vec![LNP_ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(lnp_transport_config());
    Ok(config)
}

pub fn quinn_enrollment_client_config(
    root_pem: &[u8],
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let mut tls = ClientConfig::builder()
        .with_root_certificates(root_store(root_pem)?)
        .with_no_client_auth();
    tls.alpn_protocols = vec![LNP_ENROLLMENT_ALPN.to_vec()];
    let crypto =
        QuicClientConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

pub fn quinn_server_config(
    root_pem: &[u8],
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store(root_pem)?))
        .build()
        .map_err(|e| TlsConfigError::Config(e.to_string()))?;
    let mut tls = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(server_cert_pem)?, private_key(server_key_pem)?)
        .map_err(|e| TlsConfigError::Config(e.to_string()))?;
    tls.alpn_protocols = vec![LNP_ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut server.transport).expect("new server transport is unique");
    transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    transport.datagram_send_buffer_size(16 * 1024 * 1024);
    configure_lnp_transport(transport);
    Ok(server)
}

fn lnp_transport_config() -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    configure_lnp_transport(&mut transport);
    Arc::new(transport)
}

fn configure_lnp_transport(transport: &mut quinn::TransportConfig) {
    // TUN traffic can be idle for long periods. Retain NAT mappings and avoid
    // silently dropping a healthy VPN after Quinn's short default idle timer.
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(90)
                .try_into()
                .expect("90 second QUIC timeout is representable"),
        ))
        .keep_alive_interval(Some(Duration::from_secs(10)));
}

pub fn quinn_enrollment_server_config(
    server_cert_pem: &[u8],
    server_key_pem: &[u8],
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let mut tls = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates(server_cert_pem)?, private_key(server_key_pem)?)
        .map_err(|e| TlsConfigError::Config(e.to_string()))?;
    tls.alpn_protocols = vec![LNP_ENROLLMENT_ALPN.to_vec()];
    let crypto =
        QuicServerConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    #[test]
    fn certificate_spki_pin_is_stable_and_invalid_pem_fails() {
        let mut params = CertificateParams::new(vec!["gateway.test".into()]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let der = cert.der();
        let first = spki_sha256_from_der(der.as_ref()).unwrap();
        let second = spki_sha256_from_der(der.as_ref()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(root_store(cert.pem().as_bytes()).is_ok());
        assert!(root_store(b"not a certificate").is_err());
        assert!(private_key(key.serialize_pem().as_bytes()).is_ok());
    }
}
