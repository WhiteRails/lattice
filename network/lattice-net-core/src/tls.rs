use std::io::{BufReader, Cursor};
use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use thiserror::Error;
use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

use crate::LNP_ALPN;

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

pub fn verify_connection_spki(connection: &quinn::Connection, expected_sha256: &str) -> Result<(), TlsConfigError> {
    let identity = connection.peer_identity().ok_or(TlsConfigError::PinMismatch)?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| TlsConfigError::PinMismatch)?;
    let leaf = certificates.first().ok_or(TlsConfigError::PinMismatch)?;
    parse_x509_certificate(leaf.as_ref()).map_err(|_| TlsConfigError::PinMismatch)?;
    let actual = spki_sha256_from_der(leaf.as_ref())?;
    if actual.eq_ignore_ascii_case(expected_sha256) { Ok(()) } else { Err(TlsConfigError::PinMismatch) }
}

pub fn spki_sha256_from_der(certificate_der: &[u8]) -> Result<String, TlsConfigError> {
    let (_, certificate) = parse_x509_certificate(certificate_der).map_err(|_| TlsConfigError::InvalidCertificate)?;
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
    if certs.is_empty() { return Err(TlsConfigError::InvalidCertificate); }
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
    if added == 0 { return Err(TlsConfigError::InvalidCertificate); }
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
    let crypto = QuicClientConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
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
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| TlsConfigError::Config(e.to_string()))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let transport = Arc::get_mut(&mut server.transport).expect("new server transport is unique");
    transport.datagram_receive_buffer_size(Some(16 * 1024 * 1024));
    transport.datagram_send_buffer_size(16 * 1024 * 1024);
    Ok(server)
}
