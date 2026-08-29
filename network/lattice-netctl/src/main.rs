use std::fs;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer, SigningKey};
use lattice_net_core::profile::{EnrollmentBundle, EnrollmentPayload};
use lattice_net_core::tls::spki_sha256_from_der;
use rand::rngs::OsRng;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};
use pkcs8::LineEnding;

#[derive(Debug, Parser)]
#[command(name = "lattice-netctl", about = "Operator PKI and signed-profile tooling for LNP/1")]
struct Cli {
    #[command(subcommand)] command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    PkiInit {
        #[arg(long)] out: PathBuf,
        #[arg(long)] organization: String,
    },
    CertificateCsr {
        #[arg(long)] name: String,
        #[arg(long)] kind: CertificateKind,
        #[arg(long)] key_out: PathBuf,
        #[arg(long)] csr_out: PathBuf,
    },
    CertificateSign {
        #[arg(long)] pki: PathBuf,
        #[arg(long)] csr: PathBuf,
        #[arg(long)] kind: CertificateKind,
        #[arg(long)] cert_out: PathBuf,
    },
    ProfileSign {
        #[arg(long)] pki: PathBuf,
        #[arg(long)] template: PathBuf,
        #[arg(long)] client_cert: PathBuf,
        #[arg(long)] out: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CertificateKind { Client, Server }

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::PkiInit { out, organization } => pki_init(&out, &organization)?,
        Command::CertificateCsr { name, kind, key_out, csr_out } => certificate_csr(&name, kind, &key_out, &csr_out)?,
        Command::CertificateSign { pki, csr, kind, cert_out } => certificate_sign(&pki, &csr, kind, &cert_out)?,
        Command::ProfileSign { pki, template, client_cert, out } => profile_sign(&pki, &template, &client_cert, &out)?,
    }
    Ok(())
}

fn pki_init(directory: &Path, organization: &str) -> Result<(), Box<dyn std::error::Error>> {
    if directory.exists() { return Err("refusing to overwrite an existing PKI directory".into()); }
    fs::create_dir_all(directory)?;
    set_private_directory(directory)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params.distinguished_name.push(DnType::OrganizationName, organization);
    params.distinguished_name.push(DnType::CommonName, format!("{organization} Lattice Root CA"));
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
    let ca_key = KeyPair::generate()?;
    let ca_cert = params.self_signed(&ca_key)?;
    write_new(&directory.join("tls-root-cert.pem"), ca_cert.pem().as_bytes(), false)?;
    write_new(&directory.join("tls-root-key.pem"), ca_key.serialize_pem().as_bytes(), true)?;

    let control_key = SigningKey::generate(&mut OsRng);
    write_new(
        &directory.join("control-signing-key.pem"),
        control_key.to_pkcs8_pem(LineEnding::LF)?.as_bytes(),
        true,
    )?;
    let public_b64 = STANDARD.encode(control_key.verifying_key().as_bytes());
    write_new(&directory.join("control-public-key.b64"), format!("{public_b64}\n").as_bytes(), false)?;
    let anchor = serde_json::json!({
        "version": 1,
        "control_public_key_b64": public_b64,
        "tls_root_spki_sha256": certificate_pin(ca_cert.pem().as_bytes())?,
        "created_at": Utc::now(),
    });
    write_new(&directory.join("pki-anchor.json"), serde_json::to_vec_pretty(&anchor)?.as_slice(), false)?;
    println!("initialized Lattice PKI at {}", directory.display());
    Ok(())
}

fn certificate_csr(name: &str, kind: CertificateKind, key_out: &Path, csr_out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() || name.len() > 253 { return Err("invalid certificate name".into()); }
    let sans = if matches!(kind, CertificateKind::Server) { vec![name.to_owned()] } else { Vec::new() };
    let mut params = CertificateParams::new(sans)?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.extended_key_usages.push(match kind {
        CertificateKind::Client => ExtendedKeyUsagePurpose::ClientAuth,
        CertificateKind::Server => ExtendedKeyUsagePurpose::ServerAuth,
    });
    let key = KeyPair::generate()?;
    let csr = params.serialize_request(&key)?;
    write_new(key_out, key.serialize_pem().as_bytes(), true)?;
    write_new(csr_out, csr.pem()?.as_bytes(), false)?;
    println!("created CSR {} and private key reference {}", csr_out.display(), key_out.display());
    Ok(())
}

fn certificate_sign(pki: &Path, csr_path: &Path, kind: CertificateKind, cert_out: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let ca_cert = fs::read_to_string(pki.join("tls-root-cert.pem"))?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(pki.join("tls-root-key.pem"))?)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert, ca_key)?;
    let mut request = CertificateSigningRequestParams::from_pem(&fs::read_to_string(csr_path)?)?;
    let expected = match kind { CertificateKind::Client => ExtendedKeyUsagePurpose::ClientAuth, CertificateKind::Server => ExtendedKeyUsagePurpose::ServerAuth };
    if !request.params.extended_key_usages.contains(&expected) { return Err("CSR extended key usage does not match requested certificate kind".into()); }
    request.params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    request.params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
    request.params.is_ca = IsCa::NoCa;
    let certificate = request.signed_by(&issuer)?;
    write_new(cert_out, certificate.pem().as_bytes(), false)?;
    println!("signed {} certificate {}", match kind { CertificateKind::Client => "client", CertificateKind::Server => "server" }, cert_out.display());
    Ok(())
}

fn profile_sign(pki: &Path, template: &Path, client_cert: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload: EnrollmentPayload = serde_json::from_slice(&fs::read(template)?)?;
    let control_pem = fs::read_to_string(pki.join("control-signing-key.pem"))?;
    let control_key = SigningKey::from_pkcs8_pem(&control_pem)?;
    payload.control_plane_key_b64 = STANDARD.encode(control_key.verifying_key().as_bytes());
    payload.tls_root_pem = fs::read_to_string(pki.join("tls-root-cert.pem"))?;
    payload.client_spki_sha256 = certificate_pin(&fs::read(client_cert)?)?;
    payload.signing_key_id = "lattice-control-1".to_owned();
    let payload_bytes = serde_json::to_vec(&payload)?;
    let bundle = EnrollmentBundle { payload, signature_b64: STANDARD.encode(control_key.sign(&payload_bytes).to_bytes()) };
    // The signing path runs the same semantic validation used by endpoints.
    bundle.verify(&control_key.verifying_key(), Utc::now())?;
    write_new(output, serde_json::to_vec_pretty(&bundle)?.as_slice(), false)?;
    println!("signed profile {}", output.display());
    Ok(())
}

fn certificate_pin(pem: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let der = rustls_pemfile::certs(&mut reader).next().ok_or("missing certificate")??;
    Ok(spki_sha256_from_der(der.as_ref())?)
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let parent = path.parent().ok_or("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
