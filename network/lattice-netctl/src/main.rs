use std::fs;
use std::io::{BufReader, Cursor};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signer, SigningKey};
use ipnet::IpNet;
use lattice_net_core::policy::{IpProtocol, NetworkRule, TunnelMode};
use lattice_net_core::profile::{
    EnrollmentBundle, EnrollmentOffer, EnrollmentOfferPayload, EnrollmentPayload,
};
use lattice_net_core::protocol::{
    decode_enrollment, encode_enrollment, EnrollmentFrame, MAX_ENROLLMENT_FRAME_BYTES,
};
use lattice_net_core::tls::{quinn_enrollment_server_config, spki_sha256_from_der};
use pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Parser)]
#[command(
    name = "lattice-netctl",
    about = "Operator PKI and signed-profile tooling for LNP/1"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    PkiInit {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        organization: String,
    },
    CertificateCsr {
        #[arg(long)]
        name: String,
        #[arg(long)]
        kind: CertificateKind,
        #[arg(long)]
        key_out: PathBuf,
        #[arg(long)]
        csr_out: PathBuf,
    },
    CertificateSign {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        csr: PathBuf,
        #[arg(long)]
        kind: CertificateKind,
        #[arg(long)]
        cert_out: PathBuf,
    },
    EnrollmentTokenIssue {
        #[arg(long)]
        pki: PathBuf,
    },
    ProfileSign {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        client_cert: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    ProfileRevoke {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Produces a full-tunnel template with an explicit CIDR egress allowlist.
    ProfileEgressAllow {
        #[arg(long)]
        template: PathBuf,
        #[arg(long = "cidr", required = true)]
        cidrs: Vec<String>,
        #[arg(long)]
        out: PathBuf,
    },
    EnrollmentOfferIssue {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        endpoint: SocketAddr,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        server_cert: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    EnrollmentServe {
        #[arg(long)]
        pki: PathBuf,
        #[arg(long)]
        offer: PathBuf,
        #[arg(long)]
        bind: SocketAddr,
        #[arg(long)]
        server_cert: PathBuf,
        #[arg(long)]
        server_key: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CertificateKind {
    Client,
    Server,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::PkiInit { out, organization } => pki_init(&out, &organization)?,
        Command::CertificateCsr {
            name,
            kind,
            key_out,
            csr_out,
        } => certificate_csr(&name, kind, &key_out, &csr_out)?,
        Command::CertificateSign {
            pki,
            csr,
            kind,
            cert_out,
        } => certificate_sign(&pki, &csr, kind, &cert_out)?,
        Command::EnrollmentTokenIssue { pki } => enrollment_token_issue(&pki)?,
        Command::ProfileSign {
            pki,
            template,
            client_cert,
            out,
        } => profile_sign(&pki, &template, &client_cert, &out)?,
        Command::ProfileRevoke { pki, profile, out } => profile_revoke(&pki, &profile, &out)?,
        Command::ProfileEgressAllow {
            template,
            cidrs,
            out,
        } => profile_egress_allow(&template, &cidrs, &out)?,
        Command::EnrollmentOfferIssue {
            pki,
            template,
            endpoint,
            server_name,
            server_cert,
            out,
        } => enrollment_offer_issue(&pki, &template, endpoint, &server_name, &server_cert, &out)?,
        Command::EnrollmentServe {
            pki,
            offer,
            bind,
            server_cert,
            server_key,
        } => enrollment_serve(&pki, &offer, bind, &server_cert, &server_key).await?,
    }
    Ok(())
}

fn pki_init(directory: &Path, organization: &str) -> Result<(), Box<dyn std::error::Error>> {
    if directory.exists() {
        return Err("refusing to overwrite an existing PKI directory".into());
    }
    fs::create_dir_all(directory)?;
    set_private_directory(directory)?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
    params
        .distinguished_name
        .push(DnType::OrganizationName, organization);
    params.distinguished_name.push(
        DnType::CommonName,
        format!("{organization} Lattice Root CA"),
    );
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = OffsetDateTime::now_utc() + Duration::days(3650);
    let ca_key = KeyPair::generate()?;
    let ca_cert = params.self_signed(&ca_key)?;
    write_new(
        &directory.join("tls-root-cert.pem"),
        ca_cert.pem().as_bytes(),
        false,
    )?;
    write_new(
        &directory.join("tls-root-key.pem"),
        ca_key.serialize_pem().as_bytes(),
        true,
    )?;

    let root_issuer =
        Issuer::from_ca_cert_pem(&ca_cert.pem(), KeyPair::from_pem(&ca_key.serialize_pem())?)?;
    let mut intermediate_params = CertificateParams::new(Vec::<String>::new())?;
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params
        .distinguished_name
        .push(DnType::OrganizationName, organization);
    intermediate_params.distinguished_name.push(
        DnType::CommonName,
        format!("{organization} Lattice Profile CA"),
    );
    intermediate_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    intermediate_params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    intermediate_params.not_after = OffsetDateTime::now_utc() + Duration::days(1825);
    let intermediate_key = KeyPair::generate()?;
    let intermediate_cert = intermediate_params.signed_by(&intermediate_key, &root_issuer)?;
    write_new(
        &directory.join("tls-profile-ca-cert.pem"),
        intermediate_cert.pem().as_bytes(),
        false,
    )?;
    write_new(
        &directory.join("tls-profile-ca-key.pem"),
        intermediate_key.serialize_pem().as_bytes(),
        true,
    )?;

    let control_key = SigningKey::generate(&mut OsRng);
    write_new(
        &directory.join("control-signing-key.pem"),
        control_key.to_pkcs8_pem(LineEnding::LF)?.as_bytes(),
        true,
    )?;
    let public_b64 = STANDARD.encode(control_key.verifying_key().as_bytes());
    write_new(
        &directory.join("control-public-key.b64"),
        format!("{public_b64}\n").as_bytes(),
        false,
    )?;
    let anchor = serde_json::json!({
        "version": 1,
        "control_public_key_b64": public_b64,
        "tls_root_spki_sha256": certificate_pin(ca_cert.pem().as_bytes())?,
        "created_at": Utc::now(),
    });
    write_new(
        &directory.join("pki-anchor.json"),
        serde_json::to_vec_pretty(&anchor)?.as_slice(),
        false,
    )?;
    println!("initialized Lattice PKI at {}", directory.display());
    Ok(())
}

fn profile_egress_allow(
    template_path: &Path,
    cidrs: &[String],
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut template: EnrollmentPayload = serde_json::from_slice(&fs::read(template_path)?)?;
    if template.policy.mode != TunnelMode::Full {
        return Err("egress allowlists require an explicit full-tunnel profile".into());
    }
    let mut parsed: Vec<IpNet> = cidrs
        .iter()
        .map(|cidr| {
            cidr.parse::<IpNet>()
                .map_err(|_| format!("invalid egress CIDR: {cidr}"))
        })
        .collect::<Result<_, _>>()?;
    parsed.sort_by_key(ToString::to_string);
    parsed.dedup();
    for cidr in parsed {
        if !template.routes.contains(&cidr) {
            template.routes.push(cidr);
        }
        if !template
            .policy
            .allow
            .iter()
            .any(|rule| rule.destination == cidr && rule.service.is_none())
        {
            template.policy.allow.push(NetworkRule {
                destination: cidr,
                protocols: vec![IpProtocol::Any],
                ports: Vec::new(),
                service: None,
            });
        }
    }
    template.routes.sort_by_key(ToString::to_string);
    template
        .policy
        .allow
        .sort_by_key(|rule| (rule.destination.to_string(), rule.service.clone()));
    write_new(
        output,
        serde_json::to_vec_pretty(&template)?.as_slice(),
        true,
    )?;
    println!("configured egress allowlist template {output:?}");
    Ok(())
}

fn certificate_csr(
    name: &str,
    kind: CertificateKind,
    key_out: &Path,
    csr_out: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if name.is_empty() || name.len() > 253 {
        return Err("invalid certificate name".into());
    }
    let sans = if matches!(kind, CertificateKind::Server) {
        vec![name.to_owned()]
    } else {
        Vec::new()
    };
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
    println!(
        "created CSR {} and private key reference {}",
        csr_out.display(),
        key_out.display()
    );
    Ok(())
}

fn certificate_sign(
    pki: &Path,
    csr_path: &Path,
    kind: CertificateKind,
    cert_out: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let ca_cert = fs::read_to_string(pki.join("tls-profile-ca-cert.pem"))?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(pki.join("tls-profile-ca-key.pem"))?)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert, ca_key)?;
    let mut request = CertificateSigningRequestParams::from_pem(&fs::read_to_string(csr_path)?)?;
    let expected = match kind {
        CertificateKind::Client => ExtendedKeyUsagePurpose::ClientAuth,
        CertificateKind::Server => ExtendedKeyUsagePurpose::ServerAuth,
    };
    if !request.params.extended_key_usages.contains(&expected) {
        return Err("CSR extended key usage does not match requested certificate kind".into());
    }
    request.params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    request.params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
    request.params.is_ca = IsCa::NoCa;
    let certificate = request.signed_by(&issuer)?;
    let chain = format!("{}{}", certificate.pem(), ca_cert);
    write_new(cert_out, chain.as_bytes(), false)?;
    println!(
        "signed {} certificate {}",
        match kind {
            CertificateKind::Client => "client",
            CertificateKind::Server => "server",
        },
        cert_out.display()
    );
    Ok(())
}

fn profile_sign(
    pki: &Path,
    template: &Path,
    client_cert: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload: EnrollmentPayload = serde_json::from_slice(&fs::read(template)?)?;
    let token_path = pending_token_path(pki, &payload.enrollment_token)?;
    if !token_path.is_file() {
        return Err("enrollment token is unknown or was already consumed".into());
    }
    let control_pem = fs::read_to_string(pki.join("control-signing-key.pem"))?;
    let control_key = SigningKey::from_pkcs8_pem(&control_pem)?;
    payload.control_plane_key_b64 = STANDARD.encode(control_key.verifying_key().as_bytes());
    payload.tls_root_pem = fs::read_to_string(pki.join("tls-root-cert.pem"))?;
    payload.client_spki_sha256 = certificate_pin(&fs::read(client_cert)?)?;
    payload.signing_key_id = "lattice-control-1".to_owned();
    let payload_bytes = serde_json::to_vec(&payload)?;
    let bundle = EnrollmentBundle {
        payload,
        signature_b64: STANDARD.encode(control_key.sign(&payload_bytes).to_bytes()),
    };
    // The signing path runs the same semantic validation used by endpoints.
    bundle.verify(&control_key.verifying_key(), Utc::now())?;
    write_new(
        output,
        serde_json::to_vec_pretty(&bundle)?.as_slice(),
        false,
    )?;
    fs::rename(&token_path, token_path.with_extension("used"))?;
    println!("signed profile {}", output.display());
    Ok(())
}

fn enrollment_offer_issue(
    pki: &Path,
    template: &Path,
    endpoint: SocketAddr,
    server_name: &str,
    server_cert: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if server_name.is_empty() || server_name.len() > 253 {
        return Err("invalid enrollment server name".into());
    }
    let mut profile_template: EnrollmentPayload = serde_json::from_slice(&fs::read(template)?)?;
    let token_path = pending_token_path(pki, &profile_template.enrollment_token)?;
    if !token_path.is_file() {
        return Err("enrollment token is unknown or was already consumed".into());
    }
    let control_key = load_control_key(pki)?;
    profile_template.control_plane_key_b64 =
        STANDARD.encode(control_key.verifying_key().as_bytes());
    profile_template.tls_root_pem = fs::read_to_string(pki.join("tls-root-cert.pem"))?;
    // The final client SPKI is generated by the device and inserted only after
    // it proves possession of the one-time token with its CSR.
    profile_template.client_spki_sha256 = "00".repeat(32);
    profile_template.signing_key_id = "lattice-control-1".to_owned();
    let payload = EnrollmentOfferPayload {
        version: 1,
        profile_template,
        endpoint,
        server_name: server_name.to_owned(),
        server_spki_sha256: certificate_pin(&fs::read(server_cert)?)?,
    };
    let offer = EnrollmentOffer {
        signature_b64: STANDARD.encode(control_key.sign(&serde_json::to_vec(&payload)?).to_bytes()),
        payload,
    };
    offer.verify(&control_key.verifying_key(), Utc::now())?;
    write_new(output, serde_json::to_vec_pretty(&offer)?.as_slice(), false)?;
    println!("issued enrollment offer {}", output.display());
    Ok(())
}

async fn enrollment_serve(
    pki: &Path,
    offer_path: &Path,
    bind: SocketAddr,
    server_cert_path: &Path,
    server_key_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let control_key = load_control_key(pki)?;
    let offer = EnrollmentOffer::parse(&fs::read(offer_path)?)?;
    offer.verify(&control_key.verifying_key(), Utc::now())?;
    let server_cert = fs::read(server_cert_path)?;
    let expected_pin = certificate_pin(&server_cert)?;
    if !expected_pin.eq_ignore_ascii_case(&offer.payload.server_spki_sha256) {
        return Err("enrollment server certificate does not match the signed offer".into());
    }
    validate_private_key_reference(server_key_path)?;
    let server_key = fs::read(server_key_path)?;
    let endpoint = quinn::Endpoint::server(
        quinn_enrollment_server_config(&server_cert, &server_key)?,
        bind,
    )?;
    eprintln!("lattice enrollment service listening on {bind}");
    while let Some(incoming) = endpoint.accept().await {
        let connection =
            match tokio::time::timeout(std::time::Duration::from_secs(15), incoming).await {
                Ok(Ok(connection)) => connection,
                Ok(Err(error)) => {
                    eprintln!("enrollment TLS rejected: {error}");
                    continue;
                }
                Err(_) => {
                    eprintln!("enrollment TLS timed out");
                    continue;
                }
            };
        if let Err(error) =
            handle_enrollment_connection(&connection, pki, &offer, &control_key).await
        {
            eprintln!("enrollment request rejected: {error}");
        }
    }
    Ok(())
}

async fn handle_enrollment_connection(
    connection: &quinn::Connection,
    pki: &Path,
    offer: &EnrollmentOffer,
    control_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut send, mut recv) =
        tokio::time::timeout(std::time::Duration::from_secs(15), connection.accept_bi())
            .await
            .map_err(|_| "enrollment request stream timed out")??;
    let request = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        recv.read_to_end(MAX_ENROLLMENT_FRAME_BYTES + 4),
    )
    .await
    .map_err(|_| "enrollment request timed out")??;
    let response = match decode_enrollment(&request) {
        Err(error) => EnrollmentFrame::Error {
            code: "invalid_request".to_owned(),
            message: error.to_string(),
        },
        Ok((_, consumed)) if consumed != request.len() => EnrollmentFrame::Error {
            code: "invalid_request".to_owned(),
            message: "trailing enrollment data".to_owned(),
        },
        Ok((frame, _)) => match frame {
            EnrollmentFrame::Request { token, csr_pem } => {
                match issue_enrolled_profile(pki, offer, control_key, &token, &csr_pem) {
                    Ok((bundle, certificate)) => EnrollmentFrame::Response {
                        profile_bundle_json: serde_json::to_string(&bundle)?,
                        client_cert_chain_pem: certificate,
                    },
                    Err(error) => EnrollmentFrame::Error {
                        code: "enrollment_denied".to_owned(),
                        message: error.to_string(),
                    },
                }
            }
            _ => EnrollmentFrame::Error {
                code: "invalid_request".to_owned(),
                message: "expected enrollment request".to_owned(),
            },
        },
    };
    send.write_all(&encode_enrollment(&response)?).await?;
    send.finish()?;
    // Keep the QUIC connection alive until the client has consumed the final
    // profile. Dropping the only Connection handle immediately after FIN can
    // race the peer's stream reader and discard a valid enrollment response.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), connection.closed()).await;
    Ok(())
}

fn issue_enrolled_profile(
    pki: &Path,
    offer: &EnrollmentOffer,
    control_key: &SigningKey,
    token: &str,
    csr_pem: &str,
) -> Result<(EnrollmentBundle, String), Box<dyn std::error::Error>> {
    if token != offer.payload.profile_template.enrollment_token {
        return Err("enrollment token does not match offer".into());
    }
    if csr_pem.len() > 32 * 1024 {
        return Err("enrollment CSR exceeds limit".into());
    }
    let certificate = sign_client_certificate(pki, csr_pem)?;
    // Atomic rename makes the one-time token single-consumer even if multiple
    // connections race with the same signed offer.
    consume_token(pki, token)?;
    let mut payload = offer.payload.profile_template.clone();
    payload.client_spki_sha256 = certificate_pin(certificate.as_bytes())?;
    let bundle = EnrollmentBundle {
        signature_b64: STANDARD.encode(control_key.sign(&serde_json::to_vec(&payload)?).to_bytes()),
        payload,
    };
    bundle.verify(&control_key.verifying_key(), Utc::now())?;
    Ok((bundle, certificate))
}

fn sign_client_certificate(
    pki: &Path,
    csr_pem: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let ca_cert = fs::read_to_string(pki.join("tls-profile-ca-cert.pem"))?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(pki.join("tls-profile-ca-key.pem"))?)?;
    let issuer = Issuer::from_ca_cert_pem(&ca_cert, ca_key)?;
    let mut request = CertificateSigningRequestParams::from_pem(csr_pem)?;
    if !request
        .params
        .extended_key_usages
        .contains(&ExtendedKeyUsagePurpose::ClientAuth)
    {
        return Err("enrollment CSR is not a client-auth CSR".into());
    }
    request.params.not_before = OffsetDateTime::now_utc() - Duration::hours(1);
    request.params.not_after = OffsetDateTime::now_utc() + Duration::days(90);
    request.params.is_ca = IsCa::NoCa;
    let certificate = request.signed_by(&issuer)?;
    Ok(format!("{}{}", certificate.pem(), ca_cert))
}

fn consume_token(pki: &Path, token: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pending = pending_token_path(pki, token)?;
    let used = pending.with_extension("used");
    fs::rename(&pending, &used)
        .map_err(|_| "enrollment token is unknown or was already consumed")?;
    Ok(())
}

fn load_control_key(pki: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    Ok(SigningKey::from_pkcs8_pem(&fs::read_to_string(
        pki.join("control-signing-key.pem"),
    )?)?)
}

fn enrollment_token_issue(pki: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !pki.join("control-signing-key.pem").is_file() {
        return Err("invalid PKI directory".into());
    }
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let token = STANDARD.encode(raw);
    let path = pending_token_path(pki, &token)?;
    write_new(&path, b"pending\n", true)?;
    println!("{token}");
    Ok(())
}

fn pending_token_path(pki: &Path, token: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let raw = STANDARD
        .decode(token)
        .map_err(|_| "invalid enrollment token")?;
    if raw.len() != 32 {
        return Err("enrollment token must contain 32 random bytes".into());
    }
    let digest = Sha256::digest(raw);
    let name: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    let directory = pki.join("enrollment-tokens");
    fs::create_dir_all(&directory)?;
    set_private_directory(&directory)?;
    Ok(directory.join(format!("{name}.pending")))
}

fn profile_revoke(
    pki: &Path,
    profile_path: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bundle = EnrollmentBundle::parse(&fs::read(profile_path)?)?;
    let control_key =
        SigningKey::from_pkcs8_pem(&fs::read_to_string(pki.join("control-signing-key.pem"))?)?;
    bundle.verify(&control_key.verifying_key(), Utc::now())?;
    let now = Utc::now();
    bundle.payload.issued_at = now;
    bundle.payload.revoked_at = Some(now);
    bundle.signature_b64 = STANDARD.encode(
        control_key
            .sign(&serde_json::to_vec(&bundle.payload)?)
            .to_bytes(),
    );
    write_new(
        output,
        serde_json::to_vec_pretty(&bundle)?.as_slice(),
        false,
    )?;
    println!("revoked profile {}", bundle.payload.profile_id);
    Ok(())
}

fn certificate_pin(pem: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(Cursor::new(pem));
    let der = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or("missing certificate")??;
    Ok(spki_sha256_from_der(der.as_ref())?)
}

fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let parent = path.parent().ok_or("output path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn validate_private_key_reference(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("server key path must be absolute".into());
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("server key must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("server key permissions must be 0600 or stricter".into());
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("server key owner does not match the service user".into());
        }
    }
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
