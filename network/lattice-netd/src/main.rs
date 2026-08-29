use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use lattice_net_core::lease::AgentLease;
use lattice_net_core::packet::{
    fragment_packet, PacketFragment, PacketReassembler, MAX_IP_PACKET_BYTES,
};
use lattice_net_core::profile::{canonical_service_fqdn, EnrollmentBundle, EnrollmentOffer};
use lattice_net_core::protocol::{
    decode_control, decode_enrollment, encode_control, encode_enrollment, ControlFrame,
    EnrollmentFrame, MAX_CONTROL_FRAME_BYTES, MAX_ENROLLMENT_FRAME_BYTES,
};
use lattice_net_core::tls::{
    quinn_client_config, quinn_enrollment_client_config, verify_connection_spki,
};
use lattice_net_core::uri::lattice_uri_to_https;
use quinn::{Connection, Endpoint};
use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tun_rs::{DeviceBuilder, Layer};
use uuid::Uuid;

mod platform;

#[cfg(target_os = "linux")]
const LINUX_SYSTEM_PROFILE_DIR: &str = "/var/lib/lattice/profiles";

#[derive(Debug, Parser)]
#[command(
    name = "lattice-netd",
    about = "Lattice LNP/1 operating-system network client"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ProfileEnroll {
        bundle: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
        #[arg(long)]
        client_cert: Option<PathBuf>,
        #[arg(long)]
        client_key_ref: Option<PathBuf>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    ProfileRenew {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    ProfileStatus {
        #[arg(long)]
        profile_id: Option<Uuid>,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    ProfileDisconnect {
        #[arg(long)]
        profile_id: Uuid,
    },
    CheckProfile {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
    },
    OpenUri {
        uri: String,
        #[arg(long)]
        print_only: bool,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    /// Privileged helper used by the desktop URI handler. It only locates a
    /// system-installed profile and starts its predeclared unit.
    OpenProfileHost {
        #[arg(long)]
        host: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Connect {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
        #[arg(long)]
        client_cert: PathBuf,
        /// Must point at an OS-protected runtime credential, never a bundle.
        #[arg(long)]
        client_key: PathBuf,
        #[arg(long)]
        tun_name: Option<String>,
        #[arg(long)]
        agent_lease: Option<PathBuf>,
        #[arg(long)]
        external_dns: bool,
    },
    ProfileConnect {
        #[arg(long)]
        profile_id: Uuid,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        client_key_ref: Option<PathBuf>,
        #[arg(long)]
        tun_name: Option<String>,
        #[arg(long)]
        agent_lease: Option<PathBuf>,
        #[arg(long)]
        external_dns: bool,
    },
    RunAgent {
        #[arg(long)]
        profile_id: Uuid,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
        trusted_control_key_b64: String,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        client_key_ref: Option<PathBuf>,
        #[arg(long)]
        namespace_id: String,
        #[arg(long)]
        agent_lease: PathBuf,
        #[arg(last = true, required = true)]
        command: Vec<OsString>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledProfileState {
    profile_id: Uuid,
    bundle_path: PathBuf,
    client_cert_path: PathBuf,
    client_key_ref: PathBuf,
    enrolled_at: chrono::DateTime<Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::ProfileEnroll {
            bundle,
            trusted_control_key_b64,
            client_cert,
            client_key_ref,
            state_dir,
        } => {
            profile_enroll(
                &bundle,
                &trusted_control_key_b64,
                client_cert,
                client_key_ref,
                state_dir,
            )
            .await?;
        }
        Command::ProfileRenew {
            bundle,
            trusted_control_key_b64,
            state_dir,
        } => {
            profile_renew(&bundle, &trusted_control_key_b64, state_dir).await?;
        }
        Command::ProfileStatus {
            profile_id,
            state_dir,
        } => profile_status(profile_id, state_dir).await?,
        Command::ProfileDisconnect { profile_id } => profile_disconnect(profile_id).await?,
        Command::CheckProfile {
            profile,
            trusted_control_key_b64,
        } => {
            let (_, bundle) = load_verified_profile(&profile, &trusted_control_key_b64).await?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "profile_id": bundle.payload.profile_id,
                    "fingerprint": bundle.fingerprint()?,
                    "expires_at": bundle.payload.expires_at,
                })
            );
        }
        Command::OpenUri {
            uri,
            print_only,
            state_dir,
        } => {
            let target = lattice_uri_to_https(&uri)?;
            if print_only {
                println!("{target}");
            } else {
                let host = target.host_str().ok_or("deep link has no host")?;
                activate_profile_for_host(host, state_dir).await?;
                open_browser(target.as_str()).await?;
            }
        }
        Command::OpenProfileHost { host, state_dir } => {
            activate_profile_for_host(&host, state_dir).await?;
        }
        Command::Connect {
            profile,
            trusted_control_key_b64,
            client_cert,
            client_key,
            tun_name,
            agent_lease,
            external_dns,
        } => {
            let (_, bundle) = load_verified_profile(&profile, &trusted_control_key_b64).await?;
            let cert = tokio::fs::read(client_cert).await?;
            validate_private_key_reference(&client_key)?;
            let key = tokio::fs::read(client_key).await?;
            let lease = match agent_lease {
                Some(path) => Some(tokio::fs::read_to_string(path).await?),
                None => None,
            };
            let tun_name = tun_name.unwrap_or_else(|| profile_tun_name(bundle.payload.profile_id));
            connect(bundle, cert, key, tun_name, lease, external_dns).await?;
        }
        Command::ProfileConnect {
            profile_id,
            trusted_control_key_b64,
            state_dir,
            client_key_ref,
            tun_name,
            agent_lease,
            external_dns,
        } => {
            let state = load_installed_profile(profile_id, state_dir).await?;
            let (_, bundle) =
                load_verified_profile(&state.bundle_path, &trusted_control_key_b64).await?;
            let cert = tokio::fs::read(&state.client_cert_path).await?;
            let key_ref = client_key_ref.as_ref().unwrap_or(&state.client_key_ref);
            validate_private_key_reference(key_ref)?;
            let key = tokio::fs::read(key_ref).await?;
            let lease = match agent_lease {
                Some(path) => Some(tokio::fs::read_to_string(path).await?),
                None => None,
            };
            let tun_name = tun_name.unwrap_or_else(|| profile_tun_name(profile_id));
            connect(bundle, cert, key, tun_name, lease, external_dns).await?;
        }
        Command::RunAgent {
            profile_id,
            trusted_control_key_b64,
            state_dir,
            client_key_ref,
            namespace_id,
            agent_lease,
            command,
        } => {
            run_agent(
                profile_id,
                &trusted_control_key_b64,
                state_dir,
                client_key_ref,
                &namespace_id,
                &agent_lease,
                &command,
            )
            .await?;
        }
    }
    Ok(())
}

async fn run_agent(
    profile_id: Uuid,
    encoded_key: &str,
    state_dir: Option<PathBuf>,
    client_key_override: Option<PathBuf>,
    namespace_id: &str,
    lease_path: &PathBuf,
    command: &[OsString],
) -> Result<(), Box<dyn std::error::Error>> {
    if !namespace_id.starts_with("lattice-")
        || namespace_id.len() > 63
        || !namespace_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("namespace id is not canonical".into());
    }
    let state_root = network_state_dir(state_dir)?;
    let state = load_installed_profile(profile_id, Some(state_root.clone())).await?;
    let (_, bundle) = load_verified_profile(&state.bundle_path, encoded_key).await?;
    let key_ref = client_key_override
        .as_ref()
        .unwrap_or(&state.client_key_ref);
    validate_private_key_reference(key_ref)?;
    let lease: AgentLease = serde_json::from_slice(&tokio::fs::read(lease_path).await?)?;
    if lease.payload.profile_id != profile_id || lease.payload.namespace_id != namespace_id {
        return Err("agent lease is not bound to this profile and namespace".into());
    }
    let encoded_agent_key = bundle
        .payload
        .agent_lease_public_keys
        .get(&lease.payload.agent_id)
        .ok_or("agent is not authorized by this profile")?;
    let raw_agent_key = STANDARD.decode(encoded_agent_key)?;
    let agent_key = VerifyingKey::from_bytes(
        &raw_agent_key
            .try_into()
            .map_err(|_| "agent lease key must be exactly 32 bytes")?,
    )?;
    lease.verify(&agent_key, Utc::now())?;
    platform::run_isolated_agent(
        namespace_id,
        &bundle,
        profile_id,
        encoded_key,
        &state_root,
        key_ref,
        lease_path,
        command,
    )?;
    Ok(())
}

fn network_state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Ok(path) = std::env::var("LATTICE_NETWORK_HOME") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } == 0 {
        return Ok(PathBuf::from(LINUX_SYSTEM_PROFILE_DIR));
    }
    let home = std::env::var("HOME").map_err(|_| "HOME or LATTICE_NETWORK_HOME is required")?;
    Ok(PathBuf::from(home).join(".lattice/network/profiles"))
}

fn profile_tun_name(profile_id: Uuid) -> String {
    format!("lp{}", &profile_id.simple().to_string()[..8])
}

async fn activate_profile_for_host(
    host: &str,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() } != 0 {
        let executable = std::env::current_exe()?;
        let system_state = state_dir.unwrap_or_else(|| PathBuf::from(LINUX_SYSTEM_PROFILE_DIR));
        let status = tokio::process::Command::new("pkexec")
            .arg(executable)
            .arg("open-profile-host")
            .arg("--host")
            .arg(host)
            .arg("--state-dir")
            .arg(system_state)
            .status()
            .await?;
        if !status.success() {
            return Err("profile activation was denied".into());
        }
        return Ok(());
    }
    let root = network_state_dir(state_dir)?;
    let mut matches = Vec::new();
    let mut entries = tokio::fs::read_dir(&root).await?;
    while let Some(entry) = entries.next_entry().await? {
        let Ok(profile_id) = entry.file_name().to_string_lossy().parse::<Uuid>() else {
            continue;
        };
        let path = entry.path().join("bundle.json");
        let Ok(bytes) = tokio::fs::read(path).await else {
            continue;
        };
        let Ok(bundle) = EnrollmentBundle::parse(&bytes) else {
            continue;
        };
        if bundle.payload.profile_id == profile_id
            && bundle.payload.services.iter().any(|service| {
                service.fqdn == host
                    || canonical_service_fqdn(&service.tls_spki_sha256)
                        .is_ok_and(|canonical| canonical == host)
            })
        {
            matches.push(profile_id);
        }
    }
    let profile_id = match matches.as_slice() {
        [profile_id] => *profile_id,
        [] => return Err("no installed profile owns this Lattice service".into()),
        _ => return Err("multiple installed profiles own this Lattice service".into()),
    };
    #[cfg(target_os = "linux")]
    {
        let units = [
            format!("lattice-netd@{profile_id}.service"),
            "lattice-resolver.service".to_owned(),
        ];
        let direct = tokio::process::Command::new("systemctl")
            .arg("start")
            .args(&units)
            .status()
            .await?;
        if !direct.success() {
            let elevated = tokio::process::Command::new("pkexec")
                .arg("/usr/bin/systemctl")
                .arg("start")
                .args(&units)
                .status()
                .await?;
            if !elevated.success() {
                return Err("profile activation was denied".into());
            }
        }
        let tun_name = profile_tun_name(profile_id);
        for _ in 0..100 {
            let netd_active = tokio::process::Command::new("systemctl")
                .args(["is-active", "--quiet", &units[0]])
                .status()
                .await?
                .success();
            let resolver_active = tokio::process::Command::new("systemctl")
                .args(["is-active", "--quiet", &units[1]])
                .status()
                .await?
                .success();
            let tun_ready = tokio::process::Command::new("ip")
                .args(["link", "show", &tun_name])
                .status()
                .await?
                .success();
            if netd_active && resolver_active && tun_ready {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err("profile did not become ready; browser was not opened".into())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile_id;
        Err("the native platform application must activate this profile".into())
    }
}

async fn profile_disconnect(profile_id: Uuid) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let units = [format!("lattice-netd@{profile_id}.service")];
        let direct = tokio::process::Command::new("systemctl")
            .arg("stop")
            .args(&units)
            .status()
            .await?;
        if !direct.success() {
            let elevated = tokio::process::Command::new("pkexec")
                .arg("/usr/bin/systemctl")
                .arg("stop")
                .args(&units)
                .status()
                .await?;
            if !elevated.success() {
                return Err("profile disconnect was denied".into());
            }
        }
        println!(
            "{}",
            serde_json::json!({"disconnected": true, "profile_id": profile_id})
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile_id;
        Err("the native platform application must disconnect this profile".into())
    }
}

async fn profile_enroll(
    bundle_path: &PathBuf,
    encoded_key: &str,
    client_cert: Option<PathBuf>,
    client_key_ref: Option<PathBuf>,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    match (client_cert, client_key_ref) {
        (Some(client_cert), Some(client_key_ref)) => {
            enroll_preissued_profile(bundle_path, encoded_key, &client_cert, &client_key_ref, state_dir)
                .await
        }
        (None, None) => enroll_from_offer(bundle_path, encoded_key, state_dir).await,
        _ => Err("client-cert and client-key-ref must be provided together, or omitted for CSR enrollment".into()),
    }
}

async fn enroll_preissued_profile(
    bundle_path: &PathBuf,
    encoded_key: &str,
    client_cert: &PathBuf,
    client_key_ref: &Path,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_private_key_reference(client_key_ref)?;
    let (_, bundle) = load_verified_profile(bundle_path, encoded_key).await?;
    let cert_bytes = tokio::fs::read(client_cert).await?;
    let certs = lattice_net_core::tls::certificates(&cert_bytes)?;
    let pin = lattice_net_core::tls::spki_sha256_from_der(certs[0].as_ref())?;
    if !pin.eq_ignore_ascii_case(&bundle.payload.client_spki_sha256) {
        return Err("client certificate does not match signed profile".into());
    }
    install_profile(
        bundle,
        tokio::fs::read(bundle_path).await?,
        cert_bytes,
        client_key_ref,
        state_dir,
        encoded_key,
    )
    .await
}

async fn enroll_from_offer(
    offer_path: &PathBuf,
    encoded_key: &str,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw_key = STANDARD.decode(encoded_key)?;
    let trusted_key = VerifyingKey::from_bytes(
        &raw_key
            .try_into()
            .map_err(|_| "control key must be exactly 32 bytes")?,
    )?;
    let offer_bytes = tokio::fs::read(offer_path).await?;
    let offer = EnrollmentOffer::parse(&offer_bytes)?;
    offer.verify(&trusted_key, Utc::now())?;
    let root = network_state_dir(state_dir)?;
    let profile_id = offer.payload.profile_template.profile_id;
    let directory = root.join(profile_id.to_string());
    let staging = root.join(format!(".{profile_id}.enrolling"));
    if tokio::fs::try_exists(&directory).await? || tokio::fs::try_exists(&staging).await? {
        return Err("profile is already enrolled".into());
    }
    tokio::fs::create_dir_all(&root).await?;
    tokio::fs::create_dir(&staging).await?;
    set_private_permissions(&staging, true)?;
    let key_path = staging.join("client-key.pem");
    let enrollment = async {
        let (csr_pem, key_pem) = generate_client_csr(profile_id)?;
        write_private_new(&key_path, key_pem.as_bytes(), true)?;
        let (bundle, bundle_bytes, cert_bytes) =
            request_enrollment(&offer, &trusted_key, &csr_pem).await?;
        let final_key = directory.join("client-key.pem");
        install_profile_at(bundle, bundle_bytes, cert_bytes, &final_key, &staging).await?;
        tokio::fs::rename(&staging, &directory).await?;
        // The staged state file contains absolute paths. Once the directory is
        // atomically moved into place, rewrite those references so a valid
        // enrollment never points back at the removed `.enrolling` directory.
        replace_installed_profile_state(profile_id, &directory, &final_key)?;
        write_system_profile_env_if_needed(&root, profile_id, encoded_key)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    if enrollment.is_err() {
        let _ = tokio::fs::remove_dir_all(&staging).await;
    }
    enrollment
}

fn generate_client_csr(profile_id: Uuid) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, format!("lattice-profile-{profile_id}"));
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let key = KeyPair::generate()?;
    let csr = params.serialize_request(&key)?;
    Ok((csr.pem()?, key.serialize_pem()))
}

async fn request_enrollment(
    offer: &EnrollmentOffer,
    trusted_key: &VerifyingKey,
    csr_pem: &str,
) -> Result<(EnrollmentBundle, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let template = &offer.payload.profile_template;
    let client_config = quinn_enrollment_client_config(template.tls_root_pem.as_bytes())?;
    let bind: SocketAddr = if offer.payload.endpoint.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(offer.payload.endpoint, &offer.payload.server_name)?
        .await?;
    verify_connection_spki(&connection, &offer.payload.server_spki_sha256)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&encode_enrollment(&EnrollmentFrame::Request {
        token: template.enrollment_token.clone(),
        csr_pem: csr_pem.to_owned(),
    })?)
    .await?;
    send.finish()?;
    let response = recv.read_to_end(MAX_ENROLLMENT_FRAME_BYTES + 4).await?;
    connection.close(0u32.into(), b"enrollment complete");
    endpoint.wait_idle().await;
    let (frame, consumed) = decode_enrollment(&response)?;
    if consumed != response.len() {
        return Err("trailing enrollment response data".into());
    }
    let EnrollmentFrame::Response {
        profile_bundle_json,
        client_cert_chain_pem,
    } = frame
    else {
        return match frame {
            EnrollmentFrame::Error { code, message } => {
                Err(format!("enrollment service rejected request ({code}): {message}").into())
            }
            _ => Err("invalid enrollment response".into()),
        };
    };
    let bundle_bytes = profile_bundle_json.into_bytes();
    let bundle = EnrollmentBundle::parse(&bundle_bytes)?;
    bundle.verify_fresh(trusted_key, Utc::now())?;
    if !offer.matches_issued_profile(&bundle) {
        return Err("issued profile does not match signed enrollment offer".into());
    }
    let cert_bytes = client_cert_chain_pem.into_bytes();
    let certs = lattice_net_core::tls::certificates(&cert_bytes)?;
    let pin = lattice_net_core::tls::spki_sha256_from_der(certs[0].as_ref())?;
    if !pin.eq_ignore_ascii_case(&bundle.payload.client_spki_sha256) {
        return Err("enrollment certificate does not match issued profile".into());
    }
    Ok((bundle, bundle_bytes, cert_bytes))
}

async fn install_profile(
    bundle: EnrollmentBundle,
    bundle_bytes: Vec<u8>,
    cert_bytes: Vec<u8>,
    client_key_ref: &Path,
    state_dir: Option<PathBuf>,
    trusted_control_key_b64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = network_state_dir(state_dir)?;
    let directory = root.join(bundle.payload.profile_id.to_string());
    if tokio::fs::try_exists(&directory).await? {
        return Err("profile is already enrolled".into());
    }
    tokio::fs::create_dir_all(&directory).await?;
    set_private_permissions(&directory, true)?;
    let profile_id = bundle.payload.profile_id;
    install_profile_at(bundle, bundle_bytes, cert_bytes, client_key_ref, &directory).await?;
    write_system_profile_env_if_needed(&root, profile_id, trusted_control_key_b64)
}

async fn install_profile_at(
    bundle: EnrollmentBundle,
    bundle_bytes: Vec<u8>,
    cert_bytes: Vec<u8>,
    client_key_ref: &Path,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let installed_bundle = directory.join("bundle.json");
    let installed_cert = directory.join("client-cert.pem");
    write_private_new(&installed_bundle, &bundle_bytes, false)?;
    write_private_new(&installed_cert, &cert_bytes, false)?;
    let state = installed_profile_state(bundle.payload.profile_id, directory, client_key_ref);
    write_private_new(
        &directory.join("state.json"),
        &serde_json::to_vec_pretty(&state)?,
        true,
    )?;
    println!(
        "{}",
        serde_json::json!({"enrolled": true, "profile_id": state.profile_id})
    );
    Ok(())
}

fn installed_profile_state(
    profile_id: Uuid,
    directory: &Path,
    client_key_ref: &Path,
) -> InstalledProfileState {
    InstalledProfileState {
        profile_id,
        bundle_path: directory.join("bundle.json"),
        client_cert_path: directory.join("client-cert.pem"),
        client_key_ref: client_key_ref.to_path_buf(),
        enrolled_at: Utc::now(),
    }
}

fn replace_installed_profile_state(
    profile_id: Uuid,
    directory: &Path,
    client_key_ref: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let state = installed_profile_state(profile_id, directory, client_key_ref);
    atomic_replace(
        &directory.join("state.json"),
        &serde_json::to_vec_pretty(&state)?,
        true,
    )
}

fn write_system_profile_env_if_needed(
    state_root: &Path,
    profile_id: Uuid,
    trusted_control_key_b64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        if state_root != Path::new(LINUX_SYSTEM_PROFILE_DIR) {
            return Ok(());
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err("system profile enrollment requires root".into());
        }
        let env_directory = Path::new("/etc/lattice/profiles");
        std::fs::create_dir_all(env_directory)?;
        set_private_permissions(&env_directory.to_path_buf(), true)?;
        let env_path = env_directory.join(format!("{profile_id}.env"));
        let contents = format!("LATTICE_CONTROL_PUBLIC_KEY_B64={trusted_control_key_b64}\n");
        write_private_new(&env_path, contents.as_bytes(), true)?;
        // The aggregate resolver reads one trusted control key while it
        // watches all enrolled profiles. Refuse a conflicting key instead of
        // silently changing the trust root when a second profile is enrolled.
        let resolver_env = Path::new("/etc/lattice/network.env");
        if resolver_env.exists() {
            let existing = std::fs::read_to_string(resolver_env)?;
            if existing != contents {
                return Err("installed profile uses a different resolver control key".into());
            }
        } else {
            write_private_new(&resolver_env, contents.as_bytes(), true)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, profile_id, trusted_control_key_b64);
    }
    Ok(())
}

async fn profile_renew(
    bundle_path: &PathBuf,
    encoded_key: &str,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = STANDARD.decode(encoded_key)?;
    let trusted_key = VerifyingKey::from_bytes(
        &raw.try_into()
            .map_err(|_| "control key must be exactly 32 bytes")?,
    )?;
    let bundle = EnrollmentBundle::parse(&tokio::fs::read(bundle_path).await?)?;
    bundle.verify_signature(&trusted_key)?;
    if bundle.payload.revoked_at.is_none() {
        bundle.verify_fresh(&trusted_key, Utc::now())?;
    }
    let state = load_installed_profile(bundle.payload.profile_id, state_dir).await?;
    let old = EnrollmentBundle::parse(&tokio::fs::read(&state.bundle_path).await?)?;
    if old.payload.profile_id != bundle.payload.profile_id
        || old.payload.client_spki_sha256 != bundle.payload.client_spki_sha256
    {
        return Err("renewal cannot change profile identity or client key".into());
    }
    atomic_replace(
        &state.bundle_path,
        &tokio::fs::read(bundle_path).await?,
        false,
    )?;
    if bundle.payload.revoked_at.is_some() {
        profile_disconnect(state.profile_id).await?;
    }
    println!(
        "{}",
        serde_json::json!({"renewed": true, "profile_id": state.profile_id, "expires_at": bundle.payload.expires_at})
    );
    Ok(())
}

async fn profile_status(
    profile_id: Option<Uuid>,
    state_dir: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = network_state_dir(state_dir)?;
    let mut states = Vec::new();
    if let Some(id) = profile_id {
        states.push(load_installed_profile(id, Some(root)).await?);
    } else if tokio::fs::try_exists(&root).await? {
        let mut entries = tokio::fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let Ok(id) = entry.file_name().to_string_lossy().parse::<Uuid>() else {
                continue;
            };
            if let Ok(state) = load_installed_profile(id, Some(root.clone())).await {
                states.push(state);
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&states)?);
    Ok(())
}

async fn load_installed_profile(
    profile_id: Uuid,
    state_dir: Option<PathBuf>,
) -> Result<InstalledProfileState, Box<dyn std::error::Error>> {
    let path = network_state_dir(state_dir)?
        .join(profile_id.to_string())
        .join("state.json");
    let metadata = tokio::fs::metadata(&path).await?;
    if metadata.len() > 64 * 1024 {
        return Err("installed profile state is too large".into());
    }
    let state: InstalledProfileState = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    if state.profile_id != profile_id {
        return Err("installed profile id mismatch".into());
    }
    Ok(state)
}

fn validate_private_key_reference(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("client key reference must be an absolute OS-protected path".into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("client key reference must be a regular non-symlink file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("client key reference permissions must be 0600 or stricter".into());
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err("client key reference owner does not match the daemon user".into());
        }
    }
    Ok(())
}

fn write_private_new(
    path: &Path,
    bytes: &[u8],
    private: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
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

fn atomic_replace(
    path: &Path,
    bytes: &[u8],
    private: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("new");
    if temporary.exists() {
        return Err("stale profile renewal file exists".into());
    }
    write_private_new(&temporary, bytes, private)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn set_private_permissions(
    path: &PathBuf,
    directory: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )?;
    }
    Ok(())
}

async fn load_verified_profile(
    path: &PathBuf,
    encoded_key: &str,
) -> Result<(VerifyingKey, EnrollmentBundle), Box<dyn std::error::Error>> {
    let raw = STANDARD.decode(encoded_key)?;
    let trusted_key = VerifyingKey::from_bytes(
        &raw.try_into()
            .map_err(|_| "control key must be exactly 32 bytes")?,
    )?;
    let bundle = EnrollmentBundle::parse(&tokio::fs::read(path).await?)?;
    bundle.verify_fresh(&trusted_key, Utc::now())?;
    Ok((trusted_key, bundle))
}

async fn connect(
    bundle: EnrollmentBundle,
    client_cert: Vec<u8>,
    client_key: Vec<u8>,
    tun_name: String,
    agent_lease: Option<String>,
    external_dns: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let gateway = bundle
        .payload
        .gateways
        .first()
        .ok_or("profile has no gateway")?
        .clone();
    let client_config = quinn_client_config(
        bundle.payload.tls_root_pem.as_bytes(),
        &client_cert,
        &client_key,
    )?;
    let bind: SocketAddr = if gateway.address.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint
        .connect(gateway.address, &gateway.server_name)?
        .await?;
    verify_connection_spki(&connection, &gateway.spki_sha256)?;
    establish_control(&connection, &bundle, agent_lease).await?;
    let device = Arc::new(build_tun(&bundle, tun_name.clone())?);
    let _network_guard =
        platform::PlatformNetworkGuard::configure(&tun_name, &gateway, &bundle, !external_dns)?;
    let outbound = tunnel_outbound(device.clone(), connection.clone(), bundle.clone());
    let inbound = tunnel_inbound(device, connection.clone(), bundle.clone());
    let freshness_deadline = std::cmp::min(
        bundle.payload.expires_at,
        bundle.payload.issued_at
            + chrono::Duration::seconds(bundle.payload.max_stale_seconds.into()),
    );
    let freshness_wait = tokio::time::sleep(
        (freshness_deadline - Utc::now())
            .to_std()
            .unwrap_or_default(),
    );
    tokio::pin!(freshness_wait);
    tokio::select! {
        result = outbound => result?,
        result = inbound => result?,
        _ = signal::ctrl_c() => {},
        _ = terminate_signal() => {},
        _ = &mut freshness_wait => return Err("signed profile state expired; tunnel closed fail-closed".into()),
    }
    connection.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

#[cfg(unix)]
async fn terminate_signal() {
    if let Ok(mut stream) =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        stream.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}

async fn establish_control(
    connection: &Connection,
    bundle: &EnrollmentBundle,
    agent_lease: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&encode_control(&ControlFrame::client_hello(
        bundle.payload.profile_id,
        agent_lease,
    ))?)
    .await?;
    send.finish()?;
    let response = recv.read_to_end(MAX_CONTROL_FRAME_BYTES + 4).await?;
    let (frame, consumed) = decode_control(&response)?;
    if consumed != response.len() {
        return Err("trailing control data".into());
    }
    match frame {
        ControlFrame::ServerHello {
            version: 1,
            mtu: 1280,
            policy_version,
        } if policy_version == bundle.payload.policy.version => Ok(()),
        ControlFrame::Error { code, message } => {
            Err(format!("gateway rejected profile ({code}): {message}").into())
        }
        _ => Err("invalid gateway control response".into()),
    }
}

fn build_tun(
    bundle: &EnrollmentBundle,
    name: String,
) -> Result<tun_rs::AsyncDevice, Box<dyn std::error::Error>> {
    let mut builder = DeviceBuilder::new()
        .name(name)
        .layer(Layer::L3)
        .mtu(bundle.payload.interface.mtu);
    if let Some(network) = bundle.payload.interface.ipv4 {
        builder = builder.ipv4(network.addr(), network.prefix_len(), None);
    }
    if let Some(network) = bundle.payload.interface.ipv6 {
        builder = builder.ipv6(network.addr(), network.prefix_len());
    }
    Ok(builder.build_async()?)
}

async fn tunnel_outbound(
    device: Arc<tun_rs::AsyncDevice>,
    connection: Connection,
    bundle: EnrollmentBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut packet_id = 1u64;
    let mut buffer = vec![0u8; MAX_IP_PACKET_BYTES];
    loop {
        let length = device.recv(&mut buffer).await?;
        let packet = &buffer[..length];
        let (allowed, _) = bundle.payload.policy.authorize(packet)?;
        if !allowed {
            continue;
        }
        for fragment in fragment_packet(packet_id, packet)? {
            connection.send_datagram(Bytes::from(fragment.encode()?))?;
        }
        packet_id = packet_id.wrapping_add(1).max(1);
    }
}

async fn tunnel_inbound(
    device: Arc<tun_rs::AsyncDevice>,
    connection: Connection,
    bundle: EnrollmentBundle,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reassembler = PacketReassembler::default();
    loop {
        let datagram = connection.read_datagram().await?;
        let fragment = PacketFragment::decode(&datagram)?;
        if let Some(packet) = reassembler.push(fragment, Instant::now())? {
            let destination = lattice_net_core::policy::packet_metadata(&packet)?.destination;
            let assigned = bundle
                .payload
                .interface
                .ipv4
                .map(|net| std::net::IpAddr::V4(net.addr()))
                == Some(destination)
                || bundle
                    .payload
                    .interface
                    .ipv6
                    .map(|net| std::net::IpAddr::V6(net.addr()))
                    == Some(destination);
            if !assigned {
                return Err("gateway sent a packet for an address outside this profile".into());
            }
            device.send(&packet).await?;
        }
    }
}

async fn open_browser(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    let status = tokio::process::Command::new("open")
        .arg(target)
        .status()
        .await?;
    #[cfg(target_os = "windows")]
    let status = tokio::process::Command::new("rundll32")
        .arg("url.dll,FileProtocolHandler")
        .arg(target)
        .status()
        .await?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = tokio::process::Command::new("xdg-open")
        .arg(target)
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err("browser handler failed".into())
    }
}
