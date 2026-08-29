use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use clap::{Parser, Subcommand};
use ed25519_dalek::VerifyingKey;
use lattice_net_core::packet::{fragment_packet, PacketFragment, PacketReassembler, MAX_IP_PACKET_BYTES};
use lattice_net_core::profile::EnrollmentBundle;
use lattice_net_core::protocol::{decode_control, encode_control, ControlFrame, MAX_CONTROL_FRAME_BYTES};
use lattice_net_core::tls::{quinn_client_config, verify_connection_spki};
use lattice_net_core::uri::lattice_uri_to_https;
use quinn::{Connection, Endpoint};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tun_rs::{DeviceBuilder, Layer};
use uuid::Uuid;

mod platform;

#[derive(Debug, Parser)]
#[command(name = "lattice-netd", about = "Lattice LNP/1 operating-system network client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    ProfileEnroll {
        #[arg(long)] bundle: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")] trusted_control_key_b64: String,
        #[arg(long)] client_cert: PathBuf,
        #[arg(long)] client_key_ref: PathBuf,
        #[arg(long)] state_dir: Option<PathBuf>,
    },
    ProfileRenew {
        #[arg(long)] bundle: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")] trusted_control_key_b64: String,
        #[arg(long)] state_dir: Option<PathBuf>,
    },
    ProfileStatus {
        #[arg(long)] profile_id: Option<Uuid>,
        #[arg(long)] state_dir: Option<PathBuf>,
    },
    CheckProfile {
        #[arg(long)] profile: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")] trusted_control_key_b64: String,
    },
    OpenUri {
        uri: String,
        #[arg(long)] print_only: bool,
    },
    Connect {
        #[arg(long)] profile: PathBuf,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")] trusted_control_key_b64: String,
        #[arg(long)] client_cert: PathBuf,
        /// Must point at an OS-protected runtime credential, never a bundle.
        #[arg(long)] client_key: PathBuf,
        #[arg(long, default_value = "lp0")] tun_name: String,
        #[arg(long)] agent_lease: Option<PathBuf>,
    },
    ProfileConnect {
        #[arg(long)] profile_id: Uuid,
        #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")] trusted_control_key_b64: String,
        #[arg(long)] state_dir: Option<PathBuf>,
        #[arg(long)] client_key_ref: Option<PathBuf>,
        #[arg(long, default_value = "lp0")] tun_name: String,
        #[arg(long)] agent_lease: Option<PathBuf>,
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
        Command::ProfileEnroll { bundle, trusted_control_key_b64, client_cert, client_key_ref, state_dir } => {
            profile_enroll(&bundle, &trusted_control_key_b64, &client_cert, &client_key_ref, state_dir).await?;
        }
        Command::ProfileRenew { bundle, trusted_control_key_b64, state_dir } => {
            profile_renew(&bundle, &trusted_control_key_b64, state_dir).await?;
        }
        Command::ProfileStatus { profile_id, state_dir } => profile_status(profile_id, state_dir).await?,
        Command::CheckProfile { profile, trusted_control_key_b64 } => {
            let (_, bundle) = load_verified_profile(&profile, &trusted_control_key_b64).await?;
            println!("{}", serde_json::json!({
                "ok": true,
                "profile_id": bundle.payload.profile_id,
                "fingerprint": bundle.fingerprint()?,
                "expires_at": bundle.payload.expires_at,
            }));
        }
        Command::OpenUri { uri, print_only } => {
            let target = lattice_uri_to_https(&uri)?;
            if print_only { println!("{target}"); } else { open_browser(target.as_str()).await?; }
        }
        Command::Connect { profile, trusted_control_key_b64, client_cert, client_key, tun_name, agent_lease } => {
            let (_, bundle) = load_verified_profile(&profile, &trusted_control_key_b64).await?;
            let cert = tokio::fs::read(client_cert).await?;
            let key = tokio::fs::read(client_key).await?;
            let lease = match agent_lease { Some(path) => Some(tokio::fs::read_to_string(path).await?), None => None };
            connect(bundle, cert, key, tun_name, lease).await?;
        }
        Command::ProfileConnect { profile_id, trusted_control_key_b64, state_dir, client_key_ref, tun_name, agent_lease } => {
            let state = load_installed_profile(profile_id, state_dir).await?;
            let (_, bundle) = load_verified_profile(&state.bundle_path, &trusted_control_key_b64).await?;
            let cert = tokio::fs::read(&state.client_cert_path).await?;
            let key_ref = client_key_ref.as_ref().unwrap_or(&state.client_key_ref);
            validate_private_key_reference(key_ref)?;
            let key = tokio::fs::read(key_ref).await?;
            let lease = match agent_lease { Some(path) => Some(tokio::fs::read_to_string(path).await?), None => None };
            connect(bundle, cert, key, tun_name, lease).await?;
        }
    }
    Ok(())
}

fn network_state_dir(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = explicit { return Ok(path); }
    if let Ok(path) = std::env::var("LATTICE_NETWORK_HOME") { return Ok(PathBuf::from(path)); }
    let home = std::env::var("HOME").map_err(|_| "HOME or LATTICE_NETWORK_HOME is required")?;
    Ok(PathBuf::from(home).join(".lattice/network/profiles"))
}

async fn profile_enroll(
    bundle_path: &PathBuf,
    encoded_key: &str,
    client_cert: &PathBuf,
    client_key_ref: &PathBuf,
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
    let root = network_state_dir(state_dir)?;
    let directory = root.join(bundle.payload.profile_id.to_string());
    if tokio::fs::try_exists(&directory).await? { return Err("profile is already enrolled".into()); }
    tokio::fs::create_dir_all(&directory).await?;
    set_private_permissions(&directory, true)?;
    let installed_bundle = directory.join("bundle.json");
    let installed_cert = directory.join("client-cert.pem");
    write_private_new(&installed_bundle, &tokio::fs::read(bundle_path).await?, false)?;
    write_private_new(&installed_cert, &cert_bytes, false)?;
    let state = InstalledProfileState {
        profile_id: bundle.payload.profile_id,
        bundle_path: installed_bundle,
        client_cert_path: installed_cert,
        client_key_ref: client_key_ref.clone(),
        enrolled_at: Utc::now(),
    };
    write_private_new(&directory.join("state.json"), &serde_json::to_vec_pretty(&state)?, true)?;
    println!("{}", serde_json::json!({"enrolled": true, "profile_id": state.profile_id}));
    Ok(())
}

async fn profile_renew(bundle_path: &PathBuf, encoded_key: &str, state_dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let (_, bundle) = load_verified_profile(bundle_path, encoded_key).await?;
    let state = load_installed_profile(bundle.payload.profile_id, state_dir).await?;
    let old = EnrollmentBundle::parse(&tokio::fs::read(&state.bundle_path).await?)?;
    if old.payload.profile_id != bundle.payload.profile_id || old.payload.client_spki_sha256 != bundle.payload.client_spki_sha256 {
        return Err("renewal cannot change profile identity or client key".into());
    }
    atomic_replace(&state.bundle_path, &tokio::fs::read(bundle_path).await?, false)?;
    println!("{}", serde_json::json!({"renewed": true, "profile_id": state.profile_id, "expires_at": bundle.payload.expires_at}));
    Ok(())
}

async fn profile_status(profile_id: Option<Uuid>, state_dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let root = network_state_dir(state_dir)?;
    let mut states = Vec::new();
    if let Some(id) = profile_id {
        states.push(load_installed_profile(id, Some(root)).await?);
    } else if tokio::fs::try_exists(&root).await? {
        let mut entries = tokio::fs::read_dir(&root).await?;
        while let Some(entry) = entries.next_entry().await? {
            let Ok(id) = entry.file_name().to_string_lossy().parse::<Uuid>() else { continue; };
            if let Ok(state) = load_installed_profile(id, Some(root.clone())).await { states.push(state); }
        }
    }
    println!("{}", serde_json::to_string_pretty(&states)?);
    Ok(())
}

async fn load_installed_profile(profile_id: Uuid, state_dir: Option<PathBuf>) -> Result<InstalledProfileState, Box<dyn std::error::Error>> {
    let path = network_state_dir(state_dir)?.join(profile_id.to_string()).join("state.json");
    let metadata = tokio::fs::metadata(&path).await?;
    if metadata.len() > 64 * 1024 { return Err("installed profile state is too large".into()); }
    let state: InstalledProfileState = serde_json::from_slice(&tokio::fs::read(path).await?)?;
    if state.profile_id != profile_id { return Err("installed profile id mismatch".into()); }
    Ok(state)
}

fn validate_private_key_reference(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() { return Err("client key reference must be an absolute OS-protected path".into()); }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err("client key reference must be a regular non-symlink file".into());
    }
    #[cfg(unix)] {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0 { return Err("client key reference permissions must be 0600 or stricter".into()); }
        if metadata.uid() != unsafe { libc::geteuid() } { return Err("client key reference owner does not match the daemon user".into()); }
    }
    Ok(())
}

fn write_private_new(path: &PathBuf, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
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

fn atomic_replace(path: &PathBuf, bytes: &[u8], private: bool) -> Result<(), Box<dyn std::error::Error>> {
    let temporary = path.with_extension("new");
    if temporary.exists() { return Err("stale profile renewal file exists".into()); }
    write_private_new(&temporary, bytes, private)?;
    std::fs::rename(temporary, path)?;
    Ok(())
}

fn set_private_permissions(path: &PathBuf, directory: bool) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }))?;
    }
    Ok(())
}

async fn load_verified_profile(path: &PathBuf, encoded_key: &str) -> Result<(VerifyingKey, EnrollmentBundle), Box<dyn std::error::Error>> {
    let raw = STANDARD.decode(encoded_key)?;
    let trusted_key = VerifyingKey::from_bytes(&raw.try_into().map_err(|_| "control key must be exactly 32 bytes")?)?;
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
) -> Result<(), Box<dyn std::error::Error>> {
    let gateway = bundle.payload.gateways.first().ok_or("profile has no gateway")?.clone();
    let client_config = quinn_client_config(bundle.payload.tls_root_pem.as_bytes(), &client_cert, &client_key)?;
    let bind: SocketAddr = if gateway.address.is_ipv4() { "0.0.0.0:0".parse()? } else { "[::]:0".parse()? };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(client_config);
    let connection = endpoint.connect(gateway.address, &gateway.server_name)?.await?;
    verify_connection_spki(&connection, &gateway.spki_sha256)?;
    establish_control(&connection, &bundle, agent_lease).await?;
    let device = Arc::new(build_tun(&bundle, tun_name.clone())?);
    let _network_guard = platform::PlatformNetworkGuard::configure(&tun_name, &gateway, &bundle)?;
    let outbound = tunnel_outbound(device.clone(), connection.clone(), bundle.clone());
    let inbound = tunnel_inbound(device, connection.clone());
    tokio::select! {
        result = outbound => result?,
        result = inbound => result?,
        _ = signal::ctrl_c() => {},
        _ = terminate_signal() => {},
    }
    connection.close(0u32.into(), b"shutdown");
    endpoint.wait_idle().await;
    Ok(())
}

#[cfg(unix)]
async fn terminate_signal() {
    if let Ok(mut stream) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        stream.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(not(unix))]
async fn terminate_signal() {
    std::future::pending::<()>().await;
}

async fn establish_control(connection: &Connection, bundle: &EnrollmentBundle, agent_lease: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&encode_control(&ControlFrame::client_hello(bundle.payload.profile_id, agent_lease))?).await?;
    send.finish()?;
    let response = recv.read_to_end(MAX_CONTROL_FRAME_BYTES + 4).await?;
    let (frame, consumed) = decode_control(&response)?;
    if consumed != response.len() { return Err("trailing control data".into()); }
    match frame {
        ControlFrame::ServerHello { version: 1, mtu: 1280, policy_version } if policy_version == bundle.payload.policy.version => Ok(()),
        ControlFrame::Error { code, message } => Err(format!("gateway rejected profile ({code}): {message}").into()),
        _ => Err("invalid gateway control response".into()),
    }
}

fn build_tun(bundle: &EnrollmentBundle, name: String) -> Result<tun_rs::AsyncDevice, Box<dyn std::error::Error>> {
    let mut builder = DeviceBuilder::new().name(name).layer(Layer::L3).mtu(bundle.payload.interface.mtu);
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
        if !allowed { continue; }
        for fragment in fragment_packet(packet_id, packet)? {
            connection.send_datagram(Bytes::from(fragment.encode()?))?;
        }
        packet_id = packet_id.wrapping_add(1).max(1);
    }
}

async fn tunnel_inbound(device: Arc<tun_rs::AsyncDevice>, connection: Connection) -> Result<(), Box<dyn std::error::Error>> {
    let mut reassembler = PacketReassembler::default();
    loop {
        let datagram = connection.read_datagram().await?;
        let fragment = PacketFragment::decode(&datagram)?;
        if let Some(packet) = reassembler.push(fragment, Instant::now())? {
            device.send(&packet).await?;
        }
    }
}

async fn open_browser(target: &str) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "macos")]
    let status = tokio::process::Command::new("open").arg(target).status().await?;
    #[cfg(target_os = "windows")]
    let status = tokio::process::Command::new("rundll32").arg("url.dll,FileProtocolHandler").arg(target).status().await?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let status = tokio::process::Command::new("xdg-open").arg(target).status().await?;
    if status.success() { Ok(()) } else { Err("browser handler failed".into()) }
}
