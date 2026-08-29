use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use lattice_net_core::profile::{canonical_service_fqdn, EnrollmentBundle};
use lattice_resolver::ResolverTable;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[derive(Debug, Parser)]
#[command(
    name = "lattice-resolver",
    about = "Authoritative private resolver for signed *.lattice, *.coral and *.reef bindings"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5353")]
    bind: SocketAddr,
    #[arg(long, conflicts_with = "profiles_dir")]
    profile: Option<PathBuf>,
    #[arg(long, conflicts_with = "profile")]
    profiles_dir: Option<PathBuf>,
    #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
    trusted_control_key_b64: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let raw_key = STANDARD.decode(&args.trusted_control_key_b64)?;
    let key = VerifyingKey::from_bytes(
        &raw_key
            .try_into()
            .map_err(|_| "control key must be 32 bytes")?,
    )?;
    let source_profile = args.profile;
    let source_directory = args.profiles_dir;
    let table = Arc::new(RwLock::new(
        load_table(source_profile.clone(), source_directory.clone(), &key).await?,
    ));
    let reload_table = table.clone();
    let reload_key = key;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            match load_table(
                source_profile.clone(),
                source_directory.clone(),
                &reload_key,
            )
            .await
            {
                Ok(updated) => *reload_table.write().await = updated,
                Err(error) => {
                    eprintln!("lattice-resolver signed state rejected: {error}");
                    if let Ok(empty) =
                        ResolverTable::new(Vec::<(String, Vec<std::net::IpAddr>)>::new(), 30)
                    {
                        *reload_table.write().await = empty;
                    }
                }
            }
        }
    });
    let socket = UdpSocket::bind(args.bind).await?;
    let mut buffer = [0u8; 4_096];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        if let Ok(answer) = table.read().await.answer(&buffer[..length]) {
            let _ = socket.send_to(&answer, peer).await;
        }
    }
}

async fn load_table(
    profile: Option<PathBuf>,
    profiles_dir: Option<PathBuf>,
    key: &VerifyingKey,
) -> Result<ResolverTable, Box<dyn std::error::Error + Send + Sync>> {
    let paths = profile_paths(profile, profiles_dir).await?;
    if paths.is_empty() {
        return Err("no installed profiles were found".into());
    }
    let mut bindings = Vec::new();
    for profile_path in paths {
        let profile = EnrollmentBundle::parse(&tokio::fs::read(profile_path).await?)?;
        profile.verify_fresh(key, Utc::now())?;
        for service in profile.payload.services {
            let canonical = canonical_service_fqdn(&service.tls_spki_sha256)?;
            let addresses = service.addresses;
            if canonical != service.fqdn {
                bindings.push((canonical, addresses.clone()));
            }
            bindings.push((service.fqdn, addresses));
        }
    }
    Ok(ResolverTable::new(bindings, 30)?)
}

async fn profile_paths(
    profile: Option<PathBuf>,
    profiles_dir: Option<PathBuf>,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(profile) = profile {
        return Ok(vec![profile]);
    }
    let directory = profiles_dir.ok_or("--profile or --profiles-dir is required")?;
    let mut paths = Vec::new();
    let mut entries = tokio::fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path().join("bundle.json");
        if tokio::fs::try_exists(&path).await? {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}
