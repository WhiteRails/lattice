use std::net::SocketAddr;
use std::path::PathBuf;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use lattice_net_core::profile::EnrollmentBundle;
use lattice_resolver::ResolverTable;
use tokio::net::UdpSocket;

#[derive(Debug, Parser)]
#[command(name = "lattice-resolver", about = "Authoritative private resolver for signed *.lattice bindings")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:5353")]
    bind: SocketAddr,
    #[arg(long)]
    profile: PathBuf,
    #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
    trusted_control_key_b64: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let raw_key = STANDARD.decode(&args.trusted_control_key_b64)?;
    let key = VerifyingKey::from_bytes(&raw_key.try_into().map_err(|_| "control key must be 32 bytes")?)?;
    let profile_bytes = tokio::fs::read(&args.profile).await?;
    let profile = EnrollmentBundle::parse(&profile_bytes)?;
    profile.verify_fresh(&key, Utc::now())?;
    let table = ResolverTable::new(
        profile.payload.services.iter().map(|service| (service.fqdn.clone(), service.addresses.clone())),
        30,
    )?;
    let socket = UdpSocket::bind(args.bind).await?;
    let mut buffer = [0u8; 4_096];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        if let Ok(answer) = table.answer(&buffer[..length]) {
            let _ = socket.send_to(&answer, peer).await;
        }
    }
}
