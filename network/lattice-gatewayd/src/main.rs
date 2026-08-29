use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ipnet::{Ipv4Net, Ipv6Net};
use lattice_net_core::packet::{fragment_packet, PacketFragment, PacketReassembler, MAX_IP_PACKET_BYTES};
use lattice_net_core::policy::{packet_metadata, NetworkPolicy};
use lattice_net_core::profile::EnrollmentBundle;
use lattice_net_core::protocol::{decode_control, encode_control, ControlFrame, MAX_CONTROL_FRAME_BYTES};
use lattice_net_core::tls::{quinn_server_config, verify_connection_spki};
use quinn::{Connection, Endpoint};
use tokio::sync::{Mutex, RwLock};
use tun_rs::{DeviceBuilder, Layer};
use uuid::Uuid;

type Connections = Arc<RwLock<HashMap<IpAddr, Connection>>>;

#[derive(Debug, Parser)]
#[command(name = "lattice-gatewayd", about = "Lattice LNP/1 mTLS packet gateway")]
struct Args {
    #[arg(long, default_value = "[::]:7443")]
    bind: SocketAddr,
    #[arg(long)] tls_root: PathBuf,
    #[arg(long)] server_cert: PathBuf,
    /// Must resolve to an OS-protected runtime credential.
    #[arg(long)] server_key: PathBuf,
    #[arg(long)] profiles_dir: PathBuf,
    #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
    trusted_control_key_b64: String,
    #[arg(long, default_value = "lp-gateway0")]
    tun_name: String,
    #[arg(long)] tun_ipv4: Option<Ipv4Net>,
    #[arg(long)] tun_ipv6: Option<Ipv6Net>,
    #[arg(long, default_value_t = 1024)] max_connections: usize,
}

#[derive(Clone)]
struct ProfileStore {
    directory: PathBuf,
    trusted_key: VerifyingKey,
}

impl ProfileStore {
    async fn load(&self, id: Uuid) -> Result<EnrollmentBundle, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.directory.join(format!("{id}.json"));
        let bytes = tokio::fs::read(path).await?;
        let profile = EnrollmentBundle::parse(&bytes)?;
        if profile.payload.profile_id != id { return Err("profile id/path mismatch".into()); }
        profile.verify_fresh(&self.trusted_key, Utc::now())?;
        Ok(profile)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.max_connections == 0 || args.max_connections > 65_536 { return Err("max-connections must be 1..65536".into()); }
    if args.tun_ipv4.is_none() && args.tun_ipv6.is_none() { return Err("at least one gateway TUN address is required".into()); }
    let raw_key = STANDARD.decode(args.trusted_control_key_b64)?;
    let store = ProfileStore {
        directory: args.profiles_dir,
        trusted_key: VerifyingKey::from_bytes(&raw_key.try_into().map_err(|_| "control key must be 32 bytes")?)?,
    };
    let root = tokio::fs::read(args.tls_root).await?;
    let cert = tokio::fs::read(args.server_cert).await?;
    let key = tokio::fs::read(args.server_key).await?;
    let server_config = quinn_server_config(&root, &cert, &key)?;
    let endpoint = Endpoint::server(server_config, args.bind)?;
    let device = Arc::new(build_tun(args.tun_name, args.tun_ipv4, args.tun_ipv6)?);
    let connections: Connections = Arc::new(RwLock::new(HashMap::new()));
    let outbound = tokio::spawn(gateway_outbound(device.clone(), connections.clone()));

    while let Some(incoming) = endpoint.accept().await {
        if endpoint.open_connections() >= args.max_connections {
            incoming.refuse();
            continue;
        }
        let store = store.clone();
        let device = device.clone();
        let connections = connections.clone();
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                if let Err(error) = handle_connection(connection, store, device, connections).await {
                    eprintln!("lattice-gatewayd connection denied: {error}");
                }
            }
        });
    }
    outbound.abort();
    Ok(())
}

fn build_tun(name: String, ipv4: Option<Ipv4Net>, ipv6: Option<Ipv6Net>) -> Result<tun_rs::AsyncDevice, Box<dyn std::error::Error>> {
    let mut builder = DeviceBuilder::new().name(name).layer(Layer::L3).mtu(1280);
    if let Some(network) = ipv4 { builder = builder.ipv4(network.addr(), network.prefix_len(), None); }
    if let Some(network) = ipv6 { builder = builder.ipv6(network.addr(), network.prefix_len()); }
    Ok(builder.build_async()?)
}

async fn handle_connection(
    connection: Connection,
    store: ProfileStore,
    device: Arc<tun_rs::AsyncDevice>,
    connections: Connections,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let hello_bytes = recv.read_to_end(MAX_CONTROL_FRAME_BYTES + 4).await?;
    let (hello, consumed) = decode_control(&hello_bytes)?;
    if consumed != hello_bytes.len() { return Err("trailing control data".into()); }
    let profile_id = match hello {
        ControlFrame::ClientHello { version: 1, profile_id, .. } => profile_id,
        _ => return Err("client did not send an LNP/1 hello".into()),
    };
    let profile = store.load(profile_id).await?;
    verify_connection_spki(&connection, &profile.payload.client_spki_sha256)?;
    send.write_all(&encode_control(&ControlFrame::server_hello(profile.payload.policy.version))?).await?;
    send.finish()?;

    let client_addresses: Vec<IpAddr> = [
        profile.payload.interface.ipv4.map(|network| IpAddr::V4(network.addr())),
        profile.payload.interface.ipv6.map(|network| IpAddr::V6(network.addr())),
    ].into_iter().flatten().collect();
    {
        let mut active = connections.write().await;
        for address in &client_addresses {
            if active.contains_key(address) { return Err("profile address is already connected".into()); }
            active.insert(*address, connection.clone());
        }
    }
    let result = gateway_inbound(connection.clone(), device, profile.payload.policy).await;
    {
        let mut active = connections.write().await;
        for address in client_addresses {
            if active.get(&address).is_some_and(|current| current.stable_id() == connection.stable_id()) {
                active.remove(&address);
            }
        }
    }
    result
}

async fn gateway_inbound(
    connection: Connection,
    device: Arc<tun_rs::AsyncDevice>,
    policy: NetworkPolicy,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reassembler = Mutex::new(PacketReassembler::default());
    loop {
        let datagram = connection.read_datagram().await?;
        let fragment = PacketFragment::decode(&datagram)?;
        let packet = reassembler.lock().await.push(fragment, Instant::now())?;
        if let Some(packet) = packet {
            let (allowed, metadata) = policy.authorize(&packet)?;
            eprintln!("{}", serde_json::json!({
                "event": "lattice_flow",
                "destination": metadata.destination,
                "port": metadata.destination_port,
                "protocol": metadata.protocol,
                "bytes": metadata.bytes,
                "decision": if allowed { "allow" } else { "deny" },
                "policy_version": policy.version,
            }));
            if allowed { device.send(&packet).await?; }
        }
    }
}

async fn gateway_outbound(device: Arc<tun_rs::AsyncDevice>, connections: Connections) {
    let mut buffer = vec![0u8; MAX_IP_PACKET_BYTES];
    let mut packet_id = 1u64;
    loop {
        let Ok(length) = device.recv(&mut buffer).await else { break; };
        let packet = &buffer[..length];
        let Ok(metadata) = packet_metadata(packet) else { continue; };
        let Some(connection) = connections.read().await.get(&metadata.destination).cloned() else { continue; };
        let Ok(fragments) = fragment_packet(packet_id, packet) else { continue; };
        for fragment in fragments {
            let Ok(encoded) = fragment.encode() else { continue; };
            if connection.send_datagram(Bytes::from(encoded)).is_err() { break; }
        }
        packet_id = packet_id.wrapping_add(1).max(1);
    }
}
