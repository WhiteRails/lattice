use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use ipnet::{Ipv4Net, Ipv6Net};
use lattice_net_core::lease::AgentLease;
use lattice_net_core::packet::{
    fragment_packet, PacketFragment, PacketReassembler, MAX_IP_PACKET_BYTES,
};
use lattice_net_core::policy::{packet_metadata, IpProtocol, NetworkPolicy, PacketMetadata};
use lattice_net_core::profile::EnrollmentBundle;
use lattice_net_core::protocol::{
    decode_control, encode_control, ControlFrame, MAX_CONTROL_FRAME_BYTES,
};
use lattice_net_core::tls::{quinn_server_config, verify_connection_spki};
use quinn::{Connection, Endpoint};
use tokio::sync::{Mutex, RwLock};
use tun_rs::{DeviceBuilder, Layer};
use uuid::Uuid;

const MAX_ACTIVE_FLOWS_PER_PROFILE: usize = 65_536;

#[derive(Clone)]
struct ConnectionState {
    connection: Connection,
    flows: Arc<Mutex<FlowTable>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    protocol: IpProtocol,
    client_address: IpAddr,
    client_port: Option<u16>,
    remote_address: IpAddr,
    remote_port: Option<u16>,
}

#[derive(Default)]
struct FlowTable {
    entries: HashMap<FlowKey, Instant>,
}

impl FlowTable {
    fn record_request(&mut self, metadata: &PacketMetadata, now: Instant) -> bool {
        self.evict_expired(now);
        let key = FlowKey {
            protocol: metadata.protocol,
            client_address: metadata.source,
            client_port: metadata.source_port,
            remote_address: metadata.destination,
            remote_port: metadata.destination_port,
        };
        if !self.entries.contains_key(&key) && self.entries.len() >= MAX_ACTIVE_FLOWS_PER_PROFILE {
            return false;
        }
        self.entries.insert(key, now + flow_ttl(metadata.protocol));
        true
    }

    fn accepts_response(&mut self, metadata: &PacketMetadata, now: Instant) -> bool {
        self.evict_expired(now);
        let reverse = FlowKey {
            protocol: metadata.protocol,
            client_address: metadata.destination,
            client_port: metadata.destination_port,
            remote_address: metadata.source,
            remote_port: metadata.source_port,
        };
        let Some(expiry) = self.entries.get_mut(&reverse) else {
            return false;
        };
        *expiry = now + flow_ttl(metadata.protocol);
        true
    }

    fn evict_expired(&mut self, now: Instant) {
        self.entries.retain(|_, expiry| *expiry > now);
    }
}

fn flow_ttl(protocol: IpProtocol) -> std::time::Duration {
    match protocol {
        IpProtocol::Tcp => std::time::Duration::from_secs(5 * 60),
        IpProtocol::Udp => std::time::Duration::from_secs(60),
        IpProtocol::Icmp | IpProtocol::Icmpv6 => std::time::Duration::from_secs(10),
        IpProtocol::Any => std::time::Duration::from_secs(0),
    }
}

type Connections = Arc<RwLock<HashMap<IpAddr, ConnectionState>>>;
type LeaseReplayCache = Arc<Mutex<HashMap<String, DateTime<Utc>>>>;

#[derive(Debug, Parser)]
#[command(name = "lattice-gatewayd", about = "Lattice LNP/1 mTLS packet gateway")]
struct Args {
    #[arg(long, default_value = "[::]:7443")]
    bind: SocketAddr,
    #[arg(long)]
    tls_root: PathBuf,
    #[arg(long)]
    server_cert: PathBuf,
    /// Must resolve to an OS-protected runtime credential.
    #[arg(long)]
    server_key: PathBuf,
    #[arg(long)]
    profiles_dir: PathBuf,
    #[arg(long, env = "LATTICE_CONTROL_PUBLIC_KEY_B64")]
    trusted_control_key_b64: String,
    #[arg(long, default_value = "lp-gateway0")]
    tun_name: String,
    #[arg(long)]
    tun_ipv4: Option<Ipv4Net>,
    #[arg(long)]
    tun_ipv6: Option<Ipv6Net>,
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
}

#[derive(Clone)]
struct ProfileStore {
    directory: PathBuf,
    trusted_key: VerifyingKey,
}

impl ProfileStore {
    async fn load(
        &self,
        id: Uuid,
    ) -> Result<EnrollmentBundle, Box<dyn std::error::Error + Send + Sync>> {
        let path = self.directory.join(format!("{id}.json"));
        let bytes = tokio::fs::read(path).await?;
        let profile = EnrollmentBundle::parse(&bytes)?;
        if profile.payload.profile_id != id {
            return Err("profile id/path mismatch".into());
        }
        profile.verify_fresh(&self.trusted_key, Utc::now())?;
        Ok(profile)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.max_connections == 0 || args.max_connections > 65_536 {
        return Err("max-connections must be 1..65536".into());
    }
    if args.tun_ipv4.is_none() && args.tun_ipv6.is_none() {
        return Err("at least one gateway TUN address is required".into());
    }
    let raw_key = STANDARD.decode(args.trusted_control_key_b64)?;
    let store = ProfileStore {
        directory: args.profiles_dir,
        trusted_key: VerifyingKey::from_bytes(
            &raw_key
                .try_into()
                .map_err(|_| "control key must be 32 bytes")?,
        )?,
    };
    let root = tokio::fs::read(args.tls_root).await?;
    let cert = tokio::fs::read(args.server_cert).await?;
    validate_private_key_reference(&args.server_key)?;
    let key = tokio::fs::read(args.server_key).await?;
    let server_config = quinn_server_config(&root, &cert, &key)?;
    let endpoint = Endpoint::server(server_config, args.bind)?;
    let device = Arc::new(build_tun(args.tun_name, args.tun_ipv4, args.tun_ipv6)?);
    let connections: Connections = Arc::new(RwLock::new(HashMap::new()));
    let lease_replays: LeaseReplayCache = Arc::new(Mutex::new(HashMap::new()));
    let outbound = tokio::spawn(gateway_outbound(device.clone(), connections.clone()));

    while let Some(incoming) = endpoint.accept().await {
        if endpoint.open_connections() >= args.max_connections {
            incoming.refuse();
            continue;
        }
        let store = store.clone();
        let device = device.clone();
        let connections = connections.clone();
        let lease_replays = lease_replays.clone();
        tokio::spawn(async move {
            if let Ok(connection) = incoming.await {
                if let Err(error) =
                    handle_connection(connection, store, device, connections, lease_replays).await
                {
                    eprintln!("lattice-gatewayd connection denied: {error}");
                }
            }
        });
    }
    outbound.abort();
    Ok(())
}

fn validate_private_key_reference(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute() {
        return Err("server key path must be absolute".into());
    }
    let metadata = std::fs::symlink_metadata(path)?;
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
            return Err("server key owner does not match the daemon user".into());
        }
    }
    Ok(())
}

fn build_tun(
    name: String,
    ipv4: Option<Ipv4Net>,
    ipv6: Option<Ipv6Net>,
) -> Result<tun_rs::AsyncDevice, Box<dyn std::error::Error>> {
    let mut builder = DeviceBuilder::new().name(name).layer(Layer::L3).mtu(1280);
    if let Some(network) = ipv4 {
        builder = builder.ipv4(network.addr(), network.prefix_len(), None);
    }
    if let Some(network) = ipv6 {
        builder = builder.ipv6(network.addr(), network.prefix_len());
    }
    Ok(builder.build_async()?)
}

async fn handle_connection(
    connection: Connection,
    store: ProfileStore,
    device: Arc<tun_rs::AsyncDevice>,
    connections: Connections,
    lease_replays: LeaseReplayCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut send, mut recv) = connection.accept_bi().await?;
    let hello_bytes = recv.read_to_end(MAX_CONTROL_FRAME_BYTES + 4).await?;
    let (hello, consumed) = decode_control(&hello_bytes)?;
    if consumed != hello_bytes.len() {
        return Err("trailing control data".into());
    }
    let (profile_id, agent_lease) = match hello {
        ControlFrame::ClientHello {
            version: 1,
            profile_id,
            agent_lease,
        } => (profile_id, agent_lease),
        _ => return Err("client did not send an LNP/1 hello".into()),
    };
    let profile = store.load(profile_id).await?;
    verify_connection_spki(&connection, &profile.payload.client_spki_sha256)?;
    verify_agent_lease(&profile, agent_lease.as_deref(), &lease_replays).await?;
    send.write_all(&encode_control(&ControlFrame::server_hello(
        profile.payload.policy.version,
    ))?)
    .await?;
    send.finish()?;

    let client_addresses: Vec<IpAddr> = [
        profile
            .payload
            .interface
            .ipv4
            .map(|network| IpAddr::V4(network.addr())),
        profile
            .payload
            .interface
            .ipv6
            .map(|network| IpAddr::V6(network.addr())),
    ]
    .into_iter()
    .flatten()
    .collect();
    let flows = Arc::new(Mutex::new(FlowTable::default()));
    {
        let mut active = connections.write().await;
        if client_addresses
            .iter()
            .any(|address| active.contains_key(address))
        {
            return Err("profile address is already connected".into());
        }
        for address in &client_addresses {
            active.insert(
                *address,
                ConnectionState {
                    connection: connection.clone(),
                    flows: flows.clone(),
                },
            );
        }
    }
    let initial_fingerprint = profile.fingerprint()?;
    let inbound = gateway_inbound(
        connection.clone(),
        device,
        profile.payload.policy,
        client_addresses.clone(),
        profile_id,
        initial_fingerprint.clone(),
        flows,
    );
    let watchdog = profile_watchdog(
        store.clone(),
        profile_id,
        initial_fingerprint,
        std::cmp::min(
            profile.payload.expires_at,
            profile.payload.issued_at
                + chrono::Duration::seconds(profile.payload.max_stale_seconds.into()),
        ),
        connection.clone(),
    );
    let result = tokio::select! {
        result = inbound => result,
        result = watchdog => result,
    };
    {
        let mut active = connections.write().await;
        for address in client_addresses {
            if active
                .get(&address)
                .is_some_and(|current| current.connection.stable_id() == connection.stable_id())
            {
                active.remove(&address);
            }
        }
    }
    result
}

async fn profile_watchdog(
    store: ProfileStore,
    profile_id: Uuid,
    initial_fingerprint: String,
    freshness_deadline: DateTime<Utc>,
    connection: Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let now = Utc::now();
        if now >= freshness_deadline {
            connection.close(0u32.into(), b"signed profile state expired");
            return Err("signed profile state expired; tunnel closed fail-closed".into());
        }
        let remaining = (freshness_deadline - now).to_std().unwrap_or_default();
        tokio::time::sleep(std::cmp::min(remaining, std::time::Duration::from_secs(30))).await;
        let current = store.load(profile_id).await?;
        if current.fingerprint()? != initial_fingerprint {
            connection.close(0u32.into(), b"signed profile changed");
            return Err("signed profile changed; reconnect required".into());
        }
    }
}

async fn gateway_inbound(
    connection: Connection,
    device: Arc<tun_rs::AsyncDevice>,
    policy: NetworkPolicy,
    assigned_sources: Vec<IpAddr>,
    profile_id: Uuid,
    profile_fingerprint: String,
    flows: Arc<Mutex<FlowTable>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let reassembler = Mutex::new(PacketReassembler::default());
    loop {
        let datagram = connection.read_datagram().await?;
        let fragment = PacketFragment::decode(&datagram)?;
        let packet = reassembler.lock().await.push(fragment, Instant::now())?;
        if let Some(packet) = packet {
            let (allowed, metadata) = policy.authorize(&packet)?;
            let source_allowed =
                packet_source(&packet).is_some_and(|source| assigned_sources.contains(&source));
            let mut allowed = allowed && source_allowed;
            if allowed {
                allowed = flows.lock().await.record_request(&metadata, Instant::now());
            }
            eprintln!(
                "{}",
                serde_json::json!({
                "event": "lattice_flow",
                "profile_id": profile_id,
                "profile_fingerprint": profile_fingerprint,
                    "destination": metadata.destination,
                    "port": metadata.destination_port,
                    "protocol": metadata.protocol,
                    "bytes": metadata.bytes,
                    "decision": if allowed { "allow" } else { "deny" },
                    "policy_version": policy.version,
                })
            );
            if allowed {
                device.send(&packet).await?;
            }
        }
    }
}

async fn verify_agent_lease(
    profile: &EnrollmentBundle,
    encoded_lease: Option<&str>,
    replays: &LeaseReplayCache,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(encoded_lease) = encoded_lease else {
        if profile.payload.require_agent_lease {
            return Err("profile requires an agent lease".into());
        }
        return Ok(());
    };
    let lease: AgentLease = serde_json::from_str(encoded_lease)?;
    if lease.payload.profile_id != profile.payload.profile_id {
        return Err("agent lease belongs to another profile".into());
    }
    let encoded_key = profile
        .payload
        .agent_lease_public_keys
        .get(&lease.payload.agent_id)
        .ok_or("agent is not authorized by this profile")?;
    let raw = STANDARD.decode(encoded_key)?;
    let key = VerifyingKey::from_bytes(
        &raw.try_into()
            .map_err(|_| "agent lease key must be 32 bytes")?,
    )?;
    lease.verify(&key, Utc::now())?;
    let mut cache = replays.lock().await;
    let now = Utc::now();
    cache.retain(|_, expiry| *expiry > now);
    if cache.len() >= 65_536 {
        return Err("agent lease replay cache capacity reached".into());
    }
    if cache
        .insert(lease.payload.nonce_b64.clone(), lease.payload.expires_at)
        .is_some()
    {
        return Err("agent lease replayed".into());
    }
    Ok(())
}

fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        Some(6) if packet.len() >= 40 => {
            let bytes: [u8; 16] = packet[8..24].try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

async fn gateway_outbound(device: Arc<tun_rs::AsyncDevice>, connections: Connections) {
    let mut buffer = vec![0u8; MAX_IP_PACKET_BYTES];
    let mut packet_id = 1u64;
    loop {
        let Ok(length) = device.recv(&mut buffer).await else {
            break;
        };
        let packet = &buffer[..length];
        let Ok(metadata) = packet_metadata(packet) else {
            continue;
        };
        let Some(state) = connections.read().await.get(&metadata.destination).cloned() else {
            continue;
        };
        if !state
            .flows
            .lock()
            .await
            .accepts_response(&metadata, Instant::now())
        {
            continue;
        }
        let Ok(fragments) = fragment_packet(packet_id, packet) else {
            continue;
        };
        for fragment in fragments {
            let Ok(encoded) = fragment.encode() else {
                continue;
            };
            if state
                .connection
                .send_datagram(Bytes::from(encoded))
                .is_err()
            {
                break;
            }
        }
        packet_id = packet_id.wrapping_add(1).max(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn udp_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet
    }

    #[test]
    fn flow_table_allows_only_reverse_traffic() {
        let client = Ipv4Addr::new(10, 88, 0, 2);
        let service = Ipv4Addr::new(10, 88, 0, 1);
        let now = Instant::now();
        let request = packet_metadata(&udp_packet(client, service, 40_000, 9090)).unwrap();
        let response = packet_metadata(&udp_packet(service, client, 9090, 40_000)).unwrap();
        let unsolicited = packet_metadata(&udp_packet(service, client, 9091, 40_000)).unwrap();
        let mut table = FlowTable::default();

        assert!(!table.accepts_response(&response, now));
        assert!(table.record_request(&request, now));
        assert!(table.accepts_response(&response, now));
        assert!(!table.accepts_response(&unsolicited, now));
    }
}
