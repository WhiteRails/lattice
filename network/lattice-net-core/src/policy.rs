use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packet::validate_ip_packet;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelMode {
    Split,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub destination: IpNet,
    #[serde(default)]
    pub protocols: Vec<IpProtocol>,
    #[serde(default)]
    pub ports: Vec<PortRange>,
    #[serde(default)]
    pub service: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }

    pub fn is_valid(&self) -> bool {
        self.start <= self.end
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    pub version: u64,
    pub mode: TunnelMode,
    #[serde(default)]
    pub allow: Vec<NetworkRule>,
    #[serde(default)]
    pub deny: Vec<NetworkRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: IpProtocol,
    pub destination_port: Option<u16>,
    pub bytes: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("invalid packet")]
    InvalidPacket,
    #[error("invalid port range")]
    InvalidPortRange,
}

impl NetworkPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.allow.iter().chain(&self.deny).flat_map(|r| &r.ports).any(|p| !p.is_valid()) {
            return Err(PolicyError::InvalidPortRange);
        }
        Ok(())
    }

    pub fn authorize(&self, packet: &[u8]) -> Result<(bool, PacketMetadata), PolicyError> {
        self.validate()?;
        let metadata = packet_metadata(packet)?;
        if self.deny.iter().any(|rule| rule_matches(rule, &metadata)) {
            return Ok((false, metadata));
        }
        Ok((self.allow.iter().any(|rule| rule_matches(rule, &metadata)), metadata))
    }
}

fn rule_matches(rule: &NetworkRule, metadata: &PacketMetadata) -> bool {
    if !rule.destination.contains(&metadata.destination) {
        return false;
    }
    if !rule.protocols.is_empty()
        && !rule.protocols.contains(&IpProtocol::Any)
        && !rule.protocols.contains(&metadata.protocol)
    {
        return false;
    }
    if rule.ports.is_empty() {
        return true;
    }
    metadata
        .destination_port
        .is_some_and(|port| rule.ports.iter().any(|range| range.contains(port)))
}

pub fn packet_metadata(packet: &[u8]) -> Result<PacketMetadata, PolicyError> {
    validate_ip_packet(packet).map_err(|_| PolicyError::InvalidPacket)?;
    match packet[0] >> 4 {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => Err(PolicyError::InvalidPacket),
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<PacketMetadata, PolicyError> {
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let protocol_number = packet[9];
    let source = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));
    let (protocol, destination_port) = transport_metadata(protocol_number, &packet[ihl..], false)?;
    Ok(PacketMetadata { source, destination, protocol, destination_port, bytes: packet.len() })
}

fn parse_ipv6(packet: &[u8]) -> Result<PacketMetadata, PolicyError> {
    let protocol_number = packet[6];
    // Extension headers are not interpreted in LNP/1 policy. They fail closed
    // instead of allowing a port rule to be bypassed through header chains.
    if matches!(protocol_number, 0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140) {
        return Err(PolicyError::InvalidPacket);
    }
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap()));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap()));
    let (protocol, destination_port) = transport_metadata(protocol_number, &packet[40..], true)?;
    Ok(PacketMetadata { source, destination, protocol, destination_port, bytes: packet.len() })
}

fn transport_metadata(number: u8, payload: &[u8], ipv6: bool) -> Result<(IpProtocol, Option<u16>), PolicyError> {
    match number {
        6 => {
            if payload.len() < 4 { return Err(PolicyError::InvalidPacket); }
            Ok((IpProtocol::Tcp, Some(u16::from_be_bytes([payload[2], payload[3]]))))
        }
        17 => {
            if payload.len() < 4 { return Err(PolicyError::InvalidPacket); }
            Ok((IpProtocol::Udp, Some(u16::from_be_bytes([payload[2], payload[3]]))))
        }
        1 if !ipv6 => Ok((IpProtocol::Icmp, None)),
        58 if ipv6 => Ok((IpProtocol::Icmpv6, None)),
        _ => Err(PolicyError::InvalidPacket),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(destination: Ipv4Addr, port: u16) -> Vec<u8> {
        let mut packet = vec![0; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&1234u16.to_be_bytes());
        packet[22..24].copy_from_slice(&port.to_be_bytes());
        packet
    }

    #[test]
    fn deny_has_precedence_over_allow() {
        let policy = NetworkPolicy {
            version: 1,
            mode: TunnelMode::Split,
            allow: vec![NetworkRule { destination: "10.0.0.0/8".parse().unwrap(), protocols: vec![IpProtocol::Any], ports: vec![], service: None }],
            deny: vec![NetworkRule { destination: "10.2.0.0/16".parse().unwrap(), protocols: vec![IpProtocol::Udp], ports: vec![PortRange { start: 53, end: 53 }], service: None }],
        };
        assert!(!policy.authorize(&udp_packet(Ipv4Addr::new(10, 2, 3, 4), 53)).unwrap().0);
        assert!(policy.authorize(&udp_packet(Ipv4Addr::new(10, 3, 3, 4), 53)).unwrap().0);
    }
}

