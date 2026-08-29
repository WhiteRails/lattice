use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use thiserror::Error;

pub const DATAGRAM_MAGIC: [u8; 4] = *b"LNP1";
pub const DATAGRAM_HEADER_BYTES: usize = 20;
pub const MAX_IP_PACKET_BYTES: usize = 65_535;
pub const MAX_FRAGMENT_PAYLOAD_BYTES: usize = 1_100;
pub const MAX_FRAGMENTS_PER_PACKET: usize = 64;
pub const DEFAULT_REASSEMBLY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_REASSEMBLY_PACKETS: usize = 1_024;
pub const DEFAULT_REASSEMBLY_TTL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFragment {
    pub packet_id: u64,
    pub offset: u16,
    pub total_len: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("invalid LNP datagram magic or version")]
    InvalidHeader,
    #[error("LNP datagram is truncated")]
    Truncated,
    #[error("packet or fragment exceeds protocol limits")]
    LimitExceeded,
    #[error("fragment range is invalid")]
    InvalidRange,
    #[error("packet is not canonical IPv4 or IPv6")]
    InvalidIp,
    #[error("conflicting duplicate fragment")]
    ConflictingFragment,
    #[error("reassembly budget exhausted")]
    ReassemblyBudget,
}

impl PacketFragment {
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        validate_fragment(self)?;
        let mut out = Vec::with_capacity(DATAGRAM_HEADER_BYTES + self.payload.len());
        out.extend_from_slice(&DATAGRAM_MAGIC);
        out.push(1);
        out.push(0);
        out.extend_from_slice(&self.packet_id.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, PacketError> {
        if input.len() < DATAGRAM_HEADER_BYTES {
            return Err(PacketError::Truncated);
        }
        if input[..4] != DATAGRAM_MAGIC || input[4] != 1 || input[5] != 0 {
            return Err(PacketError::InvalidHeader);
        }
        let payload_len = u16::from_be_bytes(input[18..20].try_into().unwrap()) as usize;
        if input.len() != DATAGRAM_HEADER_BYTES + payload_len {
            return Err(PacketError::Truncated);
        }
        let fragment = Self {
            packet_id: u64::from_be_bytes(input[6..14].try_into().unwrap()),
            offset: u16::from_be_bytes(input[14..16].try_into().unwrap()),
            total_len: u16::from_be_bytes(input[16..18].try_into().unwrap()),
            payload: input[20..].to_vec(),
        };
        validate_fragment(&fragment)?;
        Ok(fragment)
    }
}

pub fn fragment_packet(packet_id: u64, packet: &[u8]) -> Result<Vec<PacketFragment>, PacketError> {
    validate_ip_packet(packet)?;
    if packet.len() > MAX_IP_PACKET_BYTES {
        return Err(PacketError::LimitExceeded);
    }
    let fragments: Vec<_> = packet
        .chunks(MAX_FRAGMENT_PAYLOAD_BYTES)
        .enumerate()
        .map(|(index, chunk)| PacketFragment {
            packet_id,
            offset: (index * MAX_FRAGMENT_PAYLOAD_BYTES) as u16,
            total_len: packet.len() as u16,
            payload: chunk.to_vec(),
        })
        .collect();
    if fragments.len() > MAX_FRAGMENTS_PER_PACKET {
        return Err(PacketError::LimitExceeded);
    }
    Ok(fragments)
}

fn validate_fragment(fragment: &PacketFragment) -> Result<(), PacketError> {
    let total_len = fragment.total_len as usize;
    let offset = fragment.offset as usize;
    if total_len == 0
        || total_len > MAX_IP_PACKET_BYTES
        || fragment.payload.is_empty()
        || fragment.payload.len() > MAX_FRAGMENT_PAYLOAD_BYTES
    {
        return Err(PacketError::LimitExceeded);
    }
    if offset >= total_len || offset + fragment.payload.len() > total_len {
        return Err(PacketError::InvalidRange);
    }
    Ok(())
}

pub fn validate_ip_packet(packet: &[u8]) -> Result<(), PacketError> {
    let Some(first) = packet.first() else {
        return Err(PacketError::InvalidIp);
    };
    match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(PacketError::InvalidIp);
            }
            let ihl = ((first & 0x0f) as usize) * 4;
            let declared = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if ihl < 20 || ihl > packet.len() || declared != packet.len() || declared < ihl {
                return Err(PacketError::InvalidIp);
            }
        }
        6 => {
            if packet.len() < 40 {
                return Err(PacketError::InvalidIp);
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if payload_len + 40 != packet.len() {
                return Err(PacketError::InvalidIp);
            }
        }
        _ => return Err(PacketError::InvalidIp),
    }
    Ok(())
}

struct Assembly {
    total_len: usize,
    fragments: BTreeMap<usize, Vec<u8>>,
    bytes: usize,
    created: Instant,
}

pub struct PacketReassembler {
    entries: HashMap<u64, Assembly>,
    bytes: usize,
    max_bytes: usize,
    max_packets: usize,
    ttl: Duration,
}

impl Default for PacketReassembler {
    fn default() -> Self {
        Self::new(
            DEFAULT_REASSEMBLY_BYTES,
            DEFAULT_REASSEMBLY_PACKETS,
            DEFAULT_REASSEMBLY_TTL,
        )
    }
}

impl PacketReassembler {
    pub fn new(max_bytes: usize, max_packets: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            bytes: 0,
            max_bytes,
            max_packets,
            ttl,
        }
    }

    pub fn push(&mut self, fragment: PacketFragment, now: Instant) -> Result<Option<Vec<u8>>, PacketError> {
        self.evict_expired(now);
        validate_fragment(&fragment)?;
        if !self.entries.contains_key(&fragment.packet_id) && self.entries.len() >= self.max_packets {
            return Err(PacketError::ReassemblyBudget);
        }
        let entry = self.entries.entry(fragment.packet_id).or_insert_with(|| Assembly {
            total_len: fragment.total_len as usize,
            fragments: BTreeMap::new(),
            bytes: 0,
            created: now,
        });
        if entry.total_len != fragment.total_len as usize {
            return Err(PacketError::ConflictingFragment);
        }
        let offset = fragment.offset as usize;
        if let Some(existing) = entry.fragments.get(&offset) {
            return if existing == &fragment.payload {
                Ok(None)
            } else {
                Err(PacketError::ConflictingFragment)
            };
        }
        let new_bytes = fragment.payload.len();
        if self.bytes + new_bytes > self.max_bytes || entry.fragments.len() >= MAX_FRAGMENTS_PER_PACKET {
            return Err(PacketError::ReassemblyBudget);
        }
        for (&existing_offset, existing) in &entry.fragments {
            let a = offset..offset + new_bytes;
            let b = existing_offset..existing_offset + existing.len();
            if a.start < b.end && b.start < a.end {
                return Err(PacketError::ConflictingFragment);
            }
        }
        entry.fragments.insert(offset, fragment.payload);
        entry.bytes += new_bytes;
        self.bytes += new_bytes;
        if entry.bytes != entry.total_len {
            return Ok(None);
        }
        let mut cursor = 0;
        let mut packet = Vec::with_capacity(entry.total_len);
        for (&fragment_offset, bytes) in &entry.fragments {
            if fragment_offset != cursor {
                return Ok(None);
            }
            packet.extend_from_slice(bytes);
            cursor += bytes.len();
        }
        if cursor != entry.total_len {
            return Ok(None);
        }
        validate_ip_packet(&packet)?;
        let removed = self.entries.remove(&fragment.packet_id).unwrap();
        self.bytes -= removed.bytes;
        Ok(Some(packet))
    }

    pub fn evict_expired(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter_map(|(&id, entry)| (now.duration_since(entry.created) >= self.ttl).then_some(id))
            .collect();
        for id in expired {
            if let Some(entry) = self.entries.remove(&id) {
                self.bytes -= entry.bytes;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(payload_bytes: usize) -> Vec<u8> {
        let len = 20 + payload_bytes;
        let mut packet = vec![0; len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[9] = 1;
        packet
    }

    #[test]
    fn fragmented_packet_round_trips_out_of_order() {
        let packet = ipv4_packet(3_000);
        let mut fragments = fragment_packet(7, &packet).unwrap();
        fragments.reverse();
        let now = Instant::now();
        let mut reassembler = PacketReassembler::default();
        let mut result = None;
        for fragment in fragments {
            result = reassembler.push(fragment, now).unwrap().or(result);
        }
        assert_eq!(result.unwrap(), packet);
    }

    #[test]
    fn overlapping_fragments_fail_closed() {
        let now = Instant::now();
        let mut reassembler = PacketReassembler::default();
        reassembler
            .push(PacketFragment { packet_id: 1, offset: 0, total_len: 40, payload: vec![0; 20] }, now)
            .unwrap();
        let error = reassembler
            .push(PacketFragment { packet_id: 1, offset: 10, total_len: 40, payload: vec![0; 20] }, now)
            .unwrap_err();
        assert_eq!(error, PacketError::ConflictingFragment);
    }
}

