use std::collections::HashMap;
use std::net::IpAddr;

use thiserror::Error;

const DNS_HEADER_BYTES: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_DNS_MESSAGE_BYTES: usize = 4_096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("malformed DNS query")]
    Malformed,
    #[error("unsupported DNS query")]
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct ResolverTable {
    entries: HashMap<String, Vec<IpAddr>>,
    ttl: u32,
}

impl ResolverTable {
    pub fn new(entries: impl IntoIterator<Item = (String, Vec<IpAddr>)>, ttl: u32) -> Result<Self, DnsError> {
        if ttl == 0 || ttl > 300 { return Err(DnsError::Unsupported); }
        let mut table = HashMap::new();
        for (name, addresses) in entries {
            if !lattice_net_core::profile::valid_lattice_fqdn(&name) || addresses.is_empty() {
                return Err(DnsError::Unsupported);
            }
            table.insert(name, addresses);
        }
        Ok(Self { entries: table, ttl })
    }

    pub fn answer(&self, query: &[u8]) -> Result<Vec<u8>, DnsError> {
        if query.len() < DNS_HEADER_BYTES || query.len() > MAX_DNS_MESSAGE_BYTES { return Err(DnsError::Malformed); }
        let flags = u16::from_be_bytes([query[2], query[3]]);
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if flags & 0x8000 != 0 || qdcount != 1 { return Err(DnsError::Unsupported); }
        let (name, name_end) = parse_name(query, DNS_HEADER_BYTES, 0)?;
        if name_end + 4 > query.len() { return Err(DnsError::Malformed); }
        let qtype = u16::from_be_bytes([query[name_end], query[name_end + 1]]);
        let qclass = u16::from_be_bytes([query[name_end + 2], query[name_end + 3]]);
        if qclass != CLASS_IN || !matches!(qtype, TYPE_A | TYPE_AAAA) {
            return Ok(response(query, name_end + 4, &[], qtype, self.ttl, 0));
        }
        if !name.ends_with(".lattice") {
            return Ok(response(query, name_end + 4, &[], qtype, self.ttl, 5));
        }
        let Some(addresses) = self.entries.get(&name) else {
            return Ok(response(query, name_end + 4, &[], qtype, self.ttl, 3));
        };
        let filtered: Vec<_> = addresses.iter().copied().filter(|address| {
            matches!((qtype, address), (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_)))
        }).collect();
        Ok(response(query, name_end + 4, &filtered, qtype, self.ttl, 0))
    }
}

fn parse_name(message: &[u8], start: usize, depth: usize) -> Result<(String, usize), DnsError> {
    if depth > 8 || start >= message.len() { return Err(DnsError::Malformed); }
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut wire_end = None;
    let mut total_len = 0usize;
    loop {
        let length = *message.get(cursor).ok_or(DnsError::Malformed)?;
        if length & 0xc0 == 0xc0 {
            let next = *message.get(cursor + 1).ok_or(DnsError::Malformed)?;
            let pointer = (((length & 0x3f) as usize) << 8) | next as usize;
            if pointer >= cursor { return Err(DnsError::Malformed); }
            wire_end.get_or_insert(cursor + 2);
            let (suffix, _) = parse_name(message, pointer, depth + 1)?;
            labels.extend(suffix.split('.').map(str::to_owned));
            break;
        }
        if length & 0xc0 != 0 || length > 63 { return Err(DnsError::Malformed); }
        cursor += 1;
        if length == 0 { wire_end.get_or_insert(cursor); break; }
        let end = cursor.checked_add(length as usize).ok_or(DnsError::Malformed)?;
        let raw = message.get(cursor..end).ok_or(DnsError::Malformed)?;
        if !raw.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-') { return Err(DnsError::Malformed); }
        let label = std::str::from_utf8(raw).map_err(|_| DnsError::Malformed)?.to_ascii_lowercase();
        total_len += label.len() + usize::from(!labels.is_empty());
        if total_len > 253 { return Err(DnsError::Malformed); }
        labels.push(label);
        cursor = end;
    }
    if labels.is_empty() { return Err(DnsError::Malformed); }
    Ok((labels.join("."), wire_end.unwrap()))
}

fn response(query: &[u8], question_end: usize, addresses: &[IpAddr], qtype: u16, ttl: u32, rcode: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(question_end + addresses.len() * 32);
    out.extend_from_slice(&query[..2]);
    let request_flags = u16::from_be_bytes([query[2], query[3]]);
    let response_flags = 0x8000 | 0x0400 | (request_flags & 0x0100) | (rcode & 0x000f);
    out.extend_from_slice(&response_flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[DNS_HEADER_BYTES..question_end]);
    for address in addresses {
        out.extend_from_slice(&0xc00cu16.to_be_bytes());
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        match address {
            IpAddr::V4(value) => { out.extend_from_slice(&4u16.to_be_bytes()); out.extend_from_slice(&value.octets()); }
            IpAddr::V6(value) => { out.extend_from_slice(&16u16.to_be_bytes()); out.extend_from_slice(&value.octets()); }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') { out.push(label.len() as u8); out.extend_from_slice(label.as_bytes()); }
        out.push(0); out.extend_from_slice(&qtype.to_be_bytes()); out.extend_from_slice(&CLASS_IN.to_be_bytes()); out
    }

    fn answer_addresses(message: &[u8]) -> Vec<IpAddr> {
        let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
        let (_, question_end) = parse_name(message, DNS_HEADER_BYTES, 0).unwrap();
        let mut cursor = question_end + 4;
        let mut result = Vec::new();
        for _ in 0..answers {
            let (_, name_end) = parse_name(message, cursor, 0).unwrap();
            cursor = name_end;
            let kind = u16::from_be_bytes([message[cursor], message[cursor + 1]]);
            let length = u16::from_be_bytes([message[cursor + 8], message[cursor + 9]]) as usize;
            cursor += 10;
            let data = &message[cursor..cursor + length];
            match (kind, data.len()) {
                (TYPE_A, 4) => result.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
                (TYPE_AAAA, 16) => result.push(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).unwrap()))),
                _ => {}
            }
            cursor += length;
        }
        result
    }

    #[test]
    fn resolves_only_lattice_names() {
        let table = ResolverTable::new([("echo.lattice".into(), vec!["10.64.0.2".parse().unwrap()])], 30).unwrap();
        let answer = table.answer(&query("echo.lattice", TYPE_A)).unwrap();
        assert_eq!(answer_addresses(&answer), vec!["10.64.0.2".parse::<IpAddr>().unwrap()]);
        let refused = table.answer(&query("example.com", TYPE_A)).unwrap();
        assert_eq!(u16::from_be_bytes([refused[2], refused[3]]) & 0xf, 5);
    }

    #[test]
    fn unknown_lattice_name_is_nxdomain_without_forwarding() {
        let table = ResolverTable::new([], 30).unwrap();
        let answer = table.answer(&query("missing.lattice", TYPE_A)).unwrap();
        assert_eq!(u16::from_be_bytes([answer[2], answer[3]]) & 0xf, 3);
    }
}
