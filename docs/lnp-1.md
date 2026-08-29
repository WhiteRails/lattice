# LNP/1 wire and trust contract

LNP/1 carries canonical IPv4 or IPv6 packets in QUIC v1 DATAGRAM frames. QUIC
must negotiate TLS 1.3 with ALPN `lattice-lnp/1`; both peers authenticate with
the private Lattice X.509 hierarchy and independently check the signed SPKI pin.

## Control stream

The first client-initiated bidirectional stream contains one four-byte
big-endian length followed by a JSON `ClientHello`. Maximum JSON size is 64 KiB.
It contains protocol version 1, profile UUID and optional serialized agent
lease. The Gateway replies with `ServerHello` containing version, MTU and policy
version or a bounded error. Unknown versions, trailing bytes and policy mismatch
are fatal.

An agent lease binds agent ID, profile UUID, Linux namespace ID, issue/expiry
and a random nonce. Lifetime is at most five minutes. Its signature key is
pinned in the signed profile and replay nonces are retained until expiry.

## Datagram

```text
0..4    ASCII LNP1
4       version = 1
5       flags (reserved, zero)
6..14   packet ID, big endian
14..16  fragment offset, big endian
16..18  total IP packet bytes, big endian
18..20  fragment payload bytes, big endian
20..    fragment payload
```

The link MTU is 1280. One IP packet is at most 65,535 bytes; fragment payload is
at most 1,100 bytes and count at most 64. Reassembly rejects overlap,
conflicting metadata, out-of-range data and non-canonical IP lengths. Per-peer
budgets are 1,024 in-flight packets, 16 MiB and five seconds. IPv6 extension
headers not understood by policy fail closed.

## Authorization

The Gateway verifies, in order: TLS chain, profile SPKI, signed/fresh profile,
optional lease, replay state, packet source equals the assigned profile address,
valid IP packet, deny rules, then allow rules. A rule matches CIDR, protocol and
optional destination port range. Deny wins. Full tunnel still requires explicit
allow rules and is deployed only against a dedicated egress Gateway.

The client also pins the Gateway, rejects inbound packets not addressed to its
assigned profile IP and closes at the signed-state deadline. Both peers force a
reconnect when signed profile state changes.

Gateway return delivery is stateful: a packet from a private service reaches a
virtual client only when it reverses an active, profile-authorized L3/L4 flow.
The table is bounded to 65,536 flows per profile; unsolicited inbound traffic
fails closed.

## Enrollment stream

Before mTLS credentials exist, a signed enrollment offer supplies the private
root, QUIC endpoint, server name/SPKI pin, profile template and one-time token.
The client verifies the offer against its provisioned control key, creates its
own client key and client-auth CSR, then sends the CSR in a separate QUIC/TLS
1.3 stream using ALPN `lattice-lnp-enroll/1`. The service verifies the token,
issues a 90-day client chain, signs the final profile by replacing only the
client SPKI pin, and atomically consumes the token. Enrollment frames use the
same four-byte length prefix with a 1 MiB maximum.

## DNS and audit

`lattice-resolver` is authoritative for signed `.lattice`, `.coral` and `.reef`
bindings in the profile. Each service has two answers with the same signed
virtual addresses: its human alias and a canonical identity hostname made from
lowercase unpadded base32 of the SHA-256 SPKI pin
(`52-character-label.coral`). The profile signature binds the alias to that
pin; the TLS certificate proves it at connection time. It returns REFUSED for
all other suffixes and does not forward. Audit records contain bounded flow
metadata and decisions, never IP payloads or full DNS query strings.
