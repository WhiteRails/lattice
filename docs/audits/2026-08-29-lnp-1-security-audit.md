# LNP/1 security audit — 2026-08-29

## Scope

Reviewed the LNP/1 Rust workspace, Linux enforcement, native CLI integration,
the network binding contract/migrator and the retirement boundary for the
previous HTTP/WebSocket overlay. This is a repository-level implementation
audit, not an independent penetration test or a production authorization.

## Verified remediation

- Signed profile verification is anchored to an externally supplied control
  key; stale, expired and revoked profiles fail closed.
- QUIC uses TLS 1.3 mTLS and pins the server and profile-client SPKIs.
- LNP/1 control frames, fragments and reassembly have length, age, count and
  memory limits; overlaps fail closed.
- Gateway admission binds an authenticated profile to its assigned source IP,
  validates one-time agent leases and rejects replay.
- Both tunnel endpoints enforce the signed-state deadline for an established
  connection. The Gateway therefore closes a client that attempts to retain a
  QUIC session past the profile's expiry or 24-hour freshness ceiling.
- Gateway return traffic is now stateful and bounded: only the reverse of a
  profile-authorized client flow reaches a virtual client address. Unsolicited
  private-network packets are dropped.
- Linux full tunnel has a namespace-scoped exclusive lock, explicit Gateway
  UDP exception and nftables output-drop policy. Agent execution uses a fresh
  namespace, unprivileged UID, `no_new_privs`, a dedicated resolver and
  fail-closed setup.
- `*.lattice` DNS is authoritative-only and never forwards unknown private
  names. Legacy proxy commands are rejected; old source and examples are
  labelled archived rather than a runtime fallback.

## Evidence

- `cargo test --locked --manifest-path network/Cargo.toml --workspace`: 15
  tests passed, including parser, reassembly, signature, revocation, URI,
  resolver and stateful-return tests.
- `cargo clippy --locked --manifest-path network/Cargo.toml --workspace --all-targets -- -D warnings`: passed.
- Privileged Docker Linux E2E passed in split and full modes: QUIC/mTLS, TUN,
  IPv4/IPv6 TCP, UDP, ICMP/ICMPv6, private DNS, route enforcement,
  full-tunnel underlay-bypass denial, unsolicited return-traffic denial and
  signed-revocation tunnel closure.
- Docker enrollment E2E passed: client-local key/CSR generation, signed offer,
  root/SPKI-pinned QUIC service, final profile verification and one-time-token
  replay denial.
- The enrolment E2E was also run directly on the development host after making
  its UUID, date and permission checks portable; it passed with the same
  pinned-QUIC and replay-denial assertions.
- `npm test`: 216 tests passed and 6 historical-overlay tests skipped; `npm
  audit --audit-level=high`: zero vulnerabilities.
- `cargo audit`: no known vulnerabilities in either lockfile. The network
  lockfile retains advisory warnings for unmaintained `paste` and
  `rustls-pemfile`, plus transitive yanked `chacha20`; these require upstream
  replacement/upgrade tracking before a production release.

## Release blockers and limits

- The Linux E2E is an isolated namespace test, not the full release matrix:
  split tunnel, control-plane outage, DoH/proxy bypass and browser Chrome
  trust must still run on a managed Linux host.
- Linux now generates the profile key locally in its protected state directory
  and enrolls by a one-time CSR over a pinned QUIC endpoint. Native Keychain
  and Windows certificate-store backends remain outstanding for their adapters.
- macOS and Windows hosts compile as fail-closed adapters, but their Rust
  packet engine bridge, platform-native tests, signing/notarization and public
  installers are not complete.
- No verified critical or high finding remains in the reviewed LNP/1 code at
  this revision. That statement does not cover the archived overlay as a
  deployable transport, nor replace an independent audit.
