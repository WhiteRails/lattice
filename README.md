# Lattice Network Protocol

<p align="center">
  <img src="docs/assets/lattice.svg" alt="Lattice logo" width="180" />
</p>

Lattice is a managed private network for connecting agents, people, and
services without exposing them directly to the Internet. Applications keep
using TCP, UDP, or ICMP normally; `lattice-netd` captures those packets on a
virtual interface and carries them through **LNP/1**, a QUIC tunnel with TLS
1.3, mTLS, signed routes, and L3/L4 policy.

```text
your application → Lattice interface (TUN) → QUIC/mTLS → Gateway → private service
```

The first installable distribution is Linux. macOS and Windows adapters are
included for compilation and testing, but require platform entitlements,
signing, and notarization before they can be distributed.

## Get started in five minutes

### 1. Try the code without changing your network

You need Rust 1.88+, Node.js 20+, and CMake/OpenSSL for the native daemon.

```bash
git clone <repository-url>
cd AgneticProtocol
npm install
npm run build:network
npm run test:network
```

This builds `lattice-netd`, `lattice-gatewayd`, `lattice-resolver`, and
`lattice-netctl`, then runs the network workspace tests. It does not create a
VPN by itself: a signed profile, TUN permissions, and a Gateway are required.

### 2. Install the Linux client

Download a Lattice release bundle, extract it, and run:

```bash
sudo ./install-network.sh
```

The installer places the binaries, systemd units, the `lttc://` URI handler,
forwarding settings, and protected profile directories. It does not create an
identity automatically: the private key is generated in the OS store during
enrollment.

### 3. Enroll a profile

An operator must provide a signed `profile.offer.json`. The offer contains the
private TLS root, Gateway pin, initial routes/policies, and a one-time token;
**it never contains a private key**.

First, create the control-plane key pair on the operator or Gateway host:

```bash
lattice-netctl pki-init --out /secure/lattice-pki --organization example
```

`pki-init` generates `control-signing-key.pem` (keep this private) and the
corresponding pinned public key at
`/secure/lattice-pki/control-public-key.b64`. Read only the public value:

```bash
CONTROL_KEY=$(tr -d '[:space:]' < /secure/lattice-pki/control-public-key.b64)
echo "$CONTROL_KEY"
```

Use that base64 value when enrolling a client. Never copy
`control-signing-key.pem` to a client machine or commit it to Git.

```bash
export LATTICE_CONTROL_PUBLIC_KEY_B64="$CONTROL_KEY"
sudo -E lattice profile enroll /secure/profile.offer.json
sudo lattice profile status
```

The command creates the client key locally, sends a pinned CSR, and stores the
profile under `/var/lib/lattice/profiles/<uuid>` with restrictive permissions.
Certificates and leases are short-lived; if signed state is stale for 24 hours,
the tunnel closes (fail closed).

If you need the profile UUID, read it from the offer instead of inventing one:

```bash
jq -r '.payload.profile_template.profile_id' /secure/profile.offer.json
```

### 4. Connect and verify

The recommended mode is systemd, which keeps the profile pin and state active:

```bash
sudo systemctl enable --now lattice-resolver
sudo systemctl enable --now lattice-netd@<profile-uuid>
sudo lattice profile status --profile-id <profile-uuid>
ip -br addr | grep -E 'lp|lattice' || true
ip route
```

For a manual test, keep the same pinned control key in the environment:

```bash
sudo -E lattice profile connect --profile-id <profile-uuid>
```

If TUN, permissions, or the profile are invalid, the command fails; it does
not enable a proxy fallback or leave traffic open.

To stop or renew a profile:

```bash
sudo lattice profile disconnect --profile-id <profile-uuid>
sudo -E lattice profile renew --bundle /secure/profile.offer.json
```

### 5. Test DNS and a service

Private names are resolved from signed routes. On a Linux host using
`systemd-resolved`:

```bash
resolvectl query echo.lattice
```

When a binding publishes HTTPS and the private CA is installed, test it with
`curl --fail --noproxy '*' https://<service>.coral/health` (or its `.reef`
alias). The Docker example uses HTTP test endpoints and validates them with
`network/tests/dev-client-e2e.sh`.

The Docker development client does not have `systemd-resolved`. The scripts
below assume the development stack is already running (containers named
`lattice-lnp-e2e` and `lattice-dev-gateway`, with `/dev/net/tun`). From the
Docker host, configure split DNS and run the E2E check:

```bash
network/tests/configure-dev-dns.sh
network/tests/dev-client-e2e.sh <profile-uuid>
```

The bridge sends only `.lattice`, `.coral`, and `.reef` to the Lattice resolver
and keeps public resolvers for everything else. A public name queried directly
against the Lattice resolver returns `REFUSED` by design.

### Quick troubleshooting

- `profile status` shows no profiles: enrollment has not run, or you are using
  a different `--state-dir`.
- `ping echo.lattice` says *Name or service not known*: check `resolvectl
  status`; in Docker, rerun `network/tests/configure-dev-dns.sh` and isolate
  DNS with `dig @127.0.0.1 -p 5353 echo.lattice`.
- No `lp...` interface appears: the process lacks TUN/network permissions or
  the profile was rejected. Check `journalctl -u lattice-netd@<profile-uuid>`;
  do not disable the kill switch to test.

## Naming

Each namespace has one job:

| Name | Meaning | Example |
| --- | --- | --- |
| `lttc://` | Deep link that activates a profile and opens HTTPS | `lttc://alice.coral/health` |
| `*.coral` | Participant identity or delegated service | `alice.coral`, `api.alice.coral` |
| `<hash>.coral` | Canonical identity derived from the service TLS SPKI | `<base32-sha256>.coral` |
| `*.reef` | Human-readable on-chain registered name | `clipma.reef` |
| `*.lattice` | Lattice infrastructure | `resolver.lattice`, `echo.lattice` |

The virtual IP (`10.x`, `fd00:...`) is only a current route. The actual
identity is established by the profile signature, TLS certificate, and SPKI
pin. A human alias is valid only when signed and delegated by its canonical
identity. A service can therefore change Wi-Fi, Gateway, or IP without changing
its name.

Examples:

```text
lttc://alice.coral/                  → https://alice.coral/
lttc://api.alice.coral/health        → https://api.alice.coral/health
lttc://clipma.reef/orders?id=42      → https://clipma.reef/orders?id=42
lttc://echo/health                    → https://echo.lattice/health
```

The parser accepts only `lttc://`. It rejects `lattice://`, `lp://`,
credentials, explicit ports, fragments, IP literals, and non-canonical hosts.
Chrome receives no password and is not configured with a proxy: the handler
validates the deep link, activates the required profile, and lets Chrome use
HTTPS with the private CA installed on the managed device.

## What LNP/1 includes

- **`lattice-net-core`**: control frames, bounded fragmentation, profiles,
  leases, policy, URI validation, and TLS pinning.
- **`lattice-netd`**: QUIC client, TUN, routes, DNS, kill switch, and profile
  lifecycle; `lattice run --agent ...` requires verifiable isolation.
- **`lattice-gatewayd`**: mTLS Gateway authorizing profile, agent, service or
  CIDR, protocol, and port before forwarding packets.
- **`lattice-resolver`**: authoritative resolver for `.lattice`, `.coral`, and
  `.reef`; it never leaks private queries to public DNS.
- **`lattice-netctl`**: private X.509 PKI, CSRs, bundles, revocation, and egress
  allowlists.
- **`latticed`**: local Ed25519 key custody and short-lived agent leases.

QUIC provides encryption and congestion control; Lattice does not invent
cryptography. LNP/1 advertises MTU 1280 and bounds reassembly size, count, age,
and memory. Split-tunnel and full-tunnel are explicit profile choices; a
full-tunnel profile requires a Gateway with an egress allowlist.

## Per-agent isolation

On Linux, per-agent mode creates a dedicated namespace and permits only
loopback, the Lattice interface, and the exact Gateway UDP endpoint:

```bash
sudo --preserve-env=LATTICE_CONTROL_PUBLIC_KEY_B64 \
  lattice run --agent bot1 --profile <profile-uuid> -- /path/to/your-agent
```

If the system cannot prove that isolation, the command refuses to run. macOS
and Windows enable per-app mode only when native or MDM policy is verifiable.

## Migrating from the previous overlay

The HTTP/Relay overlay and `lp://` addresses are archived; there is no runtime
fallback. The migrator transforms namespaces, services, and grants once into
virtual-IP bindings and L3/L4 rules. It never copies old private keys or JSON
certificates.

```bash
npm run migrate:network -- \
  --agent bot1 --organization example \
  --gateway 203.0.113.10:7443 --gateway-name gateway.example.com \
  --gateway-pin <gateway-spki-sha256> \
  --service-tls-pin <service-spki-sha256> \
  --enrollment-token <one-time-token> --mode split \
  --out /secure/profile-template.json
```

HTTP authorizations are preserved only with an explicit `--terminate-tls`; an
encrypted packet does not imply HTTP permission by itself.

## Platform status

- **Linux:** installable client with TUN, systemd, `iproute2`, `nftables`, split
  DNS, and namespaces. This is the only distribution in this release.
- **macOS:** compilable `NEPacketTunnelProvider` host. Requires Network
  Extension entitlement, Apple signing, and notarization.
- **Windows:** compilable `IVpnPlugIn`/MSIX host. Requires Microsoft signing and
  a traffic-filter policy for per-app mode.
- **Mobile:** out of scope.

## Development and validation

```bash
npm run build                 # TypeScript
npm run build:contracts       # LatticeChain ABI/bin
npm run build:network         # LNP/1 Rust workspace
npm run test:network          # Rust workspace tests
npm run test:rust             # LTP/1 Rust client
cargo clippy --manifest-path network/Cargo.toml --workspace --all-targets -- -D warnings
```

Privileged network tests require Linux with `/dev/net/tun`, `iproute2`,
`nftables`, `setpriv`, and network permissions. macOS and Windows tests run on
native CI runners. Before enabling a VPN outside a local environment, complete
authenticated E2E tests, DNS leak checks, revocation, control-plane outage,
IPv4/IPv6/DoH/proxy bypass blocking, and a fresh security audit.

## Security and operations

Log only profile identity, destination service or IP, protocol, bytes, decision,
policy version, and fingerprints. Never log payloads or complete DNS queries.
Revoke profiles/certificates from the control plane and renew before 90 days.

More detail:

- [Naming specification](docs/lattice-naming-protocol.md)
- [LNP/1](docs/lnp-1.md)
- [Platform support](docs/platform-support.md)
- [`lttc://` scheme](docs/lattice-uri-scheme.md)
- [Operations runbook](RUNBOOK.md)

## Repository layout

```text
network/       LNP/1 Rust workspace (client, Gateway, resolver, PKI)
clients/rust/  native LTP/1 client and `lattice` wrapper
daemon/        `latticed`, local key custody
node/          archived control plane/overlay for migration and audit
contracts/     LatticeChain and on-chain bindings
services/      example services (including echo)
tests/         TypeScript tests
docs/          specifications and runbooks
```

Refer to the license terms included with the release you distribute.

Lattice is designed to fail closed: a missing profile, invalid signature,
expired route, or unverifiable adapter blocks traffic instead of silently
degrading to HTTP, a proxy, or `lp://`.
