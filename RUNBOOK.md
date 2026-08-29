# Lattice LNP/1 operations runbook

This runbook covers the supported OS-level VPN. It contains no proxy or
WebSocket fallback procedure.

## 1. Preconditions

- A private Lattice X.509 root/intermediate and Ed25519 control signing key.
- A managed client whose trust store may receive the private service root.
- Linux: `iproute2`, `nftables`, `systemd`, `util-linux` and TUN.
- UDP reachability to the configured QUIC port (default 7443).

Never copy a CA private key or the control signing key to a client or Gateway.
Runtime services get only their leaf key, chain, trust root and signed profile.

## 2. Initialize PKI

```bash
umask 077
lattice-netctl pki-init --out /secure/lattice-pki --organization example
```

Back up the root offline. Pin `pki-anchor.json` through a separate managed
channel; never trust the key embedded in a bundle by itself.

```bash
lattice-netctl certificate-csr \
  --name gateway.example.com --kind server \
  --key-out /secure/gateway-key.pem --csr-out /tmp/gateway.csr
lattice-netctl certificate-sign \
  --pki /secure/lattice-pki --csr /tmp/gateway.csr \
  --kind server --cert-out /tmp/gateway-chain.pem
```

The output contains leaf plus intermediate; trust stores contain the root.

## 3. Issue a profile

```bash
lattice-netctl enrollment-token-issue --pki /secure/lattice-pki
lattice-netctl enrollment-offer-issue \
  --pki /secure/lattice-pki \
  --template /secure/profile-template.json \
  --endpoint 203.0.113.10:7442 --server-name enroll.example.com \
  --server-cert /secure/enrollment-chain.pem \
  --out /secure/profile.offer.json
```

Required invariants:

- MTU 1280 and explicit `split` or `full` mode.
- SHA-256 SPKI pins for all Gateways and inner services.
- Full-tunnel policy contains only approved egress CIDRs/protocols/ports.
- `max_stale_seconds` is at most 86400.
- Per-agent profiles require leases and pin each agent's raw Ed25519 public key.
- `http_policy` is absent unless the Gateway terminates inner TLS.

Start `lattice-netctl enrollment-serve` on the pinned endpoint with its server
certificate/key. The one-time token is consumed atomically after a valid CSR;
the client creates its own private key and receives the final signed profile.
Offers and profiles never contain private keys. Certificates and profiles may
not exceed 90 days.

## 4. Gateway

Install signed profiles as
`/var/lib/lattice/gateway-profiles/<profile-uuid>.json` and start:

```bash
export LATTICE_CONTROL_PUBLIC_KEY_B64="$(tr -d '\n' </secure/lattice-pki/control-public-key.b64)"
sudo lattice-gatewayd \
  --bind '[::]:7443' \
  --tls-root /etc/lattice/pki/tls-root-cert.pem \
  --server-cert /etc/lattice/pki/gateway-chain.pem \
  --server-key /run/credentials/lattice-gatewayd.service/server-key \
  --profiles-dir /var/lib/lattice/gateway-profiles \
  --tun-ipv4 100.127.0.1/16
```

Route virtual IPs from the Gateway TUN to private backends. A dedicated
full-tunnel Gateway must enforce its egress allowlist as a second boundary.

Audit only profile identity, destination service/IP, protocol, port, bytes,
decision, policy version and fingerprints—never payloads or full DNS questions.

## 5. Linux client

The release bundle's `install-network.sh` installs the four LNP binaries,
systemd units and `lattice:` desktop handler.

```bash
export LATTICE_CONTROL_PUBLIC_KEY_B64='<pinned-control-key>'
sudo lattice profile enroll \
  /secure/profile.offer.json
sudo systemctl enable --now lattice-resolver lattice-netd@<profile-uuid>
```

Root enrolment stores the private key at
`/var/lib/lattice/profiles/<uuid>/client-key.pem` (mode `0600`) and writes the
pinned control key into `/etc/lattice/profiles/<uuid>.env` for the matching
systemd unit. Start the shared `lattice-resolver` plus
`lattice-netd@<uuid>`; do not replace this enrolled key with a copied browser
or application credential. Verify TUN, routes, nftables and DNS:

```bash
sudo lattice profile status --profile-id <profile-uuid>
ip address show lp<first-8-profile-uuid-hex>
ip route show
sudo nft list ruleset
resolvectl query echo.lattice
```

Full mode installs profile route tables and an output-drop kill switch; only
loopback, TUN and the exact Gateway UDP endpoint bypass it.

Configure egress only through a dedicated full-tunnel profile, then sign and
issue the resulting template:

```bash
lattice-netctl profile-egress-allow --template /secure/full-template.json \
  --cidr 198.51.100.0/24 --out /secure/full-template-allowlisted.json
```

## 5.1 One-time legacy migration

Generate only a new unsigned profile template from the archived service/policy
metadata. The migrator excludes all legacy private keys and certificates. It
converts `lp://` grants to L3/L4 and needs `--terminate-tls` before it preserves
an explicit HTTP action policy.

```bash
npm run migrate:network -- \
  --lattice-home /secure/legacy-lattice --agent bot1 --organization example \
  --gateway 203.0.113.10:7443 --gateway-name gateway.example.com \
  --gateway-pin <gateway-spki-sha256> --service-tls-pin <service-spki-sha256> \
  --enrollment-token <one-time-token> --out /secure/profile-template.json
```

Review this template, issue a new enrolment offer, enroll a fresh X.509 client
credential, then revoke and decommission the overlay. Do not copy its agent or
CA material into LNP/1.

## 6. Agent isolation

Confirm `net.ipv4.ip_forward=1`, then:

```bash
sudo --preserve-env=LATTICE_CONTROL_PUBLIC_KEY_B64,LATTICE_SOCKET,LATTICE_SESSION_TOKEN_FILE \
  lattice run --agent <agent-id> --profile <profile-uuid> -- <command> [args...]
```

The process starts only after its namespace veth, dedicated LNP tunnel, private
resolver and output-drop firewall are ready. It runs with `SUDO_UID`/`SUDO_GID`,
cleared groups and `no_new_privs`. Any missing enforcement condition fails
closed before executing the command.

## 7. DNS and browser

Route only the `lattice` domain to `lattice-resolver`. Unknown private names are
NXDOMAIN and public names are REFUSED. Confirm packet capture shows no private
question on public DNS interfaces.

Install the private service root only on managed clients, then test:

```bash
lattice open 'lttc://echo/health'
```

Expected: strict URI validation and `https://echo.lattice/health`. Browser trust
covers inner HTTPS; outer QUIC uses independent LNP mTLS.

## 8. Renewal and revocation

```bash
lattice profile renew --bundle /secure/renewed.bundle.json
lattice-netctl profile-revoke \
  --pki /secure/lattice-pki \
  --profile /secure/profile.bundle.json \
  --out /secure/profile.revoked.json
```

Renewal cannot change profile ID or client SPKI. Atomically distribute a revoked
record to Gateways and client state. Gateways re-check every 30 seconds; changed,
revoked, expired or stale state closes the connection. Clients close at the
earlier of profile expiry and the 24-hour signed-state deadline.

## 9. Release gates

On an isolated Linux host, verify with packet capture and expected-deny cases:

1. IPv4/IPv6 TCP, UDP and ICMP.
2. Split route selection and full-tunnel no-leak behavior.
3. Egress allowlist and QUIC/control-plane failure.
4. IPv4, IPv6, public DNS, DoH and proxy bypass attempts.
5. Unknown private names never fall through to public DNS.
6. Wrong mTLS root/client/Gateway pins and profile signature.
7. Source spoofing, stale/revoked profiles and replayed agent leases.
8. Oversized, overlapping, excess and expired fragments.
9. `lttc://` through Chrome to valid private HTTPS.

Compile/unit evidence is not production E2E. Public enablement requires this
privileged Linux matrix, native tests where signing allows, and a fresh audit
with no verified critical/high issue.

## 10. Rollback

Stop the client/resolver, confirm Lattice nftables tables and routes were
removed, then remove the managed private CA and URI handler. Do not restore the
retired proxy. Reuse an earlier LNP profile only if it remains signed, fresh and
not revoked; otherwise issue a new one.
