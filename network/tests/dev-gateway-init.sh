#!/usr/bin/env bash
# Development-only LNP/1 Gateway bootstrap. State lives in a private Docker
# volume; this script deliberately never places a CA key, enrollment token or
# profile credential in the image or repository.
set -euo pipefail

state_dir=${LATTICE_DEV_STATE_DIR:-/lattice}
bin_dir=${LATTICE_BIN_DIR:-/workspace/network/target/debug}
enrollment_endpoint=${LATTICE_ENROLL_ENDPOINT:?LATTICE_ENROLL_ENDPOINT is required}
gateway_endpoint=${LATTICE_GATEWAY_ENDPOINT:?LATTICE_GATEWAY_ENDPOINT is required}

netctl="$bin_dir/lattice-netctl"
gatewayd="$bin_dir/lattice-gatewayd"

for executable in "$netctl" "$gatewayd"; do
  [ -x "$executable" ] || { echo "missing $executable" >&2; exit 1; }
done

umask 077
mkdir -p "$state_dir"
chmod 700 "$state_dir"

# The Docker bridge is used solely so the host can publish the two UDP
# listeners on its LAN address. The Gateway is nevertheless unable to start
# arbitrary egress connections: only loopback, the LNP TUN, and replies to
# traffic that arrived at the two listeners are permitted.
nft add table inet lattice_dev
nft add chain inet lattice_dev output '{ type filter hook output priority -150 ; policy drop ; }'
nft add rule inet lattice_dev output oifname lo accept
nft add rule inet lattice_dev output oifname lp-gateway0 accept
# Docker's port forwarding may not preserve conntrack state within this
# namespace. These are server response ports only; the Gateway still cannot
# initiate a connection from an arbitrary source port.
nft add rule inet lattice_dev output udp sport '{ 7442, 7443 }' accept
nft add rule inet lattice_dev output ct state established,related accept

if [ ! -f "$state_dir/.initialized" ]; then
  "$netctl" pki-init --out "$state_dir/pki" --organization lattice-development

  "$netctl" certificate-csr \
    --name enroll.dev.lattice --kind server \
    --key-out "$state_dir/enrollment-key.pem" --csr-out "$state_dir/enrollment.csr"
  "$netctl" certificate-sign \
    --pki "$state_dir/pki" --csr "$state_dir/enrollment.csr" \
    --kind server --cert-out "$state_dir/enrollment-chain.pem"

  "$netctl" certificate-csr \
    --name gateway.dev.lattice --kind server \
    --key-out "$state_dir/gateway-key.pem" --csr-out "$state_dir/gateway.csr"
  "$netctl" certificate-sign \
    --pki "$state_dir/pki" --csr "$state_dir/gateway.csr" \
    --kind server --cert-out "$state_dir/gateway-chain.pem"

  enrollment_token=$("$netctl" enrollment-token-issue --pki "$state_dir/pki")
  profile_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
  gateway_pin=$(openssl x509 -in "$state_dir/gateway-chain.pem" -pubkey -noout \
    | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
  issued_at=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
  expires_at=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')

  jq -n \
    --arg profile_id "$profile_id" \
    --arg issued_at "$issued_at" \
    --arg expires_at "$expires_at" \
    --arg token "$enrollment_token" \
    --arg gateway_pin "$gateway_pin" \
    --arg gateway_endpoint "$gateway_endpoint" \
    '{
      version: 1,
      profile_id: $profile_id,
      organization_id: "lattice-development",
      issued_at: $issued_at,
      expires_at: $expires_at,
      max_stale_seconds: 86400,
      enrollment_url: "lnp-development",
      enrollment_token: $token,
      signing_key_id: "pending",
      control_plane_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      tls_root_pem: "pending",
      client_spki_sha256: ("00" * 32),
      require_agent_lease: false,
      agent_lease_public_keys: {},
      revoked_at: null,
      interface: { ipv4: "10.89.0.2/30", ipv6: "fd00:89::2/126", mtu: 1280 },
      gateways: [{ address: $gateway_endpoint, server_name: "gateway.dev.lattice", spki_sha256: $gateway_pin }],
      routes: ["10.89.0.1/32", "fd00:89::1/128"],
      services: [{
        fqdn: "echo.lattice",
        addresses: ["10.89.0.1", "fd00:89::1"],
        gateway: $gateway_endpoint,
        tls_spki_sha256: $gateway_pin,
        policy_version: 1,
        http_policy: null
      }],
      policy: {
        version: 1,
        mode: "split",
        allow: [
          { destination: "10.89.0.1/32", protocols: ["tcp"], ports: [{start: 8080, end: 8080}], service: "echo.lattice" },
          { destination: "10.89.0.1/32", protocols: ["udp"], ports: [{start: 9090, end: 9090}], service: "echo.lattice" },
          { destination: "10.89.0.1/32", protocols: ["icmp"], ports: [], service: "echo.lattice" },
          { destination: "fd00:89::1/128", protocols: ["tcp"], ports: [{start: 8081, end: 8081}], service: "echo.lattice" },
          { destination: "fd00:89::1/128", protocols: ["icmpv6"], ports: [], service: "echo.lattice" }
        ],
        deny: []
      }
    }' >"$state_dir/profile-template.json"

  "$netctl" enrollment-offer-issue \
    --pki "$state_dir/pki" --template "$state_dir/profile-template.json" \
    --endpoint "$enrollment_endpoint" --server-name enroll.dev.lattice \
    --server-cert "$state_dir/enrollment-chain.pem" --out "$state_dir/profile.offer.json"
  mkdir -p "$state_dir/gateway-profiles"
  touch "$state_dir/.initialized"
fi

chmod 600 "$state_dir"/*-key.pem
control_key=$(tr -d '\n' <"$state_dir/pki/control-public-key.b64")

"$netctl" enrollment-serve \
  --pki "$state_dir/pki" --offer "$state_dir/profile.offer.json" \
  --bind 0.0.0.0:7442 --server-cert "$state_dir/enrollment-chain.pem" \
  --server-key "$state_dir/enrollment-key.pem" &
enrollment_pid=$!

cleanup() {
  kill "${http4_pid:-}" "${http6_pid:-}" "${udp_pid:-}" \
    "${enrollment_pid:-}" "${gateway_pid:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

export LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key"
"$gatewayd" --bind 0.0.0.0:7443 \
  --tls-root "$state_dir/pki/tls-root-cert.pem" \
  --server-cert "$state_dir/gateway-chain.pem" --server-key "$state_dir/gateway-key.pem" \
  --profiles-dir "$state_dir/gateway-profiles" \
  --tun-name lp-gateway0 --tun-ipv4 10.89.0.1/30 --tun-ipv6 fd00:89::1/126 &
gateway_pid=$!

for _ in $(seq 1 100); do
  ip link show lp-gateway0 >/dev/null 2>&1 && break
  kill -0 "$gateway_pid" 2>/dev/null || { echo "Gateway did not start" >&2; exit 1; }
  sleep 0.1
done
ip link show lp-gateway0 >/dev/null

python3 -m http.server 8080 --bind 10.89.0.1 >/dev/null 2>&1 &
http4_pid=$!
python3 -m http.server 8081 --bind fd00:89::1 >/dev/null 2>&1 &
http6_pid=$!
python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.89.0.1",9090));
while True:
 data,address=s.recvfrom(2048); s.sendto(data,address)' >/dev/null 2>&1 &
udp_pid=$!

wait "$gateway_pid"
