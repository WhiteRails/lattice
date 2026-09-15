#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ] || [ ! -c /dev/net/tun ]; then
  echo "linux-e2e requires root and /dev/net/tun" >&2
  exit 77
fi

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
bin_dir=${LATTICE_E2E_BIN_DIR:-$repo_root/network/target/debug}
mode=${LATTICE_E2E_MODE:-full}
case "$mode" in full|split) ;; *) echo "LATTICE_E2E_MODE must be full or split" >&2; exit 2;; esac
test_root=$(mktemp -d /tmp/lattice-linux-e2e.XXXXXX)
gateway_ns="lattice-e2e-gw-$$"
client_ns="lattice-e2e-client-$$"

cleanup() {
  for pid in ${doh_pid:-} ${underlay4_pid:-} ${underlay6_pid:-} ${unsolicited_pid:-} ${client_pid:-} ${resolver_pid:-} ${http4_pid:-} ${http6_pid:-} ${udp_pid:-} ${gateway_pid:-}; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
  ip netns delete "$client_ns" 2>/dev/null || true
  ip netns delete "$gateway_ns" 2>/dev/null || true
  rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

netctl="$bin_dir/lattice-netctl"
netd="$bin_dir/lattice-netd"
gatewayd="$bin_dir/lattice-gatewayd"
resolver="$bin_dir/lattice-resolver"
for executable in "$netctl" "$netd" "$gatewayd" "$resolver"; do
  [ -x "$executable" ] || { echo "missing $executable" >&2; exit 1; }
done

"$netctl" pki-init --out "$test_root/pki" --organization lattice-e2e
"$netctl" certificate-csr --name gateway.test --kind server --key-out "$test_root/gateway-key.pem" --csr-out "$test_root/gateway.csr"
"$netctl" certificate-sign --pki "$test_root/pki" --csr "$test_root/gateway.csr" --kind server --cert-out "$test_root/gateway-chain.pem"
"$netctl" certificate-csr --name client.test --kind client --key-out "$test_root/client-key.pem" --csr-out "$test_root/client.csr"
"$netctl" certificate-sign --pki "$test_root/pki" --csr "$test_root/client.csr" --kind client --cert-out "$test_root/client-chain.pem"

token=$("$netctl" enrollment-token-issue --pki "$test_root/pki")
profile_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
control_key=$(tr -d '\n' <"$test_root/pki/control-public-key.b64")
gateway_pin=$(openssl x509 -in "$test_root/gateway-chain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
client_pin=$(openssl x509 -in "$test_root/client-chain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)
issued_at=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
expires_at=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')

jq -n \
  --arg profile_id "$profile_id" \
  --arg issued_at "$issued_at" \
  --arg expires_at "$expires_at" \
  --arg token "$token" \
  --arg gateway_pin "$gateway_pin" \
  --arg mode "$mode" \
  --arg client_pin "$client_pin" \
  '{
    version: 1,
    profile_id: $profile_id,
    organization_id: "lattice-e2e",
    issued_at: $issued_at,
    expires_at: $expires_at,
    max_stale_seconds: 86400,
    enrollment_url: "offline://linux-e2e",
    enrollment_token: $token,
    signing_key_id: "pending",
    control_plane_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    tls_root_pem: "pending",
    client_spki_sha256: $client_pin,
    require_agent_lease: false,
    agent_lease_public_keys: {},
    revoked_at: null,
    interface: { ipv4: "10.88.0.2/30", ipv6: "fd00:88::2/126", mtu: 1280 },
    gateways: [{ address: "192.0.2.1:7443", server_name: "gateway.test", spki_sha256: $gateway_pin }],
    routes: ["10.88.0.1/32", "fd00:88::1/128"],
    services: [{
      fqdn: "echo.lattice",
      addresses: ["10.88.0.1", "fd00:88::1"],
      gateway: "192.0.2.1:7443",
      tls_spki_sha256: $gateway_pin,
      policy_version: 1,
      http_policy: null
    }],
    policy: {
      version: 1,
      mode: $mode,
      allow: [
        { destination: "10.88.0.1/32", protocols: ["tcp"], ports: [{start: 8080, end: 8080}], service: "echo.lattice" },
        { destination: "10.88.0.1/32", protocols: ["udp"], ports: [{start: 9090, end: 9090}], service: "echo.lattice" },
        { destination: "10.88.0.1/32", protocols: ["icmp"], ports: [], service: "echo.lattice" },
        { destination: "fd00:88::1/128", protocols: ["tcp"], ports: [{start: 8081, end: 8081}], service: "echo.lattice" },
        { destination: "fd00:88::1/128", protocols: ["icmpv6"], ports: [], service: "echo.lattice" }
      ],
      deny: []
    }
  }' >"$test_root/profile-template.json"

"$netctl" profile-sign --pki "$test_root/pki" --template "$test_root/profile-template.json" --client-cert "$test_root/client-chain.pem" --out "$test_root/profile.bundle.json"
mkdir "$test_root/profiles"
cp "$test_root/profile.bundle.json" "$test_root/profiles/$profile_id.json"

# The per-agent entrypoint must never fall back to executing a requested
# command when a prerequisite for verified namespace enforcement is missing.
agent_marker="$test_root/agent-command-ran"
if LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$netd" run-agent \
  --profile-id "$profile_id" --state-dir "$test_root/not-installed" \
  --namespace-id lattice-e2e-agent --agent-lease "$test_root/missing-lease.json" \
  -- touch "$agent_marker"; then
  echo "per-agent mode executed despite missing installed enforcement state" >&2
  exit 1
fi
test ! -e "$agent_marker"

ip netns add "$gateway_ns"
ip netns add "$client_ns"
ip link add e2egw type veth peer name e2eclient
ip link set e2egw netns "$gateway_ns"
ip link set e2eclient netns "$client_ns"
ip -n "$gateway_ns" link set lo up
ip -n "$client_ns" link set lo up
ip -n "$gateway_ns" address add 192.0.2.1/30 dev e2egw
ip -n "$client_ns" address add 192.0.2.2/30 dev e2eclient
ip -n "$gateway_ns" -6 address add fd00:192::1/126 dev e2egw nodad
ip -n "$client_ns" -6 address add fd00:192::2/126 dev e2eclient nodad
ip -n "$gateway_ns" link set e2egw up
ip -n "$client_ns" link set e2eclient up

ip netns exec "$gateway_ns" env LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" \
  "$gatewayd" --bind 192.0.2.1:7443 \
  --tls-root "$test_root/pki/tls-root-cert.pem" \
  --server-cert "$test_root/gateway-chain.pem" \
  --server-key "$test_root/gateway-key.pem" \
  --profiles-dir "$test_root/profiles" \
  --tun-name lpgw0 --tun-ipv4 10.88.0.1/30 --tun-ipv6 fd00:88::1/126 &
gateway_pid=$!

for _ in $(seq 1 100); do
  ip -n "$gateway_ns" link show lpgw0 >/dev/null 2>&1 && break
  kill -0 "$gateway_pid" 2>/dev/null || { echo "gateway exited" >&2; exit 1; }
  sleep 0.1
done
ip -n "$gateway_ns" link show lpgw0 >/dev/null

ip netns exec "$gateway_ns" python3 -m http.server 8080 --bind 10.88.0.1 >/dev/null 2>&1 &
http4_pid=$!
ip netns exec "$gateway_ns" python3 -m http.server 8081 --bind fd00:88::1 >/dev/null 2>&1 &
http6_pid=$!
ip netns exec "$gateway_ns" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.88.0.1",9090));
while True:
 d,a=s.recvfrom(2048); s.sendto(d,a)' &
udp_pid=$!
sleep 0.2

# A denied bypass is meaningful only if the destination was reachable first.
ip netns exec "$gateway_ns" python3 -m http.server 9999 --bind 192.0.2.1 >/dev/null 2>&1 &
underlay4_pid=$!
ip netns exec "$gateway_ns" python3 -m http.server 9999 --bind fd00:192::1 >/dev/null 2>&1 &
underlay6_pid=$!
# An HTTPS DNS endpoint reachable before policy activation. Its DNS response
# is NXDOMAIN; the assertion below is whether HTTPS can bypass the tunnel.
ip netns exec "$gateway_ns" python3 - "$test_root/gateway-chain.pem" "$test_root/gateway-key.pem" <<'DOH' &
import base64, http.server, ssl, sys, urllib.parse
class DNS(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        encoded = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)['dns'][0]
        query = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
        response = query[:2] + b'\x81\x83' + query[4:6] + b'\x00' * 6 + query[12:]
        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.end_headers()
        self.wfile.write(response)
    def log_message(self, *args): pass
server = http.server.HTTPServer(('192.0.2.1', 9443), DNS)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
DOH
doh_pid=$!
doh_url='https://gateway.test:9443/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE'
sleep 0.3
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' \
  --cacert "$test_root/pki/tls-root-cert.pem" --resolve gateway.test:9443:192.0.2.1 "$doh_url" > "$test_root/doh.response"
python3 - "$test_root/doh.response" <<'CHECK_DOH'
import sys
r = open(sys.argv[1], 'rb').read()
assert len(r) >= 12 and r[3] & 15 == 3
CHECK_DOH
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' http://192.0.2.1:9999/ >/dev/null
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' 'http://[fd00:192::1]:9999/' >/dev/null

start_client() {
  ip netns exec "$client_ns" env LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" \
    "$netd" connect --profile "$test_root/profile.bundle.json" \
    --client-cert "$test_root/client-chain.pem" --client-key "$test_root/client-key.pem" \
    --tun-name lpclient0 --external-dns "$@" &
  client_pid=$!
}
wait_client_closed() {
  local limit=$1
  for _ in $(seq 1 "$limit"); do
    if ! kill -0 "$client_pid" 2>/dev/null; then
      wait "$client_pid" || true
      unset client_pid
      return
    fi
    sleep 1
  done
  echo 'client retained an expired/revoked session' >&2
  exit 1
}
start_client

ip netns exec "$client_ns" env LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" \
  "$resolver" --bind 127.0.0.1:5353 --profile "$test_root/profile.bundle.json" &
resolver_pid=$!

for _ in $(seq 1 100); do
  ip -n "$client_ns" link show lpclient0 >/dev/null 2>&1 && break
  kill -0 "$client_pid" 2>/dev/null || { echo "client exited" >&2; exit 1; }
  sleep 0.1
done
ip -n "$client_ns" link show lpclient0 >/dev/null

ip netns exec "$client_ns" ping -c 1 -W 2 10.88.0.1 >/dev/null
ip netns exec "$client_ns" ping -6 -c 1 -W 2 fd00:88::1 >/dev/null
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' http://10.88.0.1:8080/ >/dev/null
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' 'http://[fd00:88::1]:8081/' >/dev/null
ip netns exec "$client_ns" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"lnp-udp",("10.88.0.1",9090)); assert s.recv(32)==b"lnp-udp"'
ip netns exec "$client_ns" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.88.0.2",40001)); s.settimeout(2)
try:
 s.recv(32); raise SystemExit("unsolicited gateway packet reached client")
except socket.timeout:
 pass' &
unsolicited_pid=$!
sleep 0.1
ip netns exec "$gateway_ns" python3 -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.88.0.1",9091)); s.sendto(b"unsolicited",("10.88.0.2",40001))'
wait "$unsolicited_pid"
unset unsolicited_pid
ip netns exec "$client_ns" dig +short @127.0.0.1 -p 5353 echo.lattice A | grep -Fx 10.88.0.1 >/dev/null
ip netns exec "$client_ns" dig +comments @127.0.0.1 -p 5353 public.example A | grep -F 'status: REFUSED' >/dev/null
ip netns exec "$client_ns" dig +comments @127.0.0.1 -p 5353 missing.lattice A | grep -F 'status: NXDOMAIN' >/dev/null

ip netns exec "$client_ns" ip route get 10.88.0.1 | grep -F "dev lpclient0" >/dev/null
ip netns exec "$client_ns" ip route get 192.0.2.1 | grep -F "dev e2eclient" >/dev/null
if [ "$mode" = full ]; then
  if ip netns exec "$client_ns" curl --fail --max-time 2 --noproxy '*' \
    --cacert "$test_root/pki/tls-root-cert.pem" --resolve gateway.test:9443:192.0.2.1 "$doh_url" >/dev/null 2>&1; then
    echo 'full-tunnel kill switch allowed an external DoH endpoint' >&2; exit 1
  fi
  if ip netns exec "$client_ns" curl --max-time 2 --noproxy '*' http://192.0.2.1:9999/ >/dev/null 2>&1; then
    echo "full-tunnel kill switch allowed an underlay bypass" >&2
    exit 1
  fi
  if ip netns exec "$client_ns" curl --max-time 2 --noproxy '*' 'http://[fd00:192::1]:9999/' >/dev/null 2>&1; then
    echo 'full-tunnel kill switch allowed an IPv6 underlay bypass' >&2; exit 1
  fi
  if ip netns exec "$client_ns" curl --max-time 2 --noproxy '' --proxy http://192.0.2.1:9999 http://example.invalid/ >/dev/null 2>&1; then
    echo 'full-tunnel kill switch allowed an underlay HTTP proxy' >&2; exit 1
  fi
fi

# Bounded concurrency exercises real forwarding while collecting process RSS.
ip netns exec "$client_ns" python3 - <<'LOAD'
import concurrent.futures, urllib.request
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def request(_):
    with opener.open('http://10.88.0.1:8080/', timeout=5) as r:
        assert r.status == 200
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(request, range(64)))
print('load smoke: 64 requests, concurrency 8, no failed responses')
LOAD
ps -o pid,rss,comm -p "$gateway_pid,$client_pid"

"$netctl" profile-revoke --pki "$test_root/pki" --profile "$test_root/profile.bundle.json" --out "$test_root/profile.revoked.json"
mv "$test_root/profile.revoked.json" "$test_root/profiles/$profile_id.json"
wait_client_closed 40

# Issue a fresh profile that expires without any control-plane update.
# A live QUIC session must close even while its peer remains reachable.
jq --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg token "$("$netctl" enrollment-token-issue --pki "$test_root/pki")" \
  '.issued_at=$now | .enrollment_token=$token | .max_stale_seconds=12' \
  "$test_root/profile-template.json" > "$test_root/stale-template.json"
"$netctl" profile-sign --pki "$test_root/pki" --template "$test_root/stale-template.json" \
  --client-cert "$test_root/client-chain.pem" --out "$test_root/stale.bundle.json"
cp "$test_root/stale.bundle.json" "$test_root/profile.bundle.json"
cp "$test_root/stale.bundle.json" "$test_root/profiles/$profile_id.json"
start_client
sleep 1
kill -0 "$client_pid"
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' http://10.88.0.1:8080/ >/dev/null
wait_client_closed 15

# Sign an agent lease with a shorter deadline than its profile.
openssl genpkey -algorithm ED25519 -out "$test_root/agent.pem"
agent_public=$(openssl pkey -in "$test_root/agent.pem" -pubout -outform DER | tail -c 32 | openssl base64 -A)
jq --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg key "$agent_public" \
  --arg token "$("$netctl" enrollment-token-issue --pki "$test_root/pki")" \
  '.issued_at=$now | .enrollment_token=$token | .require_agent_lease=true | .agent_lease_public_keys={"test-agent":$key}' \
  "$test_root/profile-template.json" > "$test_root/agent-template.json"
"$netctl" profile-sign --pki "$test_root/pki" --template "$test_root/agent-template.json" \
  --client-cert "$test_root/client-chain.pem" --out "$test_root/agent.bundle.json"
cp "$test_root/agent.bundle.json" "$test_root/profile.bundle.json"
cp "$test_root/agent.bundle.json" "$test_root/profiles/$profile_id.json"
python3 - "$profile_id" "$test_root" <<'LEASE'
import base64, datetime, json, os, sys
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
def stamp(t): return t.isoformat().replace('+00:00', 'Z')
payload = dict(agent_id='test-agent', profile_id=sys.argv[1], namespace_id='lattice-e2e-agent',
    issued_at=stamp(now), expires_at=stamp(now+datetime.timedelta(seconds=8)), nonce_b64=base64.b64encode(os.urandom(24)).decode())
with open(sys.argv[2]+'/lease-payload.json','w') as f: json.dump(payload,f,separators=(',',':'))
LEASE
openssl pkeyutl -sign -rawin -inkey "$test_root/agent.pem" -in "$test_root/lease-payload.json" -out "$test_root/lease.sig"
jq -n --slurpfile payload "$test_root/lease-payload.json" --arg sig "$(openssl base64 -A -in "$test_root/lease.sig")" \
  '{payload:$payload[0],signature_b64:$sig}' > "$test_root/lease.json"
start_client --agent-lease "$test_root/lease.json"
sleep 1
kill -0 "$client_pid"
ip netns exec "$client_ns" curl --fail --max-time 3 --noproxy '*' http://10.88.0.1:8080/ >/dev/null
wait_client_closed 10

echo "linux-e2e ($mode): IPv4/IPv6 TCP, UDP, ICMP, private DNS, route enforcement, unsolicited-return filtering, load smoke, revocation, stale control state and agent-lease expiry passed"
