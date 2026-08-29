#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
bin_dir=${LATTICE_E2E_BIN_DIR:-$repo_root/network/target/debug}
test_root=$(mktemp -d /tmp/lattice-enrollment-e2e.XXXXXX)

cleanup() {
  [ -n "${server_pid:-}" ] && kill "$server_pid" 2>/dev/null || true
  rm -rf "$test_root"
}
trap cleanup EXIT INT TERM

netctl="$bin_dir/lattice-netctl"
netd="$bin_dir/lattice-netd"
for executable in "$netctl" "$netd"; do
  [ -x "$executable" ] || { echo "missing $executable" >&2; exit 1; }
done

"$netctl" pki-init --out "$test_root/pki" --organization lattice-enrollment-e2e
"$netctl" certificate-csr --name enrollment.test --kind server --key-out "$test_root/enrollment-key.pem" --csr-out "$test_root/enrollment.csr"
"$netctl" certificate-sign --pki "$test_root/pki" --csr "$test_root/enrollment.csr" --kind server --cert-out "$test_root/enrollment-chain.pem"

token=$("$netctl" enrollment-token-issue --pki "$test_root/pki")
profile_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
issued_at=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
expires_at=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
gateway_pin=$(openssl x509 -in "$test_root/enrollment-chain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | cut -d' ' -f1)

jq -n \
  --arg profile_id "$profile_id" \
  --arg issued_at "$issued_at" \
  --arg expires_at "$expires_at" \
  --arg token "$token" \
  --arg gateway_pin "$gateway_pin" \
  '{
    version: 1,
    profile_id: $profile_id,
    organization_id: "lattice-enrollment-e2e",
    issued_at: $issued_at,
    expires_at: $expires_at,
    max_stale_seconds: 86400,
    enrollment_url: "quic://127.0.0.1:7442",
    enrollment_token: $token,
    signing_key_id: "pending",
    control_plane_key_b64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    tls_root_pem: "pending",
    client_spki_sha256: "pending",
    require_agent_lease: false,
    agent_lease_public_keys: {},
    revoked_at: null,
    interface: { ipv4: "10.89.0.2/30", ipv6: null, mtu: 1280 },
    gateways: [{ address: "127.0.0.1:7443", server_name: "enrollment.test", spki_sha256: $gateway_pin }],
    routes: [],
    services: [],
    policy: { version: 1, mode: "split", allow: [], deny: [] }
  }' >"$test_root/profile-template.json"

"$netctl" enrollment-offer-issue \
  --pki "$test_root/pki" --template "$test_root/profile-template.json" \
  --endpoint 127.0.0.1:7442 --server-name enrollment.test \
  --server-cert "$test_root/enrollment-chain.pem" --out "$test_root/offer.json"

"$netctl" enrollment-serve \
  --pki "$test_root/pki" --offer "$test_root/offer.json" --bind 127.0.0.1:7442 \
  --server-cert "$test_root/enrollment-chain.pem" --server-key "$test_root/enrollment-key.pem" &
server_pid=$!
sleep 0.2

control_key=$(tr -d '\n' <"$test_root/pki/control-public-key.b64")
LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$netd" profile-enroll \
  "$test_root/offer.json" --state-dir "$test_root/client-state"

profile_dir="$test_root/client-state/$profile_id"
test -f "$profile_dir/client-key.pem"
if key_mode=$(stat -c '%a' "$profile_dir/client-key.pem" 2>/dev/null); then
  : # GNU stat (Linux)
else
  key_mode=$(stat -f '%Lp' "$profile_dir/client-key.pem") # BSD stat (macOS)
fi
test "$key_mode" = 600
LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$netd" check-profile --profile "$profile_dir/bundle.json"
LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$netd" profile-status \
  --profile-id "$profile_id" --state-dir "$test_root/client-state" \
  | grep -F "$profile_dir/bundle.json" >/dev/null
test ! -e "$test_root/client-state/.$profile_id.enrolling"

if LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$netd" profile-enroll \
  "$test_root/offer.json" --state-dir "$test_root/second-client-state"; then
  echo "enrollment token was reused" >&2
  exit 1
fi

echo "enrollment-e2e: local key generation, pinned CSR enrollment and token single-use passed"
