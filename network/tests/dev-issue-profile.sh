#!/usr/bin/env bash
# Emits an additional one-time development offer. It must run inside the
# development Gateway container, where the private control-plane key is held
# in its mounted state volume. The offer itself is intentionally not printed.
set -euo pipefail

state_dir=${LATTICE_DEV_STATE_DIR:-/lattice}
bin_dir=${LATTICE_BIN_DIR:-/workspace/network/target/debug}
enrollment_endpoint=${LATTICE_ENROLL_ENDPOINT:?LATTICE_ENROLL_ENDPOINT is required}

netctl="$bin_dir/lattice-netctl"
profile_id=$(python3 -c 'import uuid; print(uuid.uuid4())')
token=$("$netctl" enrollment-token-issue --pki "$state_dir/pki")
issued_at=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
expires_at=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=30)).replace(microsecond=0).isoformat().replace("+00:00", "Z"))')
template="$state_dir/profile-$profile_id.template.json"
offer="$state_dir/profile-$profile_id.offer.json"

jq --arg profile_id "$profile_id" --arg token "$token" \
  --arg issued_at "$issued_at" --arg expires_at "$expires_at" \
  '.profile_id = $profile_id | .enrollment_token = $token | .issued_at = $issued_at | .expires_at = $expires_at' \
  "$state_dir/profile-template.json" >"$template"

"$netctl" enrollment-offer-issue \
  --pki "$state_dir/pki" --template "$template" \
  --endpoint "$enrollment_endpoint" --server-name enroll.dev.lattice \
  --server-cert "$state_dir/enrollment-chain.pem" --out "$offer" >/dev/null

printf '%s\n' "$profile_id"
