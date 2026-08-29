#!/usr/bin/env bash
# Run on the Docker host after a development profile has been enrolled.
set -euo pipefail

profile_id=${1:?usage: dev-client-e2e.sh <profile-uuid>}
client=${LATTICE_DEV_CLIENT:-lattice-lnp-e2e}
gateway=${LATTICE_DEV_GATEWAY:-lattice-dev-gateway}
resolver=/opt/lattice/network/target/debug/lattice-resolver

control_key=$(docker exec "$gateway" sh -c "tr -d '\n' </lattice/pki/control-public-key.b64")
if ! docker exec "$client" sh -c "ss -lun | grep -Fq '127.0.0.1:5353'"; then
  docker exec -d -e LATTICE_CONTROL_PUBLIC_KEY_B64="$control_key" "$client" sh -c \
    "exec $resolver --bind 127.0.0.1:5353 --profile /var/lib/lattice/profiles/$profile_id/bundle.json >/var/lib/lattice/profiles/$profile_id/resolver.log 2>&1"
  sleep 1
fi

docker exec -e LATTICE_E2E_PROFILE_ID="$profile_id" "$client" sh -c '
  set -eu
  canonical=$(python3 -c '\''import base64, json, os; profile=json.load(open("/var/lib/lattice/profiles/" + os.environ["LATTICE_E2E_PROFILE_ID"] + "/bundle.json")); pin=next(s["tls_spki_sha256"] for s in profile["payload"]["services"] if s["fqdn"] == "echo.lattice"); print(base64.b32encode(bytes.fromhex(pin)).decode().rstrip("=").lower() + ".coral")'\'')
  ping -c 1 -W 2 10.89.0.1 >/dev/null
  ping -6 -c 1 -W 2 fd00:89::1 >/dev/null
  curl --fail --max-time 3 --noproxy "*" http://10.89.0.1:8080/ >/dev/null
  curl --fail --max-time 3 --noproxy "*" "http://[fd00:89::1]:8081/" >/dev/null
  python3 -c '\''import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"lnp-dev-udp",("10.89.0.1",9090)); assert s.recv(64)==b"lnp-dev-udp"'\''
  dig +short @127.0.0.1 -p 5353 echo.lattice A | grep -Fx 10.89.0.1 >/dev/null
  dig +short @127.0.0.1 -p 5353 "$canonical" A | grep -Fx 10.89.0.1 >/dev/null
  curl --fail --max-time 3 --noproxy "*" --resolve "$canonical:8080:10.89.0.1" "http://$canonical:8080/" >/dev/null
  ! dig +short @127.0.0.1 -p 5353 public.example A | grep -q .
  ip route get 10.89.0.1 | grep -F "dev lpdev0" >/dev/null
  ip -6 route get fd00:89::1 | grep -F "dev lpdev0" >/dev/null
'

echo "LNP development client E2E passed for $profile_id"
