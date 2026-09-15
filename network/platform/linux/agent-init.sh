#!/bin/sh
# Explicit local signer provisioning. Never print the private key or token.
set -eu
[ "$(id -u)" -eq 0 ] || { echo 'agent-init requires root' >&2; exit 1; }
identity_dir=/var/lib/lattice/identity
config=/etc/lattice/latticed.conf
test -f "$config" && test ! -L "$config" || { echo 'install Lattice first' >&2; exit 1; }
if grep -Eq '^[[:space:]]*(KeyFile|SessionTokenFile)[[:space:]]' "$config"; then
  echo 'signer is already configured; refusing to replace its identity' >&2
  exit 1
fi
umask 077
mkdir -m 0700 "$identity_dir" || { echo 'identity directory exists; inspect it before provisioning' >&2; exit 1; }
pending_config=$(mktemp /etc/lattice/latticed.conf.XXXXXX)
trap 'rm -f "$pending_config"' EXIT
openssl genpkey -algorithm ED25519 -out "$identity_dir/agent.pem"
openssl rand -hex 32 > "$identity_dir/session.token"
chown -R lattice:lattice "$identity_dir"
chmod 0600 "$identity_dir/agent.pem" "$identity_dir/session.token"
cat "$config" > "$pending_config"
printf '\nKeyFile %s/agent.pem\nSessionTokenFile %s/session.token\n' "$identity_dir" "$identity_dir" >> "$pending_config"
chown root:lattice "$pending_config"
chmod 0640 "$pending_config"
mv "$pending_config" "$config"
echo 'Signer configured. Pin this PUBLIC Ed25519 key in the signed agent profile:'
openssl pkey -in "$identity_dir/agent.pem" -pubout -outform DER | tail -c 32 | openssl base64 -A
printf '\nStart latticed and pass the socket and root-readable token file to lattice run.\n'
