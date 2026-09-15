#!/usr/bin/env bash
set -euo pipefail
# Destructive only to a fresh disposable runner's Lattice installation.
[[ ${LATTICE_INSTALL_E2E:-} == 1 && $(id -u) == 0 ]] || { echo 'requires explicit LATTICE_INSTALL_E2E=1 on a disposable root runner' >&2; exit 77; }
[[ ! -e /etc/lattice/latticed.conf ]] || { echo 'refusing an existing installation' >&2; exit 1; }
bundle=$(cd "$1" && pwd)
cleanup() {
  if [[ -n ${daemon_pid:-} ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi
  if [[ -d /run/systemd/system ]]; then systemctl stop latticed || true; fi
}
trap cleanup EXIT
bash "$bundle/install-network.sh"
test -x /usr/local/bin/latticed
test -x /usr/local/bin/lattice-agent-init
systemd-analyze verify /etc/systemd/system/latticed.service /etc/systemd/system/lattice-netd@.service /etc/systemd/system/lattice-gatewayd.service /etc/systemd/system/lattice-resolver.service
/usr/local/bin/lattice-agent-init >/tmp/lattice-install-public-key.txt
before=$(sha256sum /etc/lattice/latticed.conf /var/lib/lattice/identity/agent.pem /var/lib/lattice/identity/session.token)
bash "$bundle/install-network.sh"
after=$(sha256sum /etc/lattice/latticed.conf /var/lib/lattice/identity/agent.pem /var/lib/lattice/identity/session.token)
[[ "$before" == "$after" ]]
if /usr/local/bin/lattice-agent-init >/dev/null 2>&1; then echo 'initializer replaced an identity' >&2; exit 1; fi
if runuser -u nobody -- cat /var/lib/lattice/identity/session.token >/dev/null 2>&1; then echo 'token readable by agent user' >&2; exit 1; fi
if [[ -d /run/systemd/system ]]; then
  systemctl start latticed
else
  runuser -u lattice -- /usr/local/bin/latticed --config /etc/lattice/latticed.conf &
  daemon_pid=$!
fi
for _ in $(seq 1 50); do [[ -S /run/lattice/latticed.sock ]] && break; sleep 0.1; done
/usr/local/bin/lattice --socket /run/lattice/latticed.sock status
/usr/local/bin/lattice --socket /run/lattice/latticed.sock --session-token-file /var/lib/lattice/identity/session.token sign install-e2e >/dev/null
if /usr/local/bin/lattice --socket /run/lattice/latticed.sock sign unauthorized >/dev/null 2>&1; then echo 'unauthenticated signing succeeded' >&2; exit 1; fi
echo 'install-e2e: units, persistent identity, reinstall, private token, authenticated daemon signing passed'
