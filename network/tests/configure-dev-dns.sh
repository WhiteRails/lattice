#!/usr/bin/env bash
# Configure split DNS inside the disposable LNP development client container.
# Private `.lattice`, `.coral` and `.reef` names are sent only to
# lattice-resolver; ordinary names retain the container's pre-existing
# upstream resolvers. This is a Docker-only analogue of Linux
# systemd-resolved's private routing domains.
set -euo pipefail

client=${LATTICE_DEV_CLIENT:-lattice-lnp-e2e}

docker exec "$client" sh -ceu '
  if ! command -v dnsmasq >/dev/null; then
    command -v apt-get >/dev/null
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends dnsmasq
  fi

  test -s /etc/resolv.conf
  if [ ! -s /etc/dnsmasq.d/lattice-upstreams.conf ]; then
    awk "
      \$1 == \"nameserver\" {
        if (\$2 !~ /^[0-9A-Fa-f:.]+$/) bad = 1
        else { print \"server=\" \$2; count++ }
      }
      END { if (bad || count == 0) exit 1 }
    " /etc/resolv.conf >/etc/dnsmasq.d/lattice-upstreams.conf
  fi
  test -s /etc/dnsmasq.d/lattice-upstreams.conf

  printf "%s\\n" \
    "no-resolv" \
    "domain-needed" \
    "bogus-priv" \
    "listen-address=127.0.0.2" \
    "bind-interfaces" \
    "server=/lattice/127.0.0.1#5353" \
    "server=/coral/127.0.0.1#5353" \
    "server=/reef/127.0.0.1#5353" \
    "conf-file=/etc/dnsmasq.d/lattice-upstreams.conf" \
    >/etc/dnsmasq.d/lattice.conf

  pkill -x dnsmasq 2>/dev/null || true
  dnsmasq --conf-file=/etc/dnsmasq.d/lattice.conf --keep-in-foreground \
    >/tmp/lattice-dnsmasq.log 2>&1 &
  for _ in $(seq 1 20); do
    ss -lun | grep -Fq "127.0.0.2:53" && break
    sleep 0.1
  done
  ss -lun | grep -Fq "127.0.0.2:53"
  printf "nameserver 127.0.0.2\\n" >/etc/resolv.conf
'

echo "LNP development split DNS enabled in $client"
