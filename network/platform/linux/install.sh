#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "lattice Linux network installation requires root" >&2
  exit 1
fi

bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_prefix=${LATTICE_INSTALL_PREFIX:-/usr/local}

getent group lattice >/dev/null 2>&1 || groupadd --system lattice
getent passwd lattice >/dev/null 2>&1 || useradd --system --gid lattice --home-dir /var/lib/lattice --shell /usr/sbin/nologin lattice
install -d -m 0750 -o lattice -g lattice /var/lib/lattice /var/lib/lattice/profiles /var/lib/lattice/gateway-profiles /run/lattice
install -d -m 0755 /etc/lattice/profiles /etc/lattice/pki "$install_prefix/bin" /usr/local/share/applications

for binary in lattice lattice-netd lattice-gatewayd lattice-resolver lattice-netctl; do
  install -m 0755 "$bundle_root/bin/$binary" "$install_prefix/bin/$binary"
done
install -m 0644 "$bundle_root/lib/systemd/system/lattice-netd@.service" /etc/systemd/system/lattice-netd@.service
install -m 0644 "$bundle_root/lib/systemd/system/lattice-resolver.service" /etc/systemd/system/lattice-resolver.service
install -m 0644 "$bundle_root/lib/systemd/system/lattice-gatewayd.service" /etc/systemd/system/lattice-gatewayd.service
install -m 0644 "$bundle_root/share/applications/lattice-uri.desktop" /usr/local/share/applications/lattice-uri.desktop
install -m 0644 "$bundle_root/lib/sysctl.d/90-lattice.conf" /etc/sysctl.d/90-lattice.conf
sysctl -p /etc/sysctl.d/90-lattice.conf >/dev/null
if [ -n "${LATTICE_SERVICE_ROOT_CERT:-}" ]; then
  test -f "$LATTICE_SERVICE_ROOT_CERT"
  openssl x509 -in "$LATTICE_SERVICE_ROOT_CERT" -noout >/dev/null
  install -m 0644 "$LATTICE_SERVICE_ROOT_CERT" /usr/local/share/ca-certificates/lattice-service-root.crt
  command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates
fi
systemctl daemon-reload
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database /usr/local/share/applications || true
echo "Lattice network binaries and systemd units installed. Enroll a signed profile before enabling a unit."
