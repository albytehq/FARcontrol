#!/usr/bin/env bash
# Build a .deb package for FARcontrol (single binary + systemd unit + docs).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(grep '^version' "$ROOT/Cargo.toml" | head -1 | cut -d'"' -f2)"
PKG="/tmp/frtrol-deb/frtrol_${VER}_amd64"
rm -rf /tmp/frtrol-deb && mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/usr/share/doc/frtrol"
cp "$ROOT/target/release/frtrol" "$PKG/usr/bin/frtrol"
cp "$ROOT/README.md" "$PKG/usr/share/doc/frtrol/"
cat > "$PKG/lib/systemd/system/frtrol.service" <<'UNIT'
[Unit]
Description=FARcontrol agent control plane
After=network.target

[Service]
Type=simple
User=%i
ExecStart=/usr/bin/frtrol start
Restart=always
RestartSec=2
# hardening (§77 spirit): the daemon needs almost nothing
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%h/.farcontrol

[Install]
WantedBy=multi-user.target
UNIT
cat > "$PKG/DEBIAN/control" <<CTRL
Package: frtrol
Version: ${VER}
Section: admin
Priority: optional
Architecture: amd64
Depends: libc6
Maintainer: FARcontrol project
Description: approval-gated control plane for external AI agents
 An AI agent can operate your computer without ever holding permanent
 access: every capability is born from explicit owner approval and dies
 automatically (5h-72h). Authentication is not authorization.
CTRL
mkdir -p "$PKG/usr/share/doc/frtrol/examples"
cp "$ROOT/config-check" /dev/null 2>/dev/null || true
printf '[policy]\n# session_max_hours = 24\n# exec_max_secs = 120\n# extra_denylist = ["dangerous-cmd"]\n' > "$PKG/usr/share/doc/frtrol/examples/config.toml"
chmod 755 "$PKG/usr/bin/frtrol"
dpkg-deb --build --root-owner-group "$PKG" "/tmp/frtrol-deb/frtrol_${VER}_amd64.deb"
echo "built: /tmp/frtrol-deb/frtrol_${VER}_amd64.deb"
