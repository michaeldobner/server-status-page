#!/bin/bash
# Installs top-exporter as a systemd timer running every 10s.
# Run as root.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${SCRIPT_DIR}/top-exporter.sh"
if [ ! -f "$SRC" ]; then
  echo "ERROR: top-exporter.sh not found in ${SCRIPT_DIR}"
  exit 1
fi

install -m 755 "$SRC" /usr/local/bin/top-exporter.sh

cat > /etc/systemd/system/top-exporter.service <<'EOF'
[Unit]
Description=Export top processes to JSON for status page

[Service]
Type=oneshot
ExecStart=/usr/local/bin/top-exporter.sh
Nice=15
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/top-exporter.timer <<'EOF'
[Unit]
Description=Run top-exporter every 10 seconds

[Timer]
OnBootSec=15s
OnUnitActiveSec=10s
AccuracySec=1s
Unit=top-exporter.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now top-exporter.timer
systemctl start top-exporter.service
sleep 1

echo "==> Verifying"
ls -la /var/lib/status/top.json
head -c 500 /var/lib/status/top.json
echo
echo "✓ top-exporter installed"
