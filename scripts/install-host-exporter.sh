#!/bin/bash
# Installs fail2ban-exporter as a systemd timer running every 20s.
# Run as root on the host.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

install -m 755 "${SCRIPT_DIR}/fail2ban-exporter.sh" /usr/local/bin/fail2ban-exporter.sh

cat > /etc/systemd/system/fail2ban-exporter.service <<'EOF'
[Unit]
Description=Export fail2ban status to JSON for status page
After=fail2ban.service
Wants=fail2ban.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fail2ban-exporter.sh
Nice=10
EOF

cat > /etc/systemd/system/fail2ban-exporter.timer <<'EOF'
[Unit]
Description=Run fail2ban-exporter every 20 seconds

[Timer]
OnBootSec=30s
OnUnitActiveSec=20s
AccuracySec=1s
Unit=fail2ban-exporter.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now fail2ban-exporter.timer

# Run once immediately
systemctl start fail2ban-exporter.service
sleep 1
ls -la /var/lib/status/ || true
cat /var/lib/status/fail2ban.json || true
echo
echo "Installed. Timer status:"
systemctl list-timers fail2ban-exporter.timer --no-pager
