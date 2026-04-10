#!/bin/bash
# install-telegram-alerter.sh — installs telegram-alerter as a systemd service.
# Run as root. Set BOT_TOKEN and CHAT_ID before running.
# Usage: BOT_TOKEN=xxx CHAT_ID=yyy bash install-telegram-alerter.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="${SCRIPT_DIR}/telegram-alerter.py"
BOT_TOKEN="${BOT_TOKEN:-}"
CHAT_ID="${CHAT_ID:-}"

if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
  echo "ERROR: BOT_TOKEN and CHAT_ID environment variables must be set"
  echo "Usage: BOT_TOKEN=xxx CHAT_ID=yyy bash $0"
  exit 1
fi

if [ ! -f "$SRC" ]; then
  echo "ERROR: telegram-alerter.py not found in ${SCRIPT_DIR}"
  exit 1
fi

install -m 755 "$SRC" /usr/local/bin/telegram-alerter.py

cat > /etc/systemd/system/telegram-alerter.service <<EOF
[Unit]
Description=Telegram alerter for server status page
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/bin/telegram-alerter.py
Restart=on-failure
RestartSec=15

Environment=TELEGRAM_BOT_TOKEN=${BOT_TOKEN}
Environment=TELEGRAM_CHAT_ID=${CHAT_ID}
Environment=STATUS_API_URL=http://127.0.0.1:8001/api/status
Environment=ALERT_COOLDOWN_MIN=15

# Mild hardening (needs network + localhost access)
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now telegram-alerter.service
sleep 3

echo "==> Status"
systemctl is-active telegram-alerter.service
journalctl -u telegram-alerter.service -n 20 --no-pager
echo "✓ telegram-alerter installed"
