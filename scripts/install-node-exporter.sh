#!/bin/bash
# Install prometheus node_exporter as systemd service, bound to 127.0.0.1:9100.
# Run as root.
set -euo pipefail

NODE_EXPORTER_VERSION="1.8.2"
ARCH="linux-amd64"
URL="https://github.com/prometheus/node_exporter/releases/download/v${NODE_EXPORTER_VERSION}/node_exporter-${NODE_EXPORTER_VERSION}.${ARCH}.tar.gz"
INSTALL_DIR="/usr/local/bin"
TEXTFILE_DIR="/var/lib/node_exporter/textfile_collector"

echo "==> Creating user and directories"
id -u node_exporter >/dev/null 2>&1 || useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/node_exporter node_exporter
install -d -o node_exporter -g node_exporter -m 755 /var/lib/node_exporter
install -d -o node_exporter -g node_exporter -m 755 "$TEXTFILE_DIR"

echo "==> Downloading node_exporter ${NODE_EXPORTER_VERSION}"
cd /tmp
rm -rf node_exporter-*
curl -sSL -o ne.tar.gz "$URL"
tar -xzf ne.tar.gz
install -o root -g root -m 755 "node_exporter-${NODE_EXPORTER_VERSION}.${ARCH}/node_exporter" "${INSTALL_DIR}/node_exporter"
rm -rf ne.tar.gz "node_exporter-${NODE_EXPORTER_VERSION}.${ARCH}"

echo "==> Creating systemd unit"
cat > /etc/systemd/system/node_exporter.service <<'EOF'
[Unit]
Description=Prometheus Node Exporter
After=network-online.target
Wants=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
  --web.listen-address=127.0.0.1:9100 \
  --collector.textfile.directory=/var/lib/node_exporter/textfile_collector \
  --collector.systemd \
  --collector.systemd.unit-include=(docker|fail2ban|chrony|systemd-timesyncd|ssh|node_exporter|fail2ban-exporter|top-exporter)\.(service|timer) \
  --collector.processes \
  --no-collector.wifi \
  --no-collector.hwmon \
  --no-collector.nvme
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/node_exporter

[Install]
WantedBy=multi-user.target
EOF

echo "==> Enabling + starting"
systemctl daemon-reload
systemctl enable --now node_exporter.service
sleep 2

echo "==> Verifying"
systemctl is-active node_exporter.service
ss -tlnp | grep 9100 || true
curl -s http://127.0.0.1:9100/metrics | head -5
echo
echo "✓ node_exporter installed and listening on 127.0.0.1:9100"
