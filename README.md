# Server Status Page

Live server health dashboard for `161.97.132.188` — deployed to
`http://statusmdobner.duckdns.org`.

- **Backend:** FastAPI + WebSockets (Python 3.12)
- **Frontend:** Single HTML file, vanilla JS, dark mode
- **Live updates:** 30s WebSocket push
- **Metrics:** CPU / RAM / Disk / Uptime / Docker containers / Fail2Ban / n8n

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/uvicorn app.main:app --reload --port 8765
```

## Deploy with Docker Compose

```bash
docker compose up -d --build
```

The compose file uses `pid: host` so the container sees the host's `/proc`
(for accurate CPU / uptime), mounts `/var/run/docker.sock:ro` for container
listing, and mounts `/var/lib/status:/host/status:ro` for the fail2ban JSON
written by the host exporter.

## Host-side fail2ban exporter

`fail2ban-client` requires root, so the container cannot read it directly.
Run the exporter as a systemd timer on the host:

```bash
sudo bash scripts/install-host-exporter.sh
```

It writes `/var/lib/status/fail2ban.json` every 20s.

## Environment variables

| Var              | Default                                 | Purpose                       |
|------------------|-----------------------------------------|-------------------------------|
| `N8N_URL`        | `https://n8nmdobner.duckdns.org`        | URL pinged for n8n health     |
| `FAIL2BAN_JSON`  | `/host/status/fail2ban.json`            | Path to host exporter output  |
| `HOST_ROOT`      | `/host/root`                            | Host `/` mounted read-only    |
| `UPDATE_INTERVAL`| `30`                                    | WS push interval in seconds   |
