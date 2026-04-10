"""Server Status Page v3 — FastAPI backend.

Data sources (pull-model):
  * Prometheus (PromQL) for host metrics via node_exporter
  * Prometheus (PromQL) for container metrics via cadvisor
  * JSON files on disk for fail2ban history & top processes
  * JSON file on disk for restic backup status
  * Direct HTTP for n8n liveness check

No direct /proc, no docker.sock, no pid:host mounts in this container.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse


# ---------- Configuration ----------
PROMETHEUS_URL = os.environ.get("PROMETHEUS_URL", "http://prometheus:9090")
DOCKER_API_URL = os.environ.get("DOCKER_API_URL", "http://dockerproxy:2375")
N8N_URL = os.environ.get("N8N_URL", "https://n8nmdobner.duckdns.org")
FAIL2BAN_JSON = Path(os.environ.get("FAIL2BAN_JSON", "/host/status/fail2ban.json"))
TOP_JSON = Path(os.environ.get("TOP_JSON", "/host/status/top.json"))
RESTIC_JSON = Path(os.environ.get("RESTIC_JSON", "/host/status/restic.json"))
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", "30"))
STATIC_DIR = Path(__file__).parent / "static"
THRESHOLDS_PATH = Path(__file__).parent / "thresholds.yaml"
SERVICE_MAP_PATH = Path(__file__).parent / "service_map.yaml"

app = FastAPI(
    title="Server Status Page v3",
    docs_url=None,       # disable public /docs (Swagger UI)
    redoc_url=None,      # disable public /redoc
    openapi_url=None,    # disable /openapi.json schema dump
)


# ---------- Thresholds ----------
try:
    THRESHOLDS = yaml.safe_load(THRESHOLDS_PATH.read_text())
except Exception:
    THRESHOLDS = {}


# ---------- Service map ----------
try:
    _smap_raw = yaml.safe_load(SERVICE_MAP_PATH.read_text())
    SERVICE_MAP: dict[str, Any] = _smap_raw.get("services", {})
    HIDDEN_PREFIXES: list[str] = _smap_raw.get("hidden_prefixes", [])
    JAIL_LABELS: dict[str, str] = _smap_raw.get("jail_labels", {})
except Exception:
    SERVICE_MAP = {}
    HIDDEN_PREFIXES = []
    JAIL_LABELS = {}

# Pre-sort service map keys longest-first so more specific prefixes match first
_SERVICE_MAP_KEYS: list[str] = sorted(SERVICE_MAP.keys(), key=len, reverse=True)

# Coolify appends a UUID-like suffix: ≥15 lowercase alphanumeric chars after a dash
_COOLIFY_SUFFIX = re.compile(r"-[a-z0-9]{15,}$")


def _strip_coolify_suffix(name: str) -> str:
    return _COOLIFY_SUFFIX.sub("", name)


def _lookup_service(raw_name: str) -> dict[str, Any] | None:
    """Return service_map entry for a container name, or None if hidden/unknown."""
    base = _strip_coolify_suffix(raw_name)
    for key in _HIDDEN_PREFIXES:
        if base.startswith(key.rstrip("-")):
            return None  # hidden entirely
    for key in _SERVICE_MAP_KEYS:
        if base == key or base.startswith(key):
            return {"prefix": key, **SERVICE_MAP[key]}
    return None


def classify(value: float | None, warn: float, crit: float) -> str:
    if value is None:
        return "off"
    if value >= crit:
        return "crit"
    if value >= warn:
        return "warn"
    return "ok"


# ---------- Prometheus client ----------
class Prom:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=5.0)
        return self._client

    async def query(self, q: str) -> float | None:
        """Return a single scalar from an instant query (first vector value)."""
        try:
            c = await self.client()
            r = await c.get(f"{self.base_url}/api/v1/query", params={"query": q})
            r.raise_for_status()
            data = r.json()
            result = data.get("data", {}).get("result", [])
            if not result:
                return None
            val = result[0].get("value", [None, None])[1]
            return float(val) if val is not None else None
        except Exception:
            return None

    async def query_map(self, q: str, label: str) -> dict[str, float]:
        """Return {label_value: metric_value} for a vector query."""
        try:
            c = await self.client()
            r = await c.get(f"{self.base_url}/api/v1/query", params={"query": q})
            r.raise_for_status()
            data = r.json()
            out: dict[str, float] = {}
            for item in data.get("data", {}).get("result", []):
                key = item.get("metric", {}).get(label, "")
                val = item.get("value", [None, None])[1]
                if val is not None and key:
                    try:
                        out[key] = float(val)
                    except ValueError:
                        pass
            return out
        except Exception:
            return {}


prom = Prom(PROMETHEUS_URL)


# ---------- Collectors ----------

async def collect_host() -> dict[str, Any]:
    """Pull host metrics from Prometheus via PromQL."""
    queries = {
        "cpu_percent": '100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[1m])))',
        "cpu_count": 'count(count(node_cpu_seconds_total) by (cpu))',
        "load1": 'node_load1',
        "load5": 'node_load5',
        "load15": 'node_load15',
        "mem_total": 'node_memory_MemTotal_bytes',
        "mem_avail": 'node_memory_MemAvailable_bytes',
        "swap_total": 'node_memory_SwapTotal_bytes',
        "swap_free": 'node_memory_SwapFree_bytes',
        "uptime": 'node_time_seconds - node_boot_time_seconds',
        # Root filesystem
        "disk_total": 'node_filesystem_size_bytes{mountpoint="/",fstype!="tmpfs"}',
        "disk_avail": 'node_filesystem_avail_bytes{mountpoint="/",fstype!="tmpfs"}',
        # Network (sum across physical interfaces, excluding lo/docker/veth/br)
        "net_rx": 'sum(rate(node_network_receive_bytes_total{device!~"lo|docker.*|veth.*|br-.*|cni.*"}[1m]))',
        "net_tx": 'sum(rate(node_network_transmit_bytes_total{device!~"lo|docker.*|veth.*|br-.*|cni.*"}[1m]))',
    }
    results = await asyncio.gather(*[prom.query(q) for q in queries.values()])
    r = dict(zip(queries.keys(), results))

    mem_total = r.get("mem_total") or 0
    mem_avail = r.get("mem_avail") or 0
    mem_used = max(0, mem_total - mem_avail)
    mem_percent = (mem_used / mem_total * 100) if mem_total else 0

    swap_total = r.get("swap_total") or 0
    swap_free = r.get("swap_free") or 0
    swap_used = max(0, swap_total - swap_free)
    swap_percent = (swap_used / swap_total * 100) if swap_total else 0

    disk_total = r.get("disk_total") or 0
    disk_avail = r.get("disk_avail") or 0
    disk_used = max(0, disk_total - disk_avail)
    disk_percent = (disk_used / disk_total * 100) if disk_total else 0

    return {
        "cpu_percent": round(r.get("cpu_percent") or 0, 1),
        "cpu_count": int(r.get("cpu_count") or 1),
        "load_avg": [
            round(r.get("load1") or 0, 2),
            round(r.get("load5") or 0, 2),
            round(r.get("load15") or 0, 2),
        ],
        "ram": {
            "used_gb": round(mem_used / 1024**3, 1),
            "total_gb": round(mem_total / 1024**3, 1),
            "percent": round(mem_percent, 1),
        },
        "swap": {
            "used_gb": round(swap_used / 1024**3, 1),
            "total_gb": round(swap_total / 1024**3, 1),
            "percent": round(swap_percent, 1),
        },
        "disk": {
            "used_gb": round(disk_used / 1024**3, 1),
            "total_gb": round(disk_total / 1024**3, 1),
            "percent": round(disk_percent, 1),
        },
        "uptime_seconds": int(r.get("uptime") or 0),
        "network": {
            "rx_bytes_s": int(r.get("net_rx") or 0),
            "tx_bytes_s": int(r.get("net_tx") or 0),
        },
    }


async def collect_timesync() -> dict[str, Any]:
    queries = {
        "offset": 'node_timex_offset_seconds',
        "sync": 'node_timex_sync_status',
    }
    results = await asyncio.gather(*[prom.query(q) for q in queries.values()])
    r = dict(zip(queries.keys(), results))
    offset = r.get("offset")
    sync = r.get("sync")
    offset_ms = (offset * 1000) if offset is not None else None
    return {
        "available": offset is not None,
        "synchronized": bool(sync) if sync is not None else None,
        "offset_ms": round(offset_ms, 3) if offset_ms is not None else None,
    }


async def collect_docker() -> dict[str, Any]:
    """Query the Docker API via the docker-socket-proxy sidecar."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{DOCKER_API_URL}/containers/json", params={"all": "false"})
            r.raise_for_status()
            raw = r.json()
    except Exception as e:
        return {"available": False, "error": str(e)}

    now = time.time()
    containers: list[dict[str, Any]] = []
    for c in raw:
        # Docker returns /prefixed names for each alias; take the first without leading slash
        names = c.get("Names", [])
        name = (names[0].lstrip("/") if names else c.get("Id", "")[:12])
        state = c.get("State", "unknown")
        status = c.get("Status", "")
        # Health is embedded in Status like "Up 2 hours (healthy)"
        health = "-"
        if "(healthy)" in status:
            health = "healthy"
        elif "(unhealthy)" in status:
            health = "unhealthy"
        elif "(starting)" in status or "(health: starting)" in status:
            health = "starting"
        # Uptime from Created epoch
        uptime = ""
        created = c.get("Created", 0)
        if created and state == "running":
            delta = int(max(0, now - created))
            d = delta // 86400
            h = (delta % 86400) // 3600
            m = (delta % 3600) // 60
            if d > 0:
                uptime = f"{d}d {h}h"
            elif h > 0:
                uptime = f"{h}h {m}m"
            else:
                uptime = f"{m}m"
        containers.append({
            "name": name,
            "image": c.get("Image", ""),
            "state": state,
            "health": health,
            "uptime": uptime,
            "cpu_percent": 0,  # not available without stats API (which is costly)
            "mem_bytes": 0,
        })
    containers.sort(key=lambda x: x["name"])
    running = sum(1 for c in containers if c["state"] == "running")
    return {
        "available": True,
        "total": len(containers),
        "running": running,
        "containers": containers,
    }


def collect_fail2ban() -> dict[str, Any]:
    if not FAIL2BAN_JSON.exists():
        return {"available": False, "error": f"{FAIL2BAN_JSON} not found"}
    try:
        data = json.loads(FAIL2BAN_JSON.read_text())
        data["available"] = True
        age = time.time() - FAIL2BAN_JSON.stat().st_mtime
        data["age_seconds"] = int(age)
        return data
    except Exception as e:
        return {"available": False, "error": str(e)}


def collect_top() -> dict[str, Any]:
    if not TOP_JSON.exists():
        return {"available": False, "error": f"{TOP_JSON} not found"}
    try:
        data = json.loads(TOP_JSON.read_text())
        data["available"] = True
        age = time.time() - TOP_JSON.stat().st_mtime
        data["age_seconds"] = int(age)
        return data
    except Exception as e:
        return {"available": False, "error": str(e)}


async def collect_n8n() -> dict[str, Any]:
    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=True, follow_redirects=True) as client:
            r = await client.get(N8N_URL)
            latency = int((time.monotonic() - t0) * 1000)
            return {
                "reachable": 200 <= r.status_code < 500,
                "status_code": r.status_code,
                "latency_ms": latency,
                "url": N8N_URL,
            }
    except Exception as e:
        return {
            "reachable": False,
            "error": str(e),
            "latency_ms": int((time.monotonic() - t0) * 1000),
            "url": N8N_URL,
        }


def collect_restic() -> dict[str, Any]:
    if not RESTIC_JSON.exists():
        return {"available": False, "error": f"{RESTIC_JSON} not found"}
    try:
        data = json.loads(RESTIC_JSON.read_text())
        data["available"] = True
        age = time.time() - RESTIC_JSON.stat().st_mtime
        data["file_age_seconds"] = int(age)
        return data
    except Exception as e:
        return {"available": False, "error": str(e)}


def apply_severity(d: dict[str, Any]) -> dict[str, Any]:
    """Compute severity tags for each metric group using thresholds.yaml."""
    t = THRESHOLDS or {}
    host = d.get("host", {})
    host_t = t.get("host", {})
    d["severity"] = {
        "cpu":   classify(host.get("cpu_percent"),
                          host_t.get("cpu_percent", {}).get("warn", 70),
                          host_t.get("cpu_percent", {}).get("crit", 90)),
        "ram":   classify(host.get("ram", {}).get("percent"),
                          host_t.get("ram_percent", {}).get("warn", 80),
                          host_t.get("ram_percent", {}).get("crit", 95)),
        "disk":  classify(host.get("disk", {}).get("percent"),
                          host_t.get("disk_percent", {}).get("warn", 80),
                          host_t.get("disk_percent", {}).get("crit", 92)),
        "swap":  classify(host.get("swap", {}).get("percent"),
                          host_t.get("swap_percent", {}).get("warn", 40),
                          host_t.get("swap_percent", {}).get("crit", 75)),
    }
    # Load vs cores
    load1 = host.get("load_avg", [0])[0] if host.get("load_avg") else 0
    cores = max(1, host.get("cpu_count", 1))
    d["severity"]["load"] = classify(load1 / cores,
                                     host_t.get("load_per_core", {}).get("warn", 1.5),
                                     host_t.get("load_per_core", {}).get("crit", 3.0))
    # Network (bytes/s → MB/s)
    net_mb = max(
        (host.get("network", {}).get("rx_bytes_s") or 0) / 1024**2,
        (host.get("network", {}).get("tx_bytes_s") or 0) / 1024**2,
    )
    d["severity"]["net"] = classify(net_mb,
                                    host_t.get("network_rx_mb_s", {}).get("warn", 80),
                                    host_t.get("network_rx_mb_s", {}).get("crit", 120))
    # Timesync
    ts = d.get("timesync", {})
    ts_t = t.get("timesync", {})
    if ts.get("available"):
        abs_off = abs(ts.get("offset_ms") or 0)
        d["severity"]["timesync"] = classify(abs_off,
                                             ts_t.get("offset_ms_abs", {}).get("warn", 200),
                                             ts_t.get("offset_ms_abs", {}).get("crit", 1000))
    else:
        d["severity"]["timesync"] = "warn"
    # Fail2Ban
    f = d.get("fail2ban", {})
    f_t = t.get("fail2ban", {})
    if f.get("available"):
        d["severity"]["fail2ban"] = classify(f.get("currently_banned", 0),
                                             f_t.get("currently_banned", {}).get("warn", 5),
                                             f_t.get("currently_banned", {}).get("crit", 20))
    else:
        d["severity"]["fail2ban"] = "warn"
    # Docker
    dk = d.get("docker", {})
    dk_t = t.get("docker", {})
    if dk.get("available"):
        running = dk.get("running", 0)
        min_running = dk_t.get("expected_min_running", 1)
        d["severity"]["docker"] = "crit" if running < min_running else "ok"
    else:
        d["severity"]["docker"] = "crit"
    # N8N
    n = d.get("n8n", {})
    n_t = t.get("n8n", {})
    if not n.get("reachable"):
        d["severity"]["n8n"] = "crit"
    else:
        d["severity"]["n8n"] = classify(n.get("latency_ms", 0),
                                        n_t.get("latency_ms", {}).get("warn", 1500),
                                        n_t.get("latency_ms", {}).get("crit", 5000))
    # Restic backup
    res = d.get("restic", {})
    if res.get("available"):
        rs = res.get("status", "unknown")
        d["severity"]["restic"] = {"ok": "ok", "warn": "warn"}.get(rs, "crit")
    else:
        d["severity"]["restic"] = "warn"
    # Overall
    order = {"ok": 0, "warn": 1, "crit": 2, "off": 0}
    worst = "ok"
    for s in d["severity"].values():
        if order.get(s, 0) > order.get(worst, 0):
            worst = s
    d["severity"]["overall"] = worst
    return d


async def collect_all() -> dict[str, Any]:
    n8n_task = asyncio.create_task(collect_n8n())
    host_task = asyncio.create_task(collect_host())
    ts_task = asyncio.create_task(collect_timesync())
    dk_task = asyncio.create_task(collect_docker())
    f2b = collect_fail2ban()
    topd = collect_top()
    restic = collect_restic()
    host, ts, dk, n8n = await asyncio.gather(host_task, ts_task, dk_task, n8n_task)
    data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "timesync": ts,
        "fail2ban": f2b,
        "top": topd,
        "docker": dk,
        "n8n": n8n,
        "restic": restic,
    }
    return apply_severity(data)


# ---------- Public/Internal views ----------

def _enrich_containers(containers: list[dict[str, Any]]) -> dict[str, Any]:
    """Split containers into mapped services + unmapped remainder.

    Returns:
        {
          "services": [...],   # containers with friendly names from service_map
          "infrastructure": [...],  # public=False entries
          "unknown": [...],    # containers not in service_map (not hidden)
        }
    """
    services: list[dict[str, Any]] = []
    infra: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []

    for c in containers:
        mapping = _lookup_service(c["name"])
        if mapping is None:
            # Either hidden or unknown — check hidden
            base = _strip_coolify_suffix(c["name"])
            if any(base.startswith(p.rstrip("-")) for p in HIDDEN_PREFIXES):
                continue  # skip entirely
            unknown.append(c)
            continue

        enriched = {
            **c,
            "friendly_name": mapping["name"],
            "software": mapping.get("software", ""),
            "category": mapping.get("category", "application"),
            "public": mapping.get("public", True),
        }
        if mapping.get("public", True):
            services.append(enriched)
        else:
            infra.append(enriched)

    return {"services": services, "infrastructure": infra, "unknown": unknown}


def build_public_status(data: dict[str, Any]) -> dict[str, Any]:
    """Return a public-friendly view: no raw process list, no internal infra."""
    sev = data.get("severity", {})
    host = data.get("host", {})
    f2b = data.get("fail2ban", {})
    dk = data.get("docker", {})
    restic = data.get("restic", {})

    split = _enrich_containers(dk.get("containers", []))

    # Fail2Ban: only surface recent_bans (already GeoIP-enriched by exporter)
    f2b_public = {
        "available": f2b.get("available", False),
        "currently_banned": f2b.get("currently_banned", 0),
        "total_banned": f2b.get("total_banned", 0),
        "recent_bans": f2b.get("recent_bans", []),
    }

    # Restic: surface all fields except raw log details
    restic_public = {k: v for k, v in restic.items() if k != "last_error" or sev.get("restic") != "ok"}

    return {
        "timestamp": data.get("timestamp"),
        "severity": sev,
        "services": split["services"],
        "infrastructure": split["infrastructure"],
        "metrics": {
            "cpu_percent": host.get("cpu_percent"),
            "ram": host.get("ram"),
            "disk": host.get("disk"),
            "uptime_seconds": host.get("uptime_seconds"),
            "network": host.get("network"),
        },
        "fail2ban": f2b_public,
        "restic": restic_public,
        "n8n": data.get("n8n"),
    }


# ---------- HTTP Routes ----------

@app.get("/api/status")
async def api_status() -> JSONResponse:
    return JSONResponse(await collect_all())


@app.get("/api/public-status")
async def api_public_status() -> JSONResponse:
    data = await collect_all()
    return JSONResponse(build_public_status(data))


@app.get("/api/internal-status")
async def api_internal_status() -> JSONResponse:
    """Full internal view including all containers, top processes, timesync."""
    data = await collect_all()
    dk = data.get("docker", {})
    split = _enrich_containers(dk.get("containers", []))
    data["docker"]["services"] = split["services"]
    data["docker"]["infrastructure"] = split["infrastructure"]
    data["docker"]["unknown"] = split["unknown"]
    return JSONResponse(data)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/test-network")
async def test_network() -> JSONResponse:
    """Diagnose outbound connectivity."""
    import socket
    results = {}
    for host, port in [("api.telegram.org", 443), ("8.8.8.8", 53), ("n8nmdobner.duckdns.org", 443)]:
        try:
            loop = asyncio.get_event_loop()
            await asyncio.wait_for(
                loop.run_in_executor(None, lambda h=host, p=port: socket.create_connection((h, p), timeout=5)),
                timeout=6,
            )
            results[f"{host}:{port}"] = "ok"
        except Exception as e:
            results[f"{host}:{port}"] = f"{type(e).__name__}: {e}"
    return JSONResponse(results)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# ---------- WebSocket ----------

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    try:
        await ws.send_json(build_public_status(await collect_all()))
        while True:
            await asyncio.sleep(UPDATE_INTERVAL)
            await ws.send_json(build_public_status(await collect_all()))
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass
