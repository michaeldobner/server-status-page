"""Server Status Page v2 — FastAPI backend.

Data sources (pull-model):
  * Prometheus (PromQL) for host metrics via node_exporter
  * Prometheus (PromQL) for container metrics via cadvisor
  * JSON files on disk for fail2ban history & top processes
  * Direct HTTP for n8n liveness check

No direct /proc, no docker.sock, no pid:host mounts in this container.
"""
from __future__ import annotations

import asyncio
import json
import os
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
N8N_URL = os.environ.get("N8N_URL", "https://n8nmdobner.duckdns.org")
FAIL2BAN_JSON = Path(os.environ.get("FAIL2BAN_JSON", "/host/status/fail2ban.json"))
TOP_JSON = Path(os.environ.get("TOP_JSON", "/host/status/top.json"))
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", "30"))
STATIC_DIR = Path(__file__).parent / "static"
THRESHOLDS_PATH = Path(__file__).parent / "thresholds.yaml"

app = FastAPI(title="Server Status Page v2")

# ---------- Thresholds ----------
try:
    THRESHOLDS = yaml.safe_load(THRESHOLDS_PATH.read_text())
except Exception:
    THRESHOLDS = {}


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


async def collect_docker_from_cadvisor() -> dict[str, Any]:
    """Build container list from cadvisor metrics via Prometheus."""
    # container_last_seen → set of containers; container_memory_usage_bytes → per-container RAM
    try:
        client = await prom.client()
        r = await client.get(
            f"{prom.base_url}/api/v1/query",
            params={"query": 'container_last_seen{name!=""}'},
        )
        r.raise_for_status()
        result = r.json().get("data", {}).get("result", [])
    except Exception as e:
        return {"available": False, "error": str(e)}

    now = time.time()
    cpu_map = await prom.query_map(
        'sum by (name) (rate(container_cpu_usage_seconds_total{name!=""}[1m])) * 100',
        "name",
    )
    mem_map = await prom.query_map(
        'container_memory_usage_bytes{name!=""}',
        "name",
    )

    containers: list[dict[str, Any]] = []
    for item in result:
        metric = item.get("metric", {})
        name = metric.get("name", "")
        if not name:
            continue
        try:
            last_seen = float(item.get("value", [0, 0])[1])
        except ValueError:
            last_seen = 0
        age = max(0, now - last_seen)
        state = "running" if age < 30 else "stopped"
        containers.append({
            "name": name,
            "image": metric.get("image", ""),
            "state": state,
            "health": "-",   # cadvisor doesn't expose docker health; use state
            "uptime": "",
            "cpu_percent": round(cpu_map.get(name, 0), 1),
            "mem_bytes": int(mem_map.get(name, 0)),
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
    dk_task = asyncio.create_task(collect_docker_from_cadvisor())
    f2b = collect_fail2ban()
    topd = collect_top()
    host, ts, dk, n8n = await asyncio.gather(host_task, ts_task, dk_task, n8n_task)
    data: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "timesync": ts,
        "fail2ban": f2b,
        "top": topd,
        "docker": dk,
        "n8n": n8n,
    }
    return apply_severity(data)


# ---------- HTTP Routes ----------

@app.get("/api/status")
async def api_status() -> JSONResponse:
    return JSONResponse(await collect_all())


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# ---------- WebSocket ----------

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    try:
        await ws.send_json(await collect_all())
        while True:
            await asyncio.sleep(UPDATE_INTERVAL)
            await ws.send_json(await collect_all())
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await ws.close()
        except Exception:
            pass
