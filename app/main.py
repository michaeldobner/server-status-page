"""Server Status Page — FastAPI backend with WebSocket live updates."""
from __future__ import annotations

import asyncio
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
import httpx
import psutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse

# ---------- Configuration ----------
N8N_URL = os.environ.get("N8N_URL", "https://n8nmdobner.duckdns.org")
FAIL2BAN_JSON = Path(os.environ.get("FAIL2BAN_JSON", "/host/status/fail2ban.json"))
HOST_ROOT = os.environ.get("HOST_ROOT", "/host/root")
UPDATE_INTERVAL = int(os.environ.get("UPDATE_INTERVAL", "30"))
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Server Status Page")

# ---------- Metric Collectors ----------

def _host_disk() -> dict[str, Any]:
    """Use host root mount if available, else container's own root."""
    path = HOST_ROOT if os.path.isdir(HOST_ROOT) else "/"
    try:
        usage = psutil.disk_usage(path)
        return {
            "used_gb": round(usage.used / 1024**3, 1),
            "total_gb": round(usage.total / 1024**3, 1),
            "percent": round(usage.percent, 1),
        }
    except Exception as e:
        return {"error": str(e)}


def _host_uptime() -> int:
    """Read uptime from /proc (host proc if pid:host, else container proc)."""
    try:
        with open("/proc/uptime") as f:
            return int(float(f.read().split()[0]))
    except Exception:
        return int(time.time() - psutil.boot_time())


def collect_host() -> dict[str, Any]:
    try:
        mem = psutil.virtual_memory()
        load1, load5, load15 = psutil.getloadavg()
        return {
            "cpu_percent": round(psutil.cpu_percent(interval=None), 1),
            "cpu_count": psutil.cpu_count(logical=True),
            "ram": {
                "used_gb": round(mem.used / 1024**3, 1),
                "total_gb": round(mem.total / 1024**3, 1),
                "percent": round(mem.percent, 1),
            },
            "disk": _host_disk(),
            "uptime_seconds": _host_uptime(),
            "load_avg": [round(load1, 2), round(load5, 2), round(load15, 2)],
        }
    except Exception as e:
        return {"error": str(e)}


def collect_fail2ban() -> dict[str, Any]:
    """Read fail2ban JSON written by host systemd timer."""
    if not FAIL2BAN_JSON.exists():
        return {"available": False, "error": f"{FAIL2BAN_JSON} not found"}
    try:
        data = json.loads(FAIL2BAN_JSON.read_text())
        data["available"] = True
        # Freshness check — warn if stale (> 2 min)
        age = time.time() - FAIL2BAN_JSON.stat().st_mtime
        data["age_seconds"] = int(age)
        return data
    except Exception as e:
        return {"available": False, "error": str(e)}


_docker_client: docker.DockerClient | None = None


def _get_docker() -> docker.DockerClient | None:
    global _docker_client
    if _docker_client is not None:
        return _docker_client
    try:
        _docker_client = docker.from_env()
        _docker_client.ping()
        return _docker_client
    except Exception:
        _docker_client = None
        return None


def collect_docker() -> dict[str, Any]:
    client = _get_docker()
    if client is None:
        return {"available": False, "error": "docker socket not accessible"}
    try:
        containers = []
        for c in client.containers.list(all=False):
            attrs = c.attrs
            state = attrs.get("State", {})
            health = state.get("Health", {}).get("Status") if state.get("Health") else None
            started_at = state.get("StartedAt", "")
            uptime = ""
            if started_at:
                try:
                    started = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                    delta = datetime.now(timezone.utc) - started
                    days = delta.days
                    hours = delta.seconds // 3600
                    mins = (delta.seconds % 3600) // 60
                    if days > 0:
                        uptime = f"{days}d {hours}h"
                    elif hours > 0:
                        uptime = f"{hours}h {mins}m"
                    else:
                        uptime = f"{mins}m"
                except Exception:
                    pass
            containers.append({
                "name": c.name,
                "image": (c.image.tags[0] if c.image.tags else c.image.short_id),
                "state": state.get("Status", "unknown"),
                "health": health or "-",
                "uptime": uptime,
            })
        containers.sort(key=lambda x: x["name"])
        healthy = sum(1 for c in containers if c["state"] == "running")
        return {
            "available": True,
            "total": len(containers),
            "running": healthy,
            "containers": containers,
        }
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


async def collect_all() -> dict[str, Any]:
    n8n_task = asyncio.create_task(collect_n8n())
    host = collect_host()
    f2b = collect_fail2ban()
    dock = collect_docker()
    n8n = await n8n_task
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": host,
        "fail2ban": f2b,
        "docker": dock,
        "n8n": n8n,
    }


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
        # prime cpu_percent (first call returns 0.0)
        psutil.cpu_percent(interval=None)
        # send an immediate snapshot
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
