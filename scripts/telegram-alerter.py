#!/usr/bin/env python3
"""
telegram-alerter.py  —  runs on the HOST as a systemd service.

Two threads:
  alert_thread:   every 30 s, poll /api/status, detect severity changes, push Telegram.
  command_thread: long-poll Telegram getUpdates, respond to /commands.

Config via environment variables (set in systemd unit):
  TELEGRAM_BOT_TOKEN   — from @BotFather
  TELEGRAM_CHAT_ID     — your personal chat id
  STATUS_API_URL       — defaults to http://127.0.0.1:8001/api/status
  ALERT_COOLDOWN_MIN   — minutes between repeat alerts for the same metric (default 15)

Requires: Python 3.6+, no third-party packages.
"""
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BOT_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID     = os.environ.get("TELEGRAM_CHAT_ID", "")
STATUS_URL  = os.environ.get("STATUS_API_URL", "http://127.0.0.1:8001/api/status")
COOLDOWN_S  = int(os.environ.get("ALERT_COOLDOWN_MIN", "15")) * 60
CHECK_EVERY = 30   # seconds between status polls
TG_TIMEOUT  = 30   # seconds for getUpdates long-poll

TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

SEV_EMOJI = {"ok": "✅", "warn": "⚠️", "crit": "🔴", "off": "⚫"}
SEV_ORDER = {"ok": 0, "off": 0, "warn": 1, "crit": 2}

ALERT_LABELS = {
    "cpu":      "CPU usage",
    "ram":      "RAM usage",
    "disk":     "Disk usage",
    "swap":     "Swap usage",
    "load":     "System load",
    "net":      "Network traffic",
    "timesync": "Time sync",
    "fail2ban": "Fail2Ban",
    "docker":   "Docker",
    "n8n":      "N8N",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    return ctx


def _http_get(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "telegram-alerter/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_post(url: str, data: dict, timeout: int = 10) -> dict:
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "telegram-alerter/1.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _fmt_bytes(b: float) -> str:
    if b >= 1024**3:
        return f"{b/1024**3:.1f} GB/s"
    if b >= 1024**2:
        return f"{b/1024**2:.1f} MB/s"
    if b >= 1024:
        return f"{b/1024:.1f} KB/s"
    return f"{int(b)} B/s"


def _fmt_uptime(s: int) -> str:
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


def _age_str(age_s: int) -> str:
    if age_s < 3600:
        return f"{age_s // 60}m ago"
    if age_s < 86400:
        return f"{age_s // 3600}h ago"
    return f"{age_s // 86400}d ago"


# ---------------------------------------------------------------------------
# Telegram sender
# ---------------------------------------------------------------------------

_tg_lock = threading.Lock()


def tg_send(text: str) -> bool:
    url = f"{TG_API}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    try:
        with _tg_lock:
            _http_post(url, payload, timeout=10)
        return True
    except Exception as e:
        print(f"[telegram] send failed: {e}", file=sys.stderr)
        return False


def tg_get_updates(offset: int) -> list:
    url = f"{TG_API}/getUpdates"
    params = urllib.parse.urlencode({
        "timeout": TG_TIMEOUT,
        "offset": offset,
        "allowed_updates": "message",
    })
    try:
        data = _http_get(f"{url}?{params}", timeout=TG_TIMEOUT + 5)
        return data.get("result", [])
    except Exception as e:
        print(f"[telegram] getUpdates failed: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Status data fetcher
# ---------------------------------------------------------------------------

def fetch_status() -> dict | None:
    try:
        return _http_get(STATUS_URL, timeout=10)
    except Exception as e:
        print(f"[status] fetch failed: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Message formatters
# ---------------------------------------------------------------------------

def fmt_status(d: dict) -> str:
    sev  = d.get("severity", {})
    host = d.get("host", {})
    ts   = d.get("timesync", {})
    dk   = d.get("docker", {})
    n    = d.get("n8n", {})
    f    = d.get("fail2ban", {})
    overall = sev.get("overall", "?")
    ram  = host.get("ram", {})
    disk = host.get("disk", {})
    load = host.get("load_avg", [0, 0, 0])
    net  = host.get("network", {})
    lines = [
        f"<b>🖥 Server Status</b>  {SEV_EMOJI.get(overall,'?')} <b>{overall.upper()}</b>",
        "",
        "<b>Host</b>",
        f"  CPU:    {SEV_EMOJI.get(sev.get('cpu','ok'))} {host.get('cpu_percent',0):.1f}%",
        f"  RAM:    {SEV_EMOJI.get(sev.get('ram','ok'))} {ram.get('percent',0):.1f}%"
        f"  ({ram.get('used_gb',0)}/{ram.get('total_gb',0)} GB)",
        f"  Disk:   {SEV_EMOJI.get(sev.get('disk','ok'))} {disk.get('percent',0):.1f}%"
        f"  ({disk.get('used_gb',0)}/{disk.get('total_gb',0)} GB)",
        f"  Load:   {SEV_EMOJI.get(sev.get('load','ok'))} {load[0]}/{load[1]}/{load[2]}"
        f"  ({host.get('cpu_count',1)} cores)",
        f"  Net:    {SEV_EMOJI.get(sev.get('net','ok'))}"
        f" ↓{_fmt_bytes(net.get('rx_bytes_s',0))}  ↑{_fmt_bytes(net.get('tx_bytes_s',0))}",
        f"  Uptime: {_fmt_uptime(host.get('uptime_seconds',0))}",
    ]
    if ts.get("available"):
        off = ts.get("offset_ms") or 0
        lines.append(f"  Clock:  {SEV_EMOJI.get(sev.get('timesync','ok'))} {off:.1f} ms")
    n_str = "up" if n.get("reachable") else "DOWN"
    lines += [
        "",
        f"<b>Docker</b>  {SEV_EMOJI.get(sev.get('docker','ok'))}"
        f"  {dk.get('running',0)}/{dk.get('total',0)} running",
        "",
        f"<b>N8N</b>  {SEV_EMOJI.get(sev.get('n8n','ok'))}  {n_str}  {n.get('latency_ms',0)} ms",
        "",
        f"<b>Fail2Ban</b>  {SEV_EMOJI.get(sev.get('fail2ban','ok'))}"
        f"  {f.get('currently_banned',0)} banned  /  {f.get('total_banned',0)} total",
    ]
    return "\n".join(lines)


def fmt_docker(d: dict) -> str:
    dk = d.get("docker", {})
    if not dk.get("available"):
        return "❌ Docker unavailable"
    lines = [f"<b>🐳 Docker</b>  {dk.get('running',0)}/{dk.get('total',0)} running", ""]
    for c in dk.get("containers", []):
        state  = c.get("state", "?")
        health = c.get("health", "-")
        uptime = c.get("uptime", "")
        if state == "running" and health == "healthy":
            dot = "✅"
        elif state == "running" and health == "-":
            dot = "🟢"
        elif state == "running" and health in ("unhealthy", "starting"):
            dot = "⚠️"
        else:
            dot = "🔴"
        h_str  = f" ({health})" if health not in ("-", "healthy") else ""
        up_str = f"  •  {uptime}" if uptime else ""
        lines.append(f"{dot} <code>{c.get('name','?')}</code>{h_str}{up_str}")
    return "\n".join(lines)


def fmt_top(d: dict) -> str:
    top = d.get("top", {})
    if not top.get("available"):
        return "❌ Top data unavailable"
    lines = ["<b>⚡ Top Processes</b>", "", "<b>By CPU:</b>"]
    for p in top.get("by_cpu", []):
        lines.append(f"  {p.get('cpu',0):.1f}% cpu  {p.get('mem',0):.1f}% mem"
                     f"  <code>{(p.get('cmd') or '')[:45]}</code>")
    lines += ["", "<b>By RAM:</b>"]
    for p in top.get("by_mem", []):
        lines.append(f"  {p.get('mem',0):.1f}% mem  {p.get('cpu',0):.1f}% cpu"
                     f"  <code>{(p.get('cmd') or '')[:45]}</code>")
    return "\n".join(lines)


def fmt_f2b(d: dict) -> str:
    f = d.get("fail2ban", {})
    if not f.get("available"):
        return "❌ Fail2Ban data unavailable"
    lines = [
        "<b>🛡 Fail2Ban</b>",
        f"  Currently banned: <b>{f.get('currently_banned',0)}</b>",
        f"  Total banned:     {f.get('total_banned',0)}",
        f"  Total failed:     {f.get('total_failed',0)}",
    ]
    for j in f.get("jails", []):
        lines.append(f"  {j.get('name','?')}: "
                     f"{j.get('currently_banned',0)} banned  "
                     f"{j.get('currently_failed',0)} failing")
    ips = f.get("banned_ips", [])
    if ips:
        lines += ["", "<b>Currently banned:</b>"]
        for ip in ips[:10]:
            lines.append(f"  • <code>{ip}</code>")
    recent = f.get("recent_bans", [])
    if recent:
        lines += ["", "<b>Recent bans:</b>"]
        now_epoch = int(f.get("now_epoch", time.time()))
        for ban in recent[:8]:
            age_s = now_epoch - int(ban.get("timeofban", now_epoch))
            lines.append(f"  <code>{ban.get('ip','?')}</code>"
                         f"  [{ban.get('jail','?')}]"
                         f"  {_age_str(age_s)}")
    return "\n".join(lines)


def _alert_detail(metric: str, d: dict) -> str:
    host = d.get("host", {})
    if metric == "cpu":
        return f"CPU: {host.get('cpu_percent',0):.1f}%"
    if metric == "ram":
        r = host.get("ram", {})
        return f"RAM: {r.get('percent',0):.1f}%  ({r.get('used_gb',0)}/{r.get('total_gb',0)} GB)"
    if metric == "disk":
        r = host.get("disk", {})
        return f"Disk: {r.get('percent',0):.1f}%  ({r.get('used_gb',0)}/{r.get('total_gb',0)} GB)"
    if metric == "swap":
        r = host.get("swap", {})
        return f"Swap: {r.get('percent',0):.1f}%  ({r.get('used_gb',0)}/{r.get('total_gb',0)} GB)"
    if metric == "load":
        load = host.get("load_avg", [0, 0, 0])
        return f"Load: {load[0]}/{load[1]}/{load[2]}  ({host.get('cpu_count',1)} cores)"
    if metric == "net":
        net = host.get("network", {})
        return f"↓{_fmt_bytes(net.get('rx_bytes_s',0))}  ↑{_fmt_bytes(net.get('tx_bytes_s',0))}"
    if metric == "docker":
        dk = d.get("docker", {})
        return f"Running: {dk.get('running',0)}/{dk.get('total',0)} containers"
    if metric == "n8n":
        n = d.get("n8n", {})
        if not n.get("reachable"):
            err = n.get("error", "")
            return f"N8N unreachable — {err[:80]}" if err else "N8N unreachable"
        return f"N8N latency: {n.get('latency_ms',0)} ms"
    if metric == "fail2ban":
        return f"Currently banned: {d.get('fail2ban',{}).get('currently_banned',0)}"
    if metric == "timesync":
        return f"Clock offset: {d.get('timesync',{}).get('offset_ms',0):.1f} ms"
    return ""


HELP_TEXT = """\
<b>Available commands:</b>

/status  — full server overview
/docker  — container list
/top     — top processes (CPU + RAM)
/f2b     — fail2ban jails + recent bans
/help    — this message"""


# ---------------------------------------------------------------------------
# Alert thread
# ---------------------------------------------------------------------------

def alert_thread_fn() -> None:
    prev: dict[str, str] = {}
    last_alert: dict[str, float] = {}

    # Initialise state silently on first run
    time.sleep(20)
    d = fetch_status()
    if d:
        sev = d.get("severity", {})
        for m in ALERT_LABELS:
            prev[m] = sev.get(m, "ok")
        print(f"[alerter] initialised: {prev}", file=sys.stderr)

    tg_send("🚀 <b>Status page alerter started</b>\nSend /help for commands.")

    while True:
        time.sleep(CHECK_EVERY)
        d = fetch_status()
        if not d:
            continue
        sev = d.get("severity", {})
        now = time.time()

        for metric, label in ALERT_LABELS.items():
            curr = sev.get(metric, "ok")
            p    = prev.get(metric, "ok")
            if curr == p:
                continue

            curr_rank = SEV_ORDER.get(curr, 0)
            prev_rank = SEV_ORDER.get(p, 0)

            if curr_rank > prev_rank:
                if now - last_alert.get(metric, 0) < COOLDOWN_S:
                    prev[metric] = curr
                    continue
                last_alert[metric] = now
                detail = _alert_detail(metric, d)
                emoji  = SEV_EMOJI.get(curr, "?")
                msg    = f"{emoji} <b>ALERT: {label} → {curr.upper()}</b>"
                if detail:
                    msg += f"\n{detail}"
                tg_send(msg)
                print(f"[alerter] sent: {metric} {p}→{curr}", file=sys.stderr)

            elif curr == "ok" and prev_rank > 0:
                tg_send(f"✅ <b>RECOVERED: {label} is back to OK</b>")
                print(f"[alerter] recovered: {metric}", file=sys.stderr)

            prev[metric] = curr


# ---------------------------------------------------------------------------
# Command thread
# ---------------------------------------------------------------------------

def command_thread_fn() -> None:
    offset = 0
    while True:
        updates = tg_get_updates(offset)
        for upd in updates:
            offset = upd["update_id"] + 1
            text = upd.get("message", {}).get("text", "")
            if not text.startswith("/"):
                continue
            cmd = text.strip().split()[0].lower().split("@")[0]
            print(f"[bot] command: {cmd}", file=sys.stderr)
            if cmd in ("/help", "/start"):
                tg_send(HELP_TEXT)
            elif cmd == "/status":
                d = fetch_status()
                tg_send(fmt_status(d) if d else "❌ Status API unreachable")
            elif cmd == "/docker":
                d = fetch_status()
                tg_send(fmt_docker(d) if d else "❌ Status API unreachable")
            elif cmd == "/top":
                d = fetch_status()
                tg_send(fmt_top(d) if d else "❌ Status API unreachable")
            elif cmd in ("/f2b", "/fail2ban"):
                d = fetch_status()
                tg_send(fmt_f2b(d) if d else "❌ Status API unreachable")
            else:
                tg_send(f"Unknown command: <code>{cmd}</code>\n\n{HELP_TEXT}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if not BOT_TOKEN or not CHAT_ID:
        print("ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set", file=sys.stderr)
        sys.exit(1)

    print(f"[alerter] starting — status URL: {STATUS_URL}", file=sys.stderr)

    t_alert = threading.Thread(target=alert_thread_fn, daemon=True, name="alert")
    t_cmd   = threading.Thread(target=command_thread_fn, daemon=True, name="commands")
    t_alert.start()
    t_cmd.start()
    t_alert.join()
