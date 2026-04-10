#!/usr/bin/env python3
"""
telegram-alerter.py  —  runs on the HOST as a systemd service.

Alert lifecycle:
  - New incident  → send message with inline keyboard (Acknowledge / Snooze 1h)
  - Acknowledged  → edit message, remove Acknowledge button
  - Snoozed       → edit message, suppress further alerts until expiry
  - Recovered     → edit message to RESOLVED, remove buttons

Commands:  /status  /docker  /top  /f2b  /help

Config (environment variables):
  TELEGRAM_BOT_TOKEN   — from @BotFather
  TELEGRAM_CHAT_ID     — your personal chat id
  STATUS_API_URL       — default: http://127.0.0.1:8001/api/status
  STATUS_PAGE_URL      — default: https://statusmdobner.duckdns.org
  ALERT_COOLDOWN_MIN   — minutes between re-alerts for same metric (default 15)
  STATE_FILE           — default: /var/lib/status/alerter-state.json

Requires: Python 3.6+, no third-party packages.
"""
import json
import os
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
STATUS_URL  = os.environ.get("STATUS_API_URL",  "http://127.0.0.1:8001/api/status")
STATUS_PAGE = os.environ.get("STATUS_PAGE_URL", "https://statusmdobner.duckdns.org")
COOLDOWN_S  = int(os.environ.get("ALERT_COOLDOWN_MIN", "15")) * 60
STATE_FILE  = os.environ.get("STATE_FILE", "/var/lib/status/alerter-state.json")
CHECK_EVERY = 30   # seconds between status polls
TG_TIMEOUT  = 30   # seconds for getUpdates long-poll

TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

SEV_EMOJI = {"ok": "✅", "warn": "⚠️", "crit": "🔴", "off": "⚫"}
SEV_ORDER = {"ok": 0, "off": 0, "warn": 1, "crit": 2}

ALERT_LABELS = {
    "cpu":      "CPU Usage",
    "ram":      "RAM Usage",
    "disk":     "Disk Usage",
    "swap":     "Swap Usage",
    "load":     "System Load",
    "net":      "Network Traffic",
    "timesync": "Time Sync",
    "fail2ban": "Fail2Ban",
    "docker":   "Docker",
    "n8n":      "N8N",
}

# ---------------------------------------------------------------------------
# State  (kept in memory, persisted to disk)
# ---------------------------------------------------------------------------
# incidents[metric] = {
#   "message_id": int,
#   "severity":   str,
#   "since_ts":   float,
#   "acknowledged": bool,
#   "snoozed_until": float | None,
# }
_state_lock = threading.Lock()
_state: dict = {"incidents": {}}


def _load_state() -> None:
    global _state
    try:
        with open(STATE_FILE) as f:
            _state = json.load(f)
    except Exception:
        _state = {"incidents": {}}


def _save_state() -> None:
    """Must be called with _state_lock held."""
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(_state, f)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[state] save failed: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _http_get(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "telegram-alerter/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _http_post(url: str, data: dict, timeout: int = 10) -> dict:
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "telegram-alerter/2.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# Telegram API wrappers
# ---------------------------------------------------------------------------

_tg_lock = threading.Lock()


def tg_send(text: str, keyboard: list | None = None) -> int | None:
    """Send a new message. Returns message_id or None."""
    payload: dict = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    try:
        with _tg_lock:
            r = _http_post(f"{TG_API}/sendMessage", payload)
        return r.get("result", {}).get("message_id")
    except Exception as e:
        print(f"[tg] send failed: {e}", file=sys.stderr)
        return None


def tg_edit(message_id: int, text: str, keyboard: list | None = None) -> bool:
    """Edit an existing message."""
    payload: dict = {
        "chat_id": CHAT_ID,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    else:
        payload["reply_markup"] = {"inline_keyboard": []}  # remove buttons
    try:
        with _tg_lock:
            _http_post(f"{TG_API}/editMessageText", payload)
        return True
    except Exception as e:
        # Telegram returns 400 if content didn't change — not a real error
        if "message is not modified" not in str(e).lower():
            print(f"[tg] edit failed: {e}", file=sys.stderr)
        return False


def tg_answer_callback(callback_id: str, text: str = "") -> None:
    try:
        with _tg_lock:
            _http_post(f"{TG_API}/answerCallbackQuery", {
                "callback_query_id": callback_id,
                "text": text,
            })
    except Exception:
        pass


def tg_get_updates(offset: int) -> list:
    params = urllib.parse.urlencode({
        "timeout": TG_TIMEOUT,
        "offset": offset,
        "allowed_updates": json.dumps(["message", "callback_query"]),
    })
    try:
        data = _http_get(f"{TG_API}/getUpdates?{params}", timeout=TG_TIMEOUT + 5)
        return data.get("result", [])
    except Exception as e:
        print(f"[tg] getUpdates failed: {e}", file=sys.stderr)
        return []


# ---------------------------------------------------------------------------
# Alert message builders
# ---------------------------------------------------------------------------

def _alert_keyboard(metric: str, inc: dict) -> list:
    """Build inline keyboard based on current incident state."""
    buttons = []
    if not inc.get("acknowledged"):
        buttons.append({"text": "✓ Acknowledge", "callback_data": f"ack:{metric}"})
    if not inc.get("snoozed_until") or inc["snoozed_until"] < time.time():
        buttons.append({"text": "😴 Snooze 1h", "callback_data": f"snooze:{metric}"})
    return [buttons] if buttons else []


def _fmt_duration(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _alert_text(metric: str, inc: dict, detail: str) -> str:
    label    = ALERT_LABELS.get(metric, metric)
    sev      = inc["severity"]
    emoji    = SEV_EMOJI.get(sev, "?")
    duration = _fmt_duration(time.time() - inc["since_ts"])

    status_line = ""
    if inc.get("acknowledged"):
        status_line = "  ·  <i>✓ acknowledged</i>"
    elif inc.get("snoozed_until") and inc["snoozed_until"] > time.time():
        until = time.strftime("%H:%M", time.localtime(inc["snoozed_until"]))
        status_line = f"  ·  <i>😴 snoozed until {until}</i>"

    lines = [
        f"{emoji} <b>ALERT — {label.upper()} {sev.upper()}</b>{status_line}",
        "",
    ]
    if detail:
        lines.append(detail)
        lines.append("")
    lines += [
        f"Opened: {duration} ago",
        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>',
    ]
    return "\n".join(lines)


def _resolved_text(metric: str, duration_s: float) -> str:
    label = ALERT_LABELS.get(metric, metric)
    return (
        f"✅ <b>RESOLVED — {label}</b>\n\n"
        f"Was degraded for {_fmt_duration(duration_s)}\n"
        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>'
    )


def _alert_detail(metric: str, data: dict) -> str:
    host = data.get("host", {})
    if metric == "cpu":
        return f"CPU at <b>{host.get('cpu_percent', 0):.1f}%</b>"
    if metric == "ram":
        r = host.get("ram", {})
        return f"RAM at <b>{r.get('percent', 0):.1f}%</b>  ({r.get('used_gb', 0)}/{r.get('total_gb', 0)} GB)"
    if metric == "disk":
        r = host.get("disk", {})
        return f"Disk at <b>{r.get('percent', 0):.1f}%</b>  ({r.get('used_gb', 0)}/{r.get('total_gb', 0)} GB)"
    if metric == "swap":
        r = host.get("swap", {})
        return f"Swap at <b>{r.get('percent', 0):.1f}%</b>  ({r.get('used_gb', 0)}/{r.get('total_gb', 0)} GB)"
    if metric == "load":
        load = host.get("load_avg", [0, 0, 0])
        return f"Load: <b>{load[0]} / {load[1]} / {load[2]}</b>  ({host.get('cpu_count', 1)} cores)"
    if metric == "net":
        net = host.get("network", {})
        def b(v):
            if v >= 1024**2: return f"{v/1024**2:.1f} MB/s"
            if v >= 1024: return f"{v/1024:.1f} KB/s"
            return f"{int(v)} B/s"
        return f"↓ {b(net.get('rx_bytes_s', 0))}  ↑ {b(net.get('tx_bytes_s', 0))}"
    if metric == "docker":
        dk = data.get("docker", {})
        return f"Running: <b>{dk.get('running', 0)}/{dk.get('total', 0)}</b> containers"
    if metric == "n8n":
        n = data.get("n8n", {})
        if not n.get("reachable"):
            return "N8N is <b>unreachable</b>"
        return f"N8N latency: <b>{n.get('latency_ms', 0)} ms</b>"
    if metric == "fail2ban":
        return f"Currently banned: <b>{data.get('fail2ban', {}).get('currently_banned', 0)}</b>"
    if metric == "timesync":
        return f"Clock offset: <b>{data.get('timesync', {}).get('offset_ms', 0):.1f} ms</b>"
    return ""


# ---------------------------------------------------------------------------
# Alert thread
# ---------------------------------------------------------------------------

def _fetch_status() -> dict | None:
    try:
        return _http_get(STATUS_URL, timeout=10)
    except Exception as e:
        print(f"[status] fetch failed: {e}", file=sys.stderr)
        return None


def alert_thread_fn() -> None:
    prev_sev: dict[str, str] = {}

    # Wait for app to be fully up, then capture baseline silently
    time.sleep(20)
    d = _fetch_status()
    if d:
        sev = d.get("severity", {})
        for m in ALERT_LABELS:
            prev_sev[m] = sev.get(m, "ok")
        print(f"[alerter] baseline: {prev_sev}", file=sys.stderr)

    tg_send(
        f"🚀 <b>Server monitor online</b>\n\n"
        f"Watching 10 metrics · alerts via this bot\n"
        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>'
    )

    while True:
        time.sleep(CHECK_EVERY)
        d = _fetch_status()
        if not d:
            continue

        sev = d.get("severity", {})
        now = time.time()

        with _state_lock:
            incidents = _state.setdefault("incidents", {})

            for metric, label in ALERT_LABELS.items():
                curr = sev.get(metric, "ok")
                prev = prev_sev.get(metric, "ok")
                inc  = incidents.get(metric)

                curr_rank = SEV_ORDER.get(curr, 0)
                prev_rank = SEV_ORDER.get(prev, 0)

                # ── New incident ──────────────────────────────────────────
                if curr_rank > 0 and prev_rank == 0:
                    detail = _alert_detail(metric, d)
                    new_inc = {
                        "severity": curr,
                        "since_ts": now,
                        "acknowledged": False,
                        "snoozed_until": None,
                        "message_id": None,
                    }
                    text     = _alert_text(metric, new_inc, detail)
                    keyboard = _alert_keyboard(metric, new_inc)
                    mid = tg_send(text, keyboard)
                    new_inc["message_id"] = mid
                    incidents[metric] = new_inc
                    print(f"[alerter] new incident: {metric} {curr}", file=sys.stderr)

                # ── Severity changed within active incident ───────────────
                elif curr_rank > 0 and inc and curr != inc.get("severity"):
                    inc["severity"] = curr
                    # Only re-alert if not snoozed
                    if not inc.get("snoozed_until") or inc["snoozed_until"] < now:
                        detail   = _alert_detail(metric, d)
                        text     = _alert_text(metric, inc, detail)
                        keyboard = _alert_keyboard(metric, inc)
                        if inc.get("message_id"):
                            tg_edit(inc["message_id"], text, keyboard)
                        print(f"[alerter] severity change: {metric} → {curr}", file=sys.stderr)

                # ── Recovery ──────────────────────────────────────────────
                elif curr_rank == 0 and prev_rank > 0 and inc:
                    duration = now - inc.get("since_ts", now)
                    text = _resolved_text(metric, duration)
                    if inc.get("message_id"):
                        tg_edit(inc["message_id"], text, keyboard=None)
                    del incidents[metric]
                    print(f"[alerter] resolved: {metric}", file=sys.stderr)

                prev_sev[metric] = curr

            _save_state()


# ---------------------------------------------------------------------------
# Command formatters
# ---------------------------------------------------------------------------

def _fmt_bytes(b: float) -> str:
    if b >= 1024**2: return f"{b/1024**2:.1f} MB/s"
    if b >= 1024:    return f"{b/1024:.1f} KB/s"
    return f"{int(b)} B/s"


def _fmt_uptime(s: int) -> str:
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d > 0: return f"{d}d {h}h"
    if h > 0: return f"{h}h {m}m"
    return f"{m}m"


def _age_str(age_s: int) -> str:
    if age_s < 3600:  return f"{age_s // 60}m ago"
    if age_s < 86400: return f"{age_s // 3600}h ago"
    return f"{age_s // 86400}d ago"


def fmt_status(d: dict) -> str:
    sev  = d.get("severity", {})
    host = d.get("host", {})
    ts   = d.get("timesync", {})
    dk   = d.get("docker", {})
    n    = d.get("n8n", {})
    f    = d.get("fail2ban", {})
    ram  = host.get("ram", {})
    disk = host.get("disk", {})
    load = host.get("load_avg", [0, 0, 0])
    net  = host.get("network", {})
    overall = sev.get("overall", "?")
    lines = [
        f"<b>Server Status</b>  {SEV_EMOJI.get(overall, '?')} {overall.upper()}",
        "",
        f"CPU    {SEV_EMOJI.get(sev.get('cpu','ok'))}  {host.get('cpu_percent', 0):.1f}%",
        f"RAM    {SEV_EMOJI.get(sev.get('ram','ok'))}  {ram.get('percent', 0):.1f}%"
        f"  ({ram.get('used_gb', 0)}/{ram.get('total_gb', 0)} GB)",
        f"Disk   {SEV_EMOJI.get(sev.get('disk','ok'))}  {disk.get('percent', 0):.1f}%"
        f"  ({disk.get('used_gb', 0)}/{disk.get('total_gb', 0)} GB)",
        f"Load   {SEV_EMOJI.get(sev.get('load','ok'))}  {load[0]} / {load[1]} / {load[2]}"
        f"  ({host.get('cpu_count', 1)} cores)",
        f"Net    {SEV_EMOJI.get(sev.get('net','ok'))}  ↓{_fmt_bytes(net.get('rx_bytes_s', 0))}"
        f"  ↑{_fmt_bytes(net.get('tx_bytes_s', 0))}",
        f"Uptime  {_fmt_uptime(host.get('uptime_seconds', 0))}",
    ]
    if ts.get("available"):
        off = ts.get("offset_ms") or 0
        lines.append(f"Clock  {SEV_EMOJI.get(sev.get('timesync','ok'))}  {off:.1f} ms offset")
    n_str = "up" if n.get("reachable") else "DOWN"
    lines += [
        "",
        f"Docker  {SEV_EMOJI.get(sev.get('docker','ok'))}  {dk.get('running', 0)}/{dk.get('total', 0)} running",
        f"N8N     {SEV_EMOJI.get(sev.get('n8n','ok'))}  {n_str}  {n.get('latency_ms', 0)} ms",
        f"Fail2Ban  {SEV_EMOJI.get(sev.get('fail2ban','ok'))}  {f.get('currently_banned', 0)} banned",
        "",
        f'🔗 <a href="{STATUS_PAGE}">View full dashboard</a>',
    ]
    return "\n".join(lines)


def fmt_docker(d: dict) -> str:
    dk = d.get("docker", {})
    if not dk.get("available"):
        return "❌ Docker unavailable"
    lines = [
        f"<b>Docker</b>  {dk.get('running', 0)}/{dk.get('total', 0)} running",
        "",
    ]
    for c in dk.get("containers", []):
        state  = c.get("state", "?")
        health = c.get("health", "-")
        uptime = c.get("uptime", "")
        if state == "running" and health == "healthy":   dot = "✅"
        elif state == "running" and health == "-":        dot = "🟢"
        elif state == "running" and health == "unhealthy": dot = "🔴"
        elif state == "running":                           dot = "⚠️"
        else:                                              dot = "⚫"
        h_str  = f"  ({health})" if health not in ("-", "healthy") else ""
        up_str = f"  ·  {uptime}" if uptime else ""
        lines.append(f"{dot}  <code>{c.get('name', '?')}</code>{h_str}{up_str}")
    lines += ["", f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>']
    return "\n".join(lines)


def fmt_top(d: dict) -> str:
    top = d.get("top", {})
    if not top.get("available"):
        return "❌ Top data unavailable"
    lines = ["<b>Top Processes</b>", "", "<b>By CPU</b>"]
    for p in top.get("by_cpu", []):
        lines.append(f"  {p.get('cpu', 0):.1f}% cpu  {p.get('mem', 0):.1f}% mem"
                     f"  <code>{(p.get('cmd') or '')[:45]}</code>")
    lines += ["", "<b>By RAM</b>"]
    for p in top.get("by_mem", []):
        lines.append(f"  {p.get('mem', 0):.1f}% mem  {p.get('cpu', 0):.1f}% cpu"
                     f"  <code>{(p.get('cmd') or '')[:45]}</code>")
    lines += ["", f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>']
    return "\n".join(lines)


def fmt_f2b(d: dict) -> str:
    f = d.get("fail2ban", {})
    if not f.get("available"):
        return "❌ Fail2Ban data unavailable"
    lines = [
        "<b>Fail2Ban</b>",
        f"  Banned now:   <b>{f.get('currently_banned', 0)}</b>",
        f"  Total banned: {f.get('total_banned', 0)}",
        f"  Total failed: {f.get('total_failed', 0)}",
    ]
    for j in f.get("jails", []):
        lines.append(f"  {j.get('name','?')}:  {j.get('currently_banned',0)} banned"
                     f"  ·  {j.get('currently_failed',0)} failing")
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
                         f"  [{ban.get('jail','?')}]  {_age_str(age_s)}")
    lines += ["", f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>']
    return "\n".join(lines)


HELP_TEXT = (
    "<b>Available commands</b>\n\n"
    "/status  — server overview\n"
    "/docker  — container list\n"
    "/top     — top processes\n"
    "/f2b     — fail2ban status\n"
    "/help    — this message\n\n"
    f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>'
)


# ---------------------------------------------------------------------------
# Command + callback thread
# ---------------------------------------------------------------------------

def command_thread_fn() -> None:
    offset = 0
    while True:
        updates = tg_get_updates(offset)
        for upd in updates:
            offset = upd["update_id"] + 1

            # ── Inline button pressed ─────────────────────────────────────
            if "callback_query" in upd:
                cb      = upd["callback_query"]
                cb_id   = cb["id"]
                data    = cb.get("data", "")
                user    = cb.get("from", {}).get("first_name", "")
                mid     = cb.get("message", {}).get("message_id")

                action, _, metric = data.partition(":")
                print(f"[bot] callback: {action} {metric}", file=sys.stderr)

                with _state_lock:
                    inc = _state.get("incidents", {}).get(metric)
                    if not inc or inc.get("message_id") != mid:
                        tg_answer_callback(cb_id, "Alert already resolved.")
                        continue

                    if action == "ack":
                        inc["acknowledged"] = True
                        tg_answer_callback(cb_id, "✓ Acknowledged")
                    elif action == "snooze":
                        inc["snoozed_until"] = time.time() + 3600
                        tg_answer_callback(cb_id, "😴 Snoozed for 1 hour")
                    else:
                        tg_answer_callback(cb_id)
                        continue

                    detail   = ""  # don't re-fetch; keep existing detail
                    text     = _alert_text(metric, inc, detail)
                    keyboard = _alert_keyboard(metric, inc)
                    tg_edit(mid, text, keyboard)
                    _save_state()
                continue

            # ── Text command ──────────────────────────────────────────────
            text = upd.get("message", {}).get("text", "")
            if not text.startswith("/"):
                continue
            cmd = text.strip().split()[0].lower().split("@")[0]
            print(f"[bot] command: {cmd}", file=sys.stderr)

            if cmd in ("/help", "/start"):
                tg_send(HELP_TEXT)
            elif cmd == "/status":
                d = _fetch_status()
                tg_send(fmt_status(d) if d else "❌ Status API unreachable")
            elif cmd == "/docker":
                d = _fetch_status()
                tg_send(fmt_docker(d) if d else "❌ Status API unreachable")
            elif cmd == "/top":
                d = _fetch_status()
                tg_send(fmt_top(d) if d else "❌ Status API unreachable")
            elif cmd in ("/f2b", "/fail2ban"):
                d = _fetch_status()
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

    _load_state()
    print(f"[alerter] starting  status={STATUS_URL}  page={STATUS_PAGE}", file=sys.stderr)

    t_alert = threading.Thread(target=alert_thread_fn, daemon=True, name="alert")
    t_cmd   = threading.Thread(target=command_thread_fn, daemon=True, name="commands")
    t_alert.start()
    t_cmd.start()
    t_alert.join()
