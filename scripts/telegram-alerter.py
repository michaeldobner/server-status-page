#!/usr/bin/env python3
"""
telegram-alerter.py  —  runs on the HOST as a systemd service.

Commands:    /status  /docker  /top  /f2b  /help
Buttons:     🔄 Refresh  on every command response
             ✓ Acknowledge  😴 Snooze 1h  on every alert
Alert flow:  new incident → message + buttons
             state change  → edit same message
             resolved      → edit to RESOLVED, remove buttons

Config (env vars):
  TELEGRAM_BOT_TOKEN   TELEGRAM_CHAT_ID
  STATUS_API_URL       STATUS_PAGE_URL
  ALERT_COOLDOWN_MIN   STATE_FILE
"""
import json
import os
import sys
import threading
import time
import urllib.parse
import urllib.request

# ── Config ────────────────────────────────────────────────────────────────────
BOT_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID     = os.environ.get("TELEGRAM_CHAT_ID", "")
STATUS_URL  = os.environ.get("STATUS_API_URL",  "http://127.0.0.1:8001/api/status")
STATUS_PAGE = os.environ.get("STATUS_PAGE_URL", "https://statusmdobner.duckdns.org")
COOLDOWN_S  = int(os.environ.get("ALERT_COOLDOWN_MIN", "15")) * 60
STATE_FILE  = os.environ.get("STATE_FILE", "/var/lib/status/alerter-state.json")
CHECK_EVERY = 30
TG_TIMEOUT  = 30

TG_API = f"https://api.telegram.org/bot{BOT_TOKEN}"

SEV_EMOJI = {"ok": "✅", "warn": "⚠️", "crit": "🔴", "off": "⚫"}
SEV_ORDER  = {"ok": 0, "off": 0, "warn": 1, "crit": 2}

ALERT_LABELS = {
    "cpu":      "CPU Usage",
    "ram":      "RAM Usage",
    "disk":     "Disk Usage",
    "swap":     "Swap Usage",
    "load":     "System Load",
    "net":      "Network",
    "timesync": "Time Sync",
    "fail2ban": "Fail2Ban",
    "docker":   "Docker",
    "n8n":      "N8N",
}

# ── State ─────────────────────────────────────────────────────────────────────
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
    tmp = STATE_FILE + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(_state, f)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        print(f"[state] save failed: {e}", file=sys.stderr)


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 10) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "telegram-alerter/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def _http_post(url: str, data: dict, timeout: int = 10) -> dict:
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url, data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


# ── Telegram API ──────────────────────────────────────────────────────────────

_tg_lock = threading.Lock()


def tg_call(method: str, payload: dict) -> dict:
    try:
        with _tg_lock:
            return _http_post(f"{TG_API}/{method}", payload, timeout=12)
    except Exception as e:
        msg = str(e)
        if "message is not modified" not in msg:
            print(f"[tg] {method} failed: {e}", file=sys.stderr)
        return {}


def tg_send(text: str, keyboard: list | None = None) -> int | None:
    payload: dict = {
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    r = tg_call("sendMessage", payload)
    return r.get("result", {}).get("message_id")


def tg_edit(message_id: int, text: str, keyboard: list | None = None) -> None:
    payload: dict = {
        "chat_id": CHAT_ID,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": {"inline_keyboard": keyboard if keyboard is not None else []},
    }
    tg_call("editMessageText", payload)


def tg_answer(callback_id: str, text: str = "") -> None:
    tg_call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})


def tg_get_updates(offset: int) -> list:
    params = urllib.parse.urlencode({
        "timeout": TG_TIMEOUT,
        "offset": offset,
        "allowed_updates": '["message","callback_query"]',
    })
    try:
        data = _http_get(f"{TG_API}/getUpdates?{params}", timeout=TG_TIMEOUT + 5)
        return data.get("result", [])
    except Exception as e:
        print(f"[tg] getUpdates: {e}", file=sys.stderr)
        return []


# ── Helpers ───────────────────────────────────────────────────────────────────

def _bytes(b: float) -> str:
    if b >= 1_048_576: return f"{b/1_048_576:.1f} MB/s"
    if b >= 1_024:     return f"{b/1_024:.1f} KB/s"
    return f"{int(b)} B/s"


def _uptime(s: int) -> str:
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d: return f"{d}d {h}h"
    if h: return f"{h}h {m}m"
    return f"{m}m"


def _age(s: int) -> str:
    if s < 3600:  return f"{s//60}m ago"
    if s < 86400: return f"{s//3600}h ago"
    return f"{s//86400}d ago"


def _duration(s: float) -> str:
    s = int(s)
    if s < 60:   return f"{s}s"
    if s < 3600: return f"{s//60}m"
    return f"{s//3600}h {(s%3600)//60}m"


def _fetch() -> dict | None:
    try:
        return _http_get(STATUS_URL, timeout=10)
    except Exception as e:
        print(f"[status] fetch failed: {e}", file=sys.stderr)
        return None


REFRESH_BTN = {"text": "🔄 Refresh", "callback_data": "refresh:{}"}
DASH_LINK   = f'\n\n🔗 <a href="{STATUS_PAGE}">Open dashboard</a>'


# ── Formatters ────────────────────────────────────────────────────────────────

def fmt_status(d: dict) -> str:
    sev  = d.get("severity", {})
    h    = d.get("host", {})
    ts   = d.get("timesync", {})
    dk   = d.get("docker", {})
    n    = d.get("n8n", {})
    f    = d.get("fail2ban", {})
    ram  = h.get("ram", {})
    disk = h.get("disk", {})
    load = h.get("load_avg", [0, 0, 0])
    net  = h.get("network", {})

    overall = sev.get("overall", "?")
    e = SEV_EMOJI

    lines = [
        f"<b>Server Status</b>  {e.get(overall,'?')} <b>{overall.upper()}</b>",
        "",
        f"{e.get(sev.get('cpu','ok'))} CPU    <b>{h.get('cpu_percent',0):.1f}%</b>",
        f"{e.get(sev.get('ram','ok'))} RAM    <b>{ram.get('percent',0):.1f}%</b>"
        f"  ·  {ram.get('used_gb',0)} / {ram.get('total_gb',0)} GB",
        f"{e.get(sev.get('disk','ok'))} Disk   <b>{disk.get('percent',0):.1f}%</b>"
        f"  ·  {disk.get('used_gb',0)} / {disk.get('total_gb',0)} GB",
        f"{e.get(sev.get('load','ok'))} Load   <b>{load[0]}</b> · {load[1]} · {load[2]}"
        f"  ·  {h.get('cpu_count',1)} cores",
        f"{e.get(sev.get('net','ok'))} Net    ↓ {_bytes(net.get('rx_bytes_s',0))}"
        f"  ↑ {_bytes(net.get('tx_bytes_s',0))}",
        f"🕐 Uptime  <b>{_uptime(h.get('uptime_seconds',0))}</b>",
    ]

    if ts.get("available"):
        off = ts.get("offset_ms") or 0
        lines.append(
            f"{e.get(sev.get('timesync','ok'))} Clock  <b>{off:.1f} ms</b> offset"
        )

    n_up = "up" if n.get("reachable") else "<b>DOWN</b>"
    lines += [
        "",
        f"{e.get(sev.get('docker','ok'))} Docker    {dk.get('running',0)} / {dk.get('total',0)} running",
        f"{e.get(sev.get('n8n','ok'))} N8N       {n_up}  ·  {n.get('latency_ms',0)} ms",
        f"{e.get(sev.get('fail2ban','ok'))} Fail2Ban  {f.get('currently_banned',0)} banned",
    ]

    return "\n".join(lines) + DASH_LINK


def fmt_docker(d: dict) -> str:
    dk = d.get("docker", {})
    if not dk.get("available"):
        return "❌ Docker unavailable" + DASH_LINK

    lines = [
        f"<b>Docker</b>  ·  {dk.get('running',0)} / {dk.get('total',0)} running",
        "",
    ]
    for c in dk.get("containers", []):
        state  = c.get("state", "?")
        health = c.get("health", "-")
        uptime = c.get("uptime", "")
        if   state == "running" and health == "healthy":    dot = "✅"
        elif state == "running" and health == "-":           dot = "🟢"
        elif state == "running" and health == "unhealthy":   dot = "🔴"
        elif state == "running":                             dot = "⚠️"
        else:                                                dot = "⚫"
        h_str  = f"  ({health})" if health not in ("-", "healthy") else ""
        up_str = f"  ·  {uptime}" if uptime else ""
        lines.append(f"{dot}  <code>{c.get('name','?')}</code>{h_str}{up_str}")

    return "\n".join(lines) + DASH_LINK


def fmt_top(d: dict) -> str:
    top = d.get("top", {})
    if not top.get("available"):
        return "❌ Top data unavailable" + DASH_LINK

    lines = ["<b>Top Processes</b>", "", "By CPU"]
    for p in top.get("by_cpu", []):
        cmd = (p.get("cmd") or "")[:45]
        lines.append(f"<b>{p.get('cpu',0):.1f}%</b> cpu  {p.get('mem',0):.1f}% mem"
                     f"  <code>{cmd}</code>")
    lines += ["", "By RAM"]
    for p in top.get("by_mem", []):
        cmd = (p.get("cmd") or "")[:45]
        lines.append(f"<b>{p.get('mem',0):.1f}%</b> mem  {p.get('cpu',0):.1f}% cpu"
                     f"  <code>{cmd}</code>")

    return "\n".join(lines) + DASH_LINK


def fmt_f2b(d: dict) -> str:
    f = d.get("fail2ban", {})
    if not f.get("available"):
        return "❌ Fail2Ban unavailable" + DASH_LINK

    lines = [
        "<b>Fail2Ban</b>",
        f"Banned now:    <b>{f.get('currently_banned',0)}</b>",
        f"Total banned:  {f.get('total_banned',0)}",
        f"Total failed:  {f.get('total_failed',0)}",
    ]

    for j in f.get("jails", []):
        lines.append(
            f"· {j.get('name','?')}  —  "
            f"{j.get('currently_banned',0)} banned  ·  {j.get('currently_failed',0)} failing"
        )

    ips = f.get("banned_ips", [])
    if ips:
        lines += ["", "Currently banned"]
        for ip in ips[:10]:
            lines.append(f'<code>{ip}</code>  <a href="https://ipinfo.io/{ip}">whois ↗</a>')

    recent = f.get("recent_bans", [])
    if recent:
        lines += ["", "Recent bans"]
        now_e = int(f.get("now_epoch", time.time()))
        for ban in recent[:8]:
            age_s = now_e - int(ban.get("timeofban", now_e))
            ip = ban.get("ip", "?")
            lines.append(
                f'<code>{ip}</code>  <a href="https://ipinfo.io/{ip}">whois ↗</a>'
                f"  ·  {ban.get('jail','?')}  ·  {_age(age_s)}"
            )

    return "\n".join(lines) + DASH_LINK


# ── Alert message builders ─────────────────────────────────────────────────────

def _alert_detail(metric: str, d: dict) -> str:
    h = d.get("host", {})
    if metric == "cpu":
        return f"CPU at <b>{h.get('cpu_percent',0):.1f}%</b>"
    if metric == "ram":
        r = h.get("ram", {})
        return f"RAM at <b>{r.get('percent',0):.1f}%</b>  ·  {r.get('used_gb',0)} / {r.get('total_gb',0)} GB"
    if metric == "disk":
        r = h.get("disk", {})
        return f"Disk at <b>{r.get('percent',0):.1f}%</b>  ·  {r.get('used_gb',0)} / {r.get('total_gb',0)} GB"
    if metric == "swap":
        r = h.get("swap", {})
        return f"Swap at <b>{r.get('percent',0):.1f}%</b>"
    if metric == "load":
        load = h.get("load_avg", [0, 0, 0])
        return f"Load <b>{load[0]}</b> · {load[1]} · {load[2]}  ({h.get('cpu_count',1)} cores)"
    if metric == "net":
        net = h.get("network", {})
        return f"↓ {_bytes(net.get('rx_bytes_s',0))}  ↑ {_bytes(net.get('tx_bytes_s',0))}"
    if metric == "docker":
        dk = d.get("docker", {})
        return f"<b>{dk.get('running',0)} / {dk.get('total',0)}</b> containers running"
    if metric == "n8n":
        n = d.get("n8n", {})
        if not n.get("reachable"):
            err = n.get("error", "")
            return f"Unreachable" + (f"  ·  {err[:60]}" if err else "")
        return f"Latency <b>{n.get('latency_ms',0)} ms</b>"
    if metric == "fail2ban":
        return f"<b>{d.get('fail2ban',{}).get('currently_banned',0)}</b> IPs currently banned"
    if metric == "timesync":
        return f"Clock offset <b>{d.get('timesync',{}).get('offset_ms',0):.1f} ms</b>"
    return ""


def _alert_text(metric: str, inc: dict, detail: str) -> str:
    label  = ALERT_LABELS.get(metric, metric)
    sev    = inc["severity"]
    emoji  = SEV_EMOJI.get(sev, "?")
    age    = _duration(time.time() - inc["since_ts"])

    badges = []
    if inc.get("acknowledged"):
        badges.append("✓ acknowledged")
    if inc.get("snoozed_until") and inc["snoozed_until"] > time.time():
        until = time.strftime("%H:%M", time.localtime(inc["snoozed_until"]))
        badges.append(f"😴 snoozed until {until}")
    badge_str = "  ·  " + "  ·  ".join(f"<i>{b}</i>" for b in badges) if badges else ""

    lines = [
        f"{emoji} <b>{label} — {sev.upper()}</b>{badge_str}",
        "",
    ]
    if detail:
        lines += [detail, ""]
    lines += [
        f"Open for {age}",
        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>',
    ]
    return "\n".join(lines)


def _alert_keyboard(metric: str, inc: dict) -> list:
    row = []
    if not inc.get("acknowledged"):
        row.append({"text": "✓ Acknowledge", "callback_data": f"ack:{metric}"})
    snoozed = inc.get("snoozed_until") and inc["snoozed_until"] > time.time()
    if not snoozed:
        row.append({"text": "😴 Snooze 1h", "callback_data": f"snooze:{metric}"})
    return [row] if row else []


# ── Alert thread ──────────────────────────────────────────────────────────────

def alert_thread_fn() -> None:
    prev_sev: dict[str, str] = {}

    time.sleep(20)   # wait for app startup
    d = _fetch()
    if d:
        sev = d.get("severity", {})
        for m in ALERT_LABELS:
            prev_sev[m] = sev.get(m, "ok")
        print(f"[alerter] baseline: {prev_sev}", file=sys.stderr)

    tg_send(
        f"🟢 <b>Server monitor online</b>\n\n"
        f"Watching {len(ALERT_LABELS)} metrics — alerts via this chat\n"
        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>'
    )

    while True:
        time.sleep(CHECK_EVERY)
        d = _fetch()
        if not d:
            continue

        sev = d.get("severity", {})
        now = time.time()

        with _state_lock:
            incidents = _state.setdefault("incidents", {})

            for metric in ALERT_LABELS:
                curr = sev.get(metric, "ok")
                prev = prev_sev.get(metric, "ok")
                inc  = incidents.get(metric)

                curr_r = SEV_ORDER.get(curr, 0)
                prev_r = SEV_ORDER.get(prev, 0)

                # New incident
                if curr_r > 0 and prev_r == 0:
                    detail  = _alert_detail(metric, d)
                    new_inc = {"severity": curr, "since_ts": now,
                               "acknowledged": False, "snoozed_until": None,
                               "message_id": None, "detail": detail}
                    mid = tg_send(_alert_text(metric, new_inc, detail),
                                  _alert_keyboard(metric, new_inc))
                    new_inc["message_id"] = mid
                    incidents[metric] = new_inc
                    print(f"[alerter] new: {metric} → {curr}", file=sys.stderr)

                # Severity worsened
                elif curr_r > prev_r and inc:
                    inc["severity"] = curr
                    snoozed = inc.get("snoozed_until") and inc["snoozed_until"] > now
                    if not snoozed:
                        detail = _alert_detail(metric, d)
                        inc["detail"] = detail
                        if inc.get("message_id"):
                            tg_edit(inc["message_id"],
                                    _alert_text(metric, inc, detail),
                                    _alert_keyboard(metric, inc))
                    print(f"[alerter] worsened: {metric} → {curr}", file=sys.stderr)

                # Recovered
                elif curr_r == 0 and prev_r > 0 and inc:
                    dur  = now - inc.get("since_ts", now)
                    text = (
                        f"✅ <b>{ALERT_LABELS.get(metric, metric)} — Resolved</b>\n\n"
                        f"Was degraded for {_duration(dur)}\n"
                        f'🔗 <a href="{STATUS_PAGE}">View dashboard</a>'
                    )
                    if inc.get("message_id"):
                        tg_edit(inc["message_id"], text, [])
                    del incidents[metric]
                    print(f"[alerter] resolved: {metric}", file=sys.stderr)

                prev_sev[metric] = curr

            _save_state()


# ── Command + callback thread ─────────────────────────────────────────────────

def _kb(view: str) -> list:
    """Standard keyboard: refresh + home buttons."""
    return [[
        {"text": "🔄 Refresh", "callback_data": f"refresh:{view}"},
        {"text": "🏠 Home",    "callback_data": "home:_"},
    ]]


def tg_delete(message_id: int) -> None:
    tg_call("deleteMessage", {"chat_id": CHAT_ID, "message_id": message_id})


def _respond(view: str, d: dict | None, message_id: int | None = None) -> None:
    """Send or edit a command response."""
    if not d:
        text = "❌ Could not reach status API"
    elif view == "status": text = fmt_status(d)
    elif view == "docker": text = fmt_docker(d)
    elif view == "top":    text = fmt_top(d)
    elif view == "f2b":    text = fmt_f2b(d)
    else:                  text = "Unknown view"

    kb = _kb(view)
    if message_id:
        tg_edit(message_id, text, kb)
    else:
        tg_send(text, kb)


WELCOME_TEXT = (
    f"👋 <b>Server Monitor</b>\n\n"
    f"Your server at a glance — tap a button or type a command.\n\n"
    f'🔗 <a href="{STATUS_PAGE}">Open dashboard</a>'
)

WELCOME_KB = [
    [
        {"text": "🖥 Status",    "callback_data": "refresh:status"},
        {"text": "🐳 Docker",    "callback_data": "refresh:docker"},
    ],
    [
        {"text": "⚡ Top",       "callback_data": "refresh:top"},
        {"text": "🛡 Fail2Ban",  "callback_data": "refresh:f2b"},
    ],
]

HELP_TEXT = (
    "<b>Commands</b>\n\n"
    "/status  — server overview\n"
    "/docker  — container list\n"
    "/top     — top processes\n"
    "/f2b     — fail2ban\n"
    "/help    — this message\n\n"
    f'🔗 <a href="{STATUS_PAGE}">Open dashboard</a>'
)


def command_thread_fn() -> None:
    offset = 0
    while True:
        updates = tg_get_updates(offset)
        for upd in updates:
            offset = upd["update_id"] + 1

            # ── Button press ───────────────────────────────────────────────
            if "callback_query" in upd:
                cb     = upd["callback_query"]
                cb_id  = cb["id"]
                data   = cb.get("data", "")
                mid    = cb.get("message", {}).get("message_id")
                action, _, arg = data.partition(":")

                if action == "home":
                    tg_answer(cb_id)
                    tg_delete(mid)
                    tg_send(WELCOME_TEXT, WELCOME_KB)

                elif action == "refresh":
                    tg_answer(cb_id, "Refreshing…")
                    cb_text = cb.get("message", {}).get("text", "")
                    is_welcome = "Server Monitor" in cb_text
                    _respond(arg, _fetch(), None if is_welcome else mid)

                elif action == "ack":
                    with _state_lock:
                        inc = _state.get("incidents", {}).get(arg)
                        if inc and inc.get("message_id") == mid:
                            inc["acknowledged"] = True
                            tg_edit(mid,
                                    _alert_text(arg, inc, inc.get("detail", "")),
                                    _alert_keyboard(arg, inc))
                            _save_state()
                            tg_answer(cb_id, "✓ Acknowledged")
                        else:
                            tg_answer(cb_id, "Alert already resolved.")

                elif action == "snooze":
                    with _state_lock:
                        inc = _state.get("incidents", {}).get(arg)
                        if inc and inc.get("message_id") == mid:
                            inc["snoozed_until"] = time.time() + 3600
                            tg_edit(mid,
                                    _alert_text(arg, inc, inc.get("detail", "")),
                                    _alert_keyboard(arg, inc))
                            _save_state()
                            tg_answer(cb_id, "😴 Snoozed for 1 hour")
                        else:
                            tg_answer(cb_id, "Alert already resolved.")
                else:
                    tg_answer(cb_id)
                continue

            # ── Text command ───────────────────────────────────────────────
            text = upd.get("message", {}).get("text", "")
            if not text.startswith("/"):
                continue
            cmd = text.strip().split()[0].lower().split("@")[0]
            print(f"[bot] {cmd}", file=sys.stderr)

            if cmd == "/start":
                tg_send(WELCOME_TEXT, WELCOME_KB)
            elif cmd == "/help":
                tg_send(HELP_TEXT)
            elif cmd == "/status":
                _respond("status", _fetch())
            elif cmd == "/docker":
                _respond("docker", _fetch())
            elif cmd == "/top":
                _respond("top", _fetch())
            elif cmd in ("/f2b", "/fail2ban"):
                _respond("f2b", _fetch())
            else:
                tg_send(f"Unknown command: <code>{cmd}</code>\n\n{HELP_TEXT}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not BOT_TOKEN or not CHAT_ID:
        print("ERROR: TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set", file=sys.stderr)
        sys.exit(1)

    _load_state()
    print(f"[alerter] start  api={STATUS_URL}  page={STATUS_PAGE}", file=sys.stderr)

    threading.Thread(target=alert_thread_fn,  daemon=True, name="alert").start()
    threading.Thread(target=command_thread_fn, daemon=True, name="cmd").start()

    # keep main thread alive
    while True:
        time.sleep(60)
