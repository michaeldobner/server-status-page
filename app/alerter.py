"""
Telegram alerter + interactive bot for server status page.

Two concurrent background tasks:
  alert_loop:   Every 30 s, collect metrics, detect severity transitions, push notifications.
  command_loop: Long-polls Telegram getUpdates for /commands and responds with formatted data.

Config comes from env vars:
  TELEGRAM_BOT_TOKEN   — token from @BotFather
  TELEGRAM_CHAT_ID     — target chat/user id (send any message to the bot, then check getUpdates)
"""
from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

import httpx
import yaml

log = logging.getLogger(__name__)

THRESHOLDS_PATH = Path(__file__).parent / "thresholds.yaml"

SEV_EMOJI: dict[str, str] = {
    "ok":   "✅",
    "warn": "⚠️",
    "crit": "🔴",
    "off":  "⚫",
}
SEV_ORDER: dict[str, int] = {"ok": 0, "off": 0, "warn": 1, "crit": 2}

ALERT_LABELS: dict[str, str] = {
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

def _thresholds() -> dict:
    try:
        return yaml.safe_load(THRESHOLDS_PATH.read_text()) or {}
    except Exception:
        return {}


def _fmt_bytes(b: float) -> str:
    if b >= 1024 ** 3:
        return f"{b / 1024 ** 3:.1f} GB/s"
    if b >= 1024 ** 2:
        return f"{b / 1024 ** 2:.1f} MB/s"
    if b >= 1024:
        return f"{b / 1024:.1f} KB/s"
    return f"{b:.0f} B/s"


def _fmt_uptime(seconds: int) -> str:
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    if d > 0:
        return f"{d}d {h}h"
    if h > 0:
        return f"{h}h {m}m"
    return f"{m}m"


def _age_str(age_seconds: int) -> str:
    if age_seconds < 3600:
        return f"{age_seconds // 60}m ago"
    if age_seconds < 86400:
        return f"{age_seconds // 3600}h ago"
    return f"{age_seconds // 86400}d ago"


# ---------------------------------------------------------------------------
# Message formatters
# ---------------------------------------------------------------------------

def fmt_status(data: dict) -> str:
    sev = data.get("severity", {})
    host = data.get("host", {})
    ts = data.get("timesync", {})
    dk = data.get("docker", {})
    n = data.get("n8n", {})
    f = data.get("fail2ban", {})

    overall = sev.get("overall", "?")
    lines = [
        f"<b>🖥 Server Status</b>  {SEV_EMOJI.get(overall, '?')} <b>{overall.upper()}</b>",
        "",
        "<b>Host</b>",
        f"  CPU:    {SEV_EMOJI.get(sev.get('cpu','ok'))} {host.get('cpu_percent', 0):.1f}%",
    ]

    ram = host.get("ram", {})
    lines.append(
        f"  RAM:    {SEV_EMOJI.get(sev.get('ram','ok'))} "
        f"{ram.get('percent', 0):.1f}%  ({ram.get('used_gb', 0)}/{ram.get('total_gb', 0)} GB)"
    )

    disk = host.get("disk", {})
    lines.append(
        f"  Disk:   {SEV_EMOJI.get(sev.get('disk','ok'))} "
        f"{disk.get('percent', 0):.1f}%  ({disk.get('used_gb', 0)}/{disk.get('total_gb', 0)} GB)"
    )

    load = host.get("load_avg", [0, 0, 0])
    lines.append(
        f"  Load:   {SEV_EMOJI.get(sev.get('load','ok'))} "
        f"{load[0]}/{load[1]}/{load[2]}  ({host.get('cpu_count', 1)} cores)"
    )

    net = host.get("network", {})
    lines.append(
        f"  Net:    {SEV_EMOJI.get(sev.get('net','ok'))} "
        f"↓{_fmt_bytes(net.get('rx_bytes_s', 0))}  ↑{_fmt_bytes(net.get('tx_bytes_s', 0))}"
    )

    lines.append(f"  Uptime: {_fmt_uptime(host.get('uptime_seconds', 0))}")

    if ts.get("available"):
        off = ts.get("offset_ms", 0) or 0
        lines.append(
            f"  Clock:  {SEV_EMOJI.get(sev.get('timesync','ok'))} {off:.1f} ms offset"
        )

    lines += [
        "",
        f"<b>Docker</b>  {SEV_EMOJI.get(sev.get('docker','ok'))}  "
        f"{dk.get('running', 0)}/{dk.get('total', 0)} running",
        "",
        f"<b>N8N</b>  {SEV_EMOJI.get(sev.get('n8n','ok'))}  "
        + ("up" if n.get("reachable") else "DOWN")
        + f"  {n.get('latency_ms', 0)} ms",
        "",
        f"<b>Fail2Ban</b>  {SEV_EMOJI.get(sev.get('fail2ban','ok'))}  "
        f"{f.get('currently_banned', 0)} banned now  /  {f.get('total_banned', 0)} total",
    ]

    return "\n".join(lines)


def fmt_docker(data: dict) -> str:
    dk = data.get("docker", {})
    if not dk.get("available"):
        return "❌ Docker unavailable"

    lines = [f"<b>🐳 Docker</b>  {dk.get('running', 0)}/{dk.get('total', 0)} running", ""]
    for c in dk.get("containers", []):
        state = c.get("state", "?")
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

        h_str = f" ({health})" if health not in ("-", "healthy") else ""
        up_str = f"  •  {uptime}" if uptime else ""
        lines.append(f"{dot} <code>{c.get('name', '?')}</code>{h_str}{up_str}")

    return "\n".join(lines)


def fmt_top(data: dict) -> str:
    top = data.get("top", {})
    if not top.get("available"):
        return "❌ Top data unavailable"

    lines = ["<b>⚡ Top Processes</b>", "", "<b>By CPU:</b>"]
    for p in top.get("by_cpu", []):
        cmd = (p.get("cmd") or "")[:45]
        lines.append(
            f"  {p.get('cpu', 0):.1f}% cpu  {p.get('mem', 0):.1f}% mem  "
            f"<code>{cmd}</code>"
        )

    lines += ["", "<b>By RAM:</b>"]
    for p in top.get("by_mem", []):
        cmd = (p.get("cmd") or "")[:45]
        lines.append(
            f"  {p.get('mem', 0):.1f}% mem  {p.get('cpu', 0):.1f}% cpu  "
            f"<code>{cmd}</code>"
        )

    return "\n".join(lines)


def fmt_f2b(data: dict) -> str:
    f = data.get("fail2ban", {})
    if not f.get("available"):
        return "❌ Fail2Ban data unavailable"

    lines = [
        "<b>🛡 Fail2Ban</b>",
        f"  Currently banned: <b>{f.get('currently_banned', 0)}</b>",
        f"  Total banned:     {f.get('total_banned', 0)}",
        f"  Total failed:     {f.get('total_failed', 0)}",
    ]

    jails = f.get("jails", [])
    if jails:
        lines += ["", "<b>Jails:</b>"]
        for j in jails:
            lines.append(
                f"  {j.get('name','?')}: "
                f"{j.get('currently_banned',0)} banned  "
                f"{j.get('currently_failed',0)} failing"
            )

    banned_ips = f.get("banned_ips", [])
    if banned_ips:
        lines += ["", "<b>Currently banned IPs:</b>"]
        for ip in banned_ips[:10]:
            lines.append(f"  • <code>{ip}</code>")
        if len(banned_ips) > 10:
            lines.append(f"  … and {len(banned_ips) - 10} more")

    recent = f.get("recent_bans", [])
    if recent:
        lines += ["", "<b>Recent bans:</b>"]
        now_epoch = int(f.get("now_epoch", time.time()))
        for ban in recent[:8]:
            ip = ban.get("ip", "?")
            jail = ban.get("jail", "?")
            age_s = now_epoch - int(ban.get("timeofban", now_epoch))
            lines.append(f"  <code>{ip}</code>  [{jail}]  {_age_str(age_s)}")

    return "\n".join(lines)


def _alert_detail(metric: str, data: dict) -> str:
    """Return a short detail line for an alert message."""
    host = data.get("host", {})
    if metric == "cpu":
        return f"CPU: {host.get('cpu_percent', 0):.1f}%"
    if metric == "ram":
        r = host.get("ram", {})
        return f"RAM: {r.get('percent', 0):.1f}%  ({r.get('used_gb', 0)}/{r.get('total_gb', 0)} GB)"
    if metric == "disk":
        d = host.get("disk", {})
        return f"Disk: {d.get('percent', 0):.1f}%  ({d.get('used_gb', 0)}/{d.get('total_gb', 0)} GB)"
    if metric == "swap":
        s = host.get("swap", {})
        return f"Swap: {s.get('percent', 0):.1f}%  ({s.get('used_gb', 0)}/{s.get('total_gb', 0)} GB)"
    if metric == "load":
        load = host.get("load_avg", [0, 0, 0])
        cores = host.get("cpu_count", 1)
        return f"Load: {load[0]}/{load[1]}/{load[2]}  ({cores} cores)"
    if metric == "net":
        net = host.get("network", {})
        return (
            f"↓{_fmt_bytes(net.get('rx_bytes_s', 0))}  "
            f"↑{_fmt_bytes(net.get('tx_bytes_s', 0))}"
        )
    if metric == "docker":
        dk = data.get("docker", {})
        return f"Running: {dk.get('running', 0)}/{dk.get('total', 0)} containers"
    if metric == "n8n":
        n = data.get("n8n", {})
        if not n.get("reachable"):
            err = n.get("error", "")
            return f"N8N unreachable — {err[:80]}" if err else "N8N unreachable"
        return f"N8N latency: {n.get('latency_ms', 0)} ms"
    if metric == "fail2ban":
        f2b = data.get("fail2ban", {})
        return f"Currently banned: {f2b.get('currently_banned', 0)}"
    if metric == "timesync":
        ts = data.get("timesync", {})
        return f"Clock offset: {ts.get('offset_ms', 0):.1f} ms"
    return ""


# ---------------------------------------------------------------------------
# Telegram client
# ---------------------------------------------------------------------------

class TelegramBot:
    def __init__(self, token: str, chat_id: str) -> None:
        self.token = token
        self.chat_id = str(chat_id)
        self._offset = 0
        self._http: httpx.AsyncClient | None = None

    def _url(self, method: str) -> str:
        return f"https://api.telegram.org/bot{self.token}/{method}"

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(timeout=40.0)
        return self._http

    async def send(self, text: str, parse_mode: str = "HTML") -> bool:
        try:
            c = await self._client()
            r = await c.post(self._url("sendMessage"), json={
                "chat_id": self.chat_id,
                "text": text,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            })
            if r.status_code != 200:
                log.warning("Telegram sendMessage returned %d: %s", r.status_code, r.text[:200])
                return False
            return True
        except Exception as e:
            log.error("Telegram send failed: %s", e)
            return False

    async def get_updates(self) -> list[dict]:
        """Long-poll for new messages (30 s timeout)."""
        try:
            c = await self._client()
            r = await c.get(self._url("getUpdates"), params={
                "timeout": 30,
                "offset": self._offset,
                "allowed_updates": ["message"],
            })
            if r.status_code != 200:
                return []
            updates: list[dict] = r.json().get("result", [])
            if updates:
                self._offset = updates[-1]["update_id"] + 1
            return updates
        except Exception as e:
            log.warning("getUpdates error: %s", e)
            return []

    async def close(self) -> None:
        if self._http and not self._http.is_closed:
            await self._http.aclose()


# ---------------------------------------------------------------------------
# Alert manager
# ---------------------------------------------------------------------------

class AlertManager:
    def __init__(self, bot: TelegramBot, collect_fn: Callable[[], Awaitable[dict]]) -> None:
        self.bot = bot
        self.collect_fn = collect_fn
        self._prev: dict[str, str] = {}
        self._last_alert_time: dict[str, float] = {}

    def _cooldown_s(self) -> int:
        return _thresholds().get("alerts", {}).get("cooldown_minutes", 15) * 60

    async def _init_state(self) -> None:
        """Capture initial severity without firing alerts."""
        try:
            data = await self.collect_fn()
            sev = data.get("severity", {})
            for m in ALERT_LABELS:
                self._prev[m] = sev.get(m, "ok")
            log.info("Alerter ready — initial state: %s", self._prev)
        except Exception as e:
            log.error("Alerter init failed: %s", e)

    async def check(self) -> None:
        try:
            data = await self.collect_fn()
        except Exception as e:
            log.error("collect_fn error in alerter: %s", e)
            return

        sev = data.get("severity", {})
        now = time.time()
        cooldown = self._cooldown_s()

        for metric, label in ALERT_LABELS.items():
            curr = sev.get(metric, "ok")
            prev = self._prev.get(metric, "ok")

            if curr == prev:
                continue

            curr_rank = SEV_ORDER.get(curr, 0)
            prev_rank = SEV_ORDER.get(prev, 0)

            if curr_rank > prev_rank:
                # Degraded — check cooldown
                if now - self._last_alert_time.get(metric, 0) < cooldown:
                    self._prev[metric] = curr
                    continue
                self._last_alert_time[metric] = now
                emoji = SEV_EMOJI.get(curr, "?")
                detail = _alert_detail(metric, data)
                msg = (
                    f"{emoji} <b>ALERT: {label} → {curr.upper()}</b>"
                    + (f"\n{detail}" if detail else "")
                )
                await self.bot.send(msg)
                log.info("Alert sent: %s %s → %s", metric, prev, curr)

            elif curr == "ok" and prev_rank > 0:
                # Recovered
                msg = f"✅ <b>RECOVERED: {label} is back to OK</b>"
                await self.bot.send(msg)
                log.info("Recovery sent: %s", metric)

            self._prev[metric] = curr

    async def run(self) -> None:
        await asyncio.sleep(15)       # let the app fully start
        await self._init_state()
        while True:
            try:
                await self.check()
            except Exception as e:
                log.error("Alert loop error: %s", e)
            await asyncio.sleep(30)


# ---------------------------------------------------------------------------
# Command handler
# ---------------------------------------------------------------------------

HELP_TEXT = """\
<b>Available commands:</b>

/status  — full server overview
/docker  — container list
/top     — top processes (CPU + RAM)
/f2b     — fail2ban jails + recent bans
/help    — this message\
"""


async def _handle_command(
    bot: TelegramBot,
    collect_fn: Callable[[], Awaitable[dict]],
    text: str,
) -> None:
    # Strip /cmd@BotName form
    cmd = text.strip().split()[0].lower().split("@")[0]

    if cmd in ("/help", "/start"):
        await bot.send(HELP_TEXT)
        return

    # All other commands need fresh data
    try:
        data = await collect_fn()
    except Exception as e:
        await bot.send(f"❌ Error collecting data: {e}")
        return

    if cmd == "/status":
        await bot.send(fmt_status(data))
    elif cmd == "/docker":
        await bot.send(fmt_docker(data))
    elif cmd == "/top":
        await bot.send(fmt_top(data))
    elif cmd in ("/f2b", "/fail2ban"):
        await bot.send(fmt_f2b(data))
    else:
        await bot.send(f"Unknown command: <code>{cmd}</code>\n\n" + HELP_TEXT)


async def _command_loop(
    bot: TelegramBot,
    collect_fn: Callable[[], Awaitable[dict]],
) -> None:
    while True:
        try:
            updates = await bot.get_updates()
            for upd in updates:
                text: str = upd.get("message", {}).get("text", "")
                if text.startswith("/"):
                    asyncio.create_task(_handle_command(bot, collect_fn, text))
        except Exception as e:
            log.error("Command loop error: %s", e)
            await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def start(
    collect_fn: Callable[[], Awaitable[dict]],
    token: str,
    chat_id: str,
) -> None:
    """
    Start alert monitor + Telegram bot.
    Call once at app startup; runs forever as two concurrent tasks.
    """
    if not token or not chat_id:
        log.warning(
            "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set — alerter disabled"
        )
        return

    bot = TelegramBot(token, chat_id)
    await bot.send("🚀 <b>Status page started</b> — bot online.\nSend /help for commands.")

    manager = AlertManager(bot, collect_fn)

    try:
        await asyncio.gather(
            manager.run(),
            _command_loop(bot, collect_fn),
        )
    finally:
        await bot.close()
