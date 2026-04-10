#!/bin/bash
# top-exporter.sh — writes top-5 processes by CPU and by RAM to JSON.
# Uses python3 for robust JSON generation.
# Run as root (or any user that can read /proc) via systemd timer every 10s.
set -euo pipefail

OUT_DIR="/var/lib/status"
OUT_FILE="${OUT_DIR}/top.json"
TMP_FILE="${OUT_DIR}/top.json.tmp"

mkdir -p "$OUT_DIR"
chmod 755 "$OUT_DIR"

python3 - <<'PY' > "$TMP_FILE"
import json, subprocess, datetime

def top(sort_key, n=5):
    out = subprocess.check_output(
        ["ps", "-eo", "pid,user:24,pcpu,pmem,args",
         f"--sort=-{sort_key}", "--no-headers"],
        text=True
    )
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid, user, pcpu, pmem, cmd = parts
        try:
            pid = int(pid)
            pcpu = float(pcpu)
            pmem = float(pmem)
        except ValueError:
            continue
        rows.append({
            "pid": pid,
            "user": user[:24],
            "cpu": pcpu,
            "mem": pmem,
            "cmd": cmd[:80],
        })
        if len(rows) >= n:
            break
    return rows

data = {
    "timestamp": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "by_cpu": top("pcpu"),
    "by_mem": top("pmem"),
}
print(json.dumps(data))
PY

mv "$TMP_FILE" "$OUT_FILE"
chmod 644 "$OUT_FILE"
