#!/bin/bash
# restic-exporter.sh — writes /var/lib/status/restic.json after each backup.
# Called via ExecStartPost in restic-backup.service.
# Run as root.
set -euo pipefail

OUT_DIR="/var/lib/status"
OUT_FILE="${OUT_DIR}/restic.json"
TMP_FILE="${OUT_DIR}/restic.json.tmp"

mkdir -p "$OUT_DIR"
chmod 755 "$OUT_DIR"

python3 - <<'PY' > "$TMP_FILE"
import json, subprocess, datetime, re, os

LOG_FILE   = "/var/log/restic-backup.log"
REPO       = "/var/backups/restic-repo"
PW_FILE    = "/root/.restic-password"

now = datetime.datetime.now(datetime.timezone.utc)
status       = "unknown"
last_run_ts  = None
last_run_iso = None
age_hours    = None
dropbox_synced = False
last_error   = None

# ── Parse log ────────────────────────────────────────────────────────────────
if os.path.exists(LOG_FILE):
    with open(LOG_FILE) as f:
        lines = f.readlines()

    # Find last backup block (starts at BACKUP GESTARTET)
    last_start = None
    for i, line in enumerate(lines):
        if "BACKUP GESTARTET" in line:
            last_start = i

    if last_start is not None:
        block = lines[last_start:]

        # Timestamp from BACKUP FERTIG line
        for line in reversed(block):
            m = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\].*BACKUP FERTIG', line)
            if m:
                dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                last_run_iso = dt.isoformat()
                last_run_ts  = int(dt.timestamp())
                delta = now.replace(tzinfo=None) - dt
                age_hours = round(delta.total_seconds() / 3600, 1)
                break

        has_fertig   = any("BACKUP FERTIG"            in l for l in block)
        has_error    = any("❌"                        in l for l in block)
        dropbox_ok   = any("✅ Dropbox Sync erfolgreich" in l for l in block)
        dropbox_fail = any("❌ Dropbox Sync"            in l for l in block)
        dropbox_synced = dropbox_ok and not dropbox_fail

        if has_fertig and not has_error:
            status = "ok"
        elif has_fertig and has_error:
            status = "warn"
            errs = [l.strip() for l in block if "❌" in l]
            last_error = errs[-1] if errs else None
        else:
            status = "error"
            errs = [l.strip() for l in block if "❌" in l]
            last_error = errs[-1] if errs else "Backup did not complete"

# Warn if last backup is older than 25 h
if age_hours is not None and age_hours > 25 and status == "ok":
    status = "warn"
    last_error = f"Last backup {age_hours:.1f}h ago (expected every 12h)"

# ── Snapshot count ────────────────────────────────────────────────────────────
snapshot_count = 0
try:
    out = subprocess.check_output(
        ["restic", "--password-file", PW_FILE, "-r", REPO,
         "snapshots", "--json", "--quiet"],
        text=True, stderr=subprocess.DEVNULL, timeout=30,
    )
    snapshot_count = len(json.loads(out))
except Exception:
    pass

# ── Repo size on disk ─────────────────────────────────────────────────────────
repo_size_mb = 0.0
try:
    total = sum(
        os.path.getsize(os.path.join(dp, fn))
        for dp, _, fns in os.walk(REPO)
        for fn in fns
    )
    repo_size_mb = round(total / 1024 / 1024, 1)
except Exception:
    pass

data = {
    "timestamp":      now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "available":      True,
    "status":         status,
    "last_run_ts":    last_run_ts,
    "last_run_iso":   last_run_iso,
    "age_hours":      age_hours,
    "snapshot_count": snapshot_count,
    "repo_size_mb":   repo_size_mb,
    "dropbox_synced": dropbox_synced,
    "last_error":     last_error,
}
print(json.dumps(data))
PY

mv "$TMP_FILE" "$OUT_FILE"
chmod 644 "$OUT_FILE"
