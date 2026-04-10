#!/bin/bash
# fail2ban-exporter.sh — writes fail2ban status JSON for the status page.
# Includes current jail stats AND recent ban history from the sqlite3 db.
# Intended to run as root via systemd timer every ~20s.
set -euo pipefail

OUT_DIR="/var/lib/status"
OUT_FILE="${OUT_DIR}/fail2ban.json"
TMP_FILE="${OUT_DIR}/fail2ban.json.tmp"
SQLITE_DB="/var/lib/fail2ban/fail2ban.sqlite3"

mkdir -p "$OUT_DIR"
chmod 755 "$OUT_DIR"

# ---------- Current jail state via fail2ban-client ----------
status_out="$(fail2ban-client status 2>/dev/null || true)"
jails_csv="$(echo "$status_out" | awk -F':' '/Jail list/ {gsub(/^[ \t]+/,"",$2); print $2}')"
IFS=', ' read -r -a jails <<< "$jails_csv"

total_failed=0
total_banned=0
currently_banned=0

tmp_ips="$(mktemp)"
tmp_jails="$(mktemp)"
printf '[' > "$tmp_jails"
printf '[' > "$tmp_ips"
first_jail=1
first_ip=1

for jail in "${jails[@]}"; do
  [ -z "$jail" ] && continue
  jout="$(fail2ban-client status "$jail" 2>/dev/null || true)"

  jf=$(echo "$jout" | awk -F':' '/Currently failed/ {gsub(/[ \t]/,"",$2); print $2}')
  tf=$(echo "$jout" | awk -F':' '/Total failed/ {gsub(/[ \t]/,"",$2); print $2}')
  cb=$(echo "$jout" | awk -F':' '/Currently banned/ {gsub(/[ \t]/,"",$2); print $2}')
  tb=$(echo "$jout" | awk -F':' '/Total banned/ {gsub(/[ \t]/,"",$2); print $2}')
  ips_line=$(echo "$jout" | awk -F':' '/Banned IP list/ {sub(/^[^:]*:[ \t]*/,"",$0); print}')

  jf=${jf:-0}; tf=${tf:-0}; cb=${cb:-0}; tb=${tb:-0}
  total_failed=$(( total_failed + tf ))
  total_banned=$(( total_banned + tb ))
  currently_banned=$(( currently_banned + cb ))

  if [ $first_jail -eq 0 ]; then printf ',' >> "$tmp_jails"; fi
  first_jail=0
  printf '{"name":"%s","currently_failed":%s,"total_failed":%s,"currently_banned":%s,"total_banned":%s}' \
    "$jail" "$jf" "$tf" "$cb" "$tb" >> "$tmp_jails"

  for ip in $ips_line; do
    [ -z "$ip" ] && continue
    if [ $first_ip -eq 0 ]; then printf ',' >> "$tmp_ips"; fi
    first_ip=0
    printf '"%s"' "$ip" >> "$tmp_ips"
  done
done
printf ']' >> "$tmp_jails"
printf ']' >> "$tmp_ips"

jails_json="$(cat "$tmp_jails")"
banned_ips_json="$(cat "$tmp_ips")"
rm -f "$tmp_jails" "$tmp_ips"

# ---------- Recent bans from SQLite (last 20) ----------
# Schema (fail2ban >=0.10): bans(jail, ip, timeofban, data, bantime)
recent_bans_json="[]"
if [ -r "$SQLITE_DB" ] && command -v sqlite3 >/dev/null 2>&1; then
  recent_bans_json="$(sqlite3 -readonly "$SQLITE_DB" \
    "SELECT ip, jail, timeofban, bantime FROM bans ORDER BY timeofban DESC LIMIT 20;" 2>/dev/null \
    | awk -F'|' '
      BEGIN { printf "[" }
      NR>1 { printf "," }
      { printf "{\"ip\":\"%s\",\"jail\":\"%s\",\"timeofban\":%s,\"bantime\":%s}", $1, $2, $3, $4 }
      END { printf "]" }
    ')"
  [ -z "$recent_bans_json" ] && recent_bans_json="[]"
fi

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
now_epoch="$(date +%s)"

cat > "$TMP_FILE" <<EOF
{
  "timestamp": "$ts",
  "now_epoch": $now_epoch,
  "total_failed": $total_failed,
  "currently_banned": $currently_banned,
  "total_banned": $total_banned,
  "banned_ips": $banned_ips_json,
  "jails": $jails_json,
  "recent_bans": $recent_bans_json
}
EOF

mv "$TMP_FILE" "$OUT_FILE"
chmod 644 "$OUT_FILE"
