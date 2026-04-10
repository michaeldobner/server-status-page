#!/bin/bash
# fail2ban-exporter.sh — writes fail2ban status JSON for the status page.
# Includes current jail stats, recent ban history, and GeoIP enrichment.
# GeoIP uses ip-api.com with a persistent local cache (no repeated lookups).
# Intended to run as root via systemd timer every ~20s.
set -euo pipefail

OUT_DIR="/var/lib/status"
OUT_FILE="${OUT_DIR}/fail2ban.json"
TMP_FILE="${OUT_DIR}/fail2ban.json.tmp"
SQLITE_DB="/var/lib/fail2ban/fail2ban.sqlite3"
GEOIP_CACHE="${OUT_DIR}/geoip-cache.json"

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

# Write base JSON (without GeoIP yet)
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

# ---------- GeoIP enrichment (Python, ip-api.com with local cache) ----------
python3 - "$TMP_FILE" "$GEOIP_CACHE" <<'PY'
import json, sys, os, urllib.request, time

tmp_file   = sys.argv[1]
cache_file = sys.argv[2]

# Load base JSON
with open(tmp_file) as f:
    data = json.load(f)

# Load GeoIP cache
cache = {}
if os.path.exists(cache_file):
    try:
        with open(cache_file) as f:
            cache = json.load(f)
    except Exception:
        cache = {}

# Collect all IPs that need lookup
all_ips = set(data.get("banned_ips", []))
for ban in data.get("recent_bans", []):
    ip = ban.get("ip")
    if ip:
        all_ips.add(ip)

def lookup(ip):
    """Call ip-api.com for one IP. Returns dict or None."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org"
        req = urllib.request.Request(url, headers={"User-Agent": "status-page/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.loads(r.read())
        if d.get("status") == "success":
            return {
                "country":      d.get("country", "Unknown"),
                "country_code": d.get("countryCode", ""),
                "city":         d.get("city", ""),
                "isp":          d.get("isp", d.get("org", "")),
            }
    except Exception:
        pass
    return None

def flag(cc):
    """ISO 3166-1 alpha-2 → emoji flag."""
    cc = (cc or "").upper()
    if len(cc) != 2:
        return "🏳"
    return chr(0x1F1E6 + ord(cc[0]) - 65) + chr(0x1F1E6 + ord(cc[1]) - 65)

JAIL_LABELS = {
    "sshd":            "SSH Brute Force",
    "nginx":           "Web Scanner",
    "nginx-http-auth": "Web Auth Attack",
    "apache":          "Web Scanner",
    "apache-auth":     "Web Auth Attack",
    "postfix":         "Mail Attack",
    "dovecot":         "Mail Attack",
    "proftpd":         "FTP Attack",
    "vsftpd":          "FTP Attack",
}

cache_changed = False
for ip in all_ips:
    if ip not in cache:
        result = lookup(ip)
        if result:
            cache[ip] = result
            cache_changed = True
        time.sleep(0.1)   # stay well within 45 req/min

# Enrich recent_bans
enriched_bans = []
for ban in data.get("recent_bans", []):
    ip   = ban.get("ip", "")
    jail = ban.get("jail", "")
    geo  = cache.get(ip, {})
    cc   = geo.get("country_code", "")
    enriched_bans.append({
        **ban,
        "country":     geo.get("country", "Unknown"),
        "country_code": cc,
        "flag":        flag(cc),
        "city":        geo.get("city", ""),
        "isp":         geo.get("isp", ""),
        "jail_label":  JAIL_LABELS.get(jail, "Intrusion Attempt"),
    })
data["recent_bans"] = enriched_bans

# Enrich banned_ips → banned_ips_geo
data["banned_ips_geo"] = []
for ip in data.get("banned_ips", []):
    geo = cache.get(ip, {})
    cc  = geo.get("country_code", "")
    data["banned_ips_geo"].append({
        "ip":          ip,
        "country":     geo.get("country", "Unknown"),
        "country_code": cc,
        "flag":        flag(cc),
    })

# Save updated cache
if cache_changed:
    tmp_cache = cache_file + ".tmp"
    with open(tmp_cache, "w") as f:
        json.dump(cache, f)
    os.replace(tmp_cache, cache_file)

# Write enriched JSON back
with open(tmp_file, "w") as f:
    json.dump(data, f, indent=2)
PY

mv "$TMP_FILE" "$OUT_FILE"
chmod 644 "$OUT_FILE"
