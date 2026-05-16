#!/usr/bin/env bash
# External RF environment analysis — home network filtered out.
# Reports: foreign APs, roving clients, PNL leaks, anomalies.
# Usage: ./03-analyze.sh <capture_file> [oui_db]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

CAPFILE="${1:-}"
OUIDB="${2:-/var/lib/ieee-data/oui.txt}"

if [[ -z "$CAPFILE" || ! -f "$CAPFILE" ]]; then
  echo "Usage: $0 <capture_file.pcapng|.cap>"
  exit 1
fi

FRAMES=$(tshark -r "$CAPFILE" 2>/dev/null | wc -l)
echo "=== External WiFi SIGINT: $(basename "$CAPFILE") ==="
echo "    Frames: $FRAMES  |  Home network excluded: $HOME_SSID"
echo ""

TMP=$(mktemp)
tshark -r "$CAPFILE" 2>/dev/null > "$TMP"

# ── OUI lookup ────────────────────────────────────────────────────────────────
oui_lookup() {
  local mac="${1,,}"
  if ! [[ "$mac" =~ ^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}: ]]; then
    echo "unknown"; return
  fi
  local first=$(( 16#$(echo "$mac" | cut -c1-2) ))
  if (( first & 0x02 )); then echo "RANDOMIZED-MAC"; return; fi
  local prefix
  prefix=$(echo "$mac" | awk -F: '{printf "%s%s%s", toupper($1), toupper($2), toupper($3)}')
  local vendor
  vendor=$(grep "^$prefix" "$OUIDB" 2>/dev/null | head -1 | cut -f3-)
  echo "${vendor:-unknown}"
}

# ── Foreign Access Points ─────────────────────────────────────────────────────
echo "=== FOREIGN ACCESS POINTS ==="
FOREIGN_APS=()
while IFS=" " read -r bssid ssid; do
  is_home_bssid "$bssid" && continue
  vendor=$(oui_lookup "$bssid")
  printf "  %-20s  %-30s  %s\n" "$bssid" "$ssid" "$vendor"
  FOREIGN_APS+=("$bssid")
done < <(grep "Beacon frame" "$TMP" | awk '{print $3, $NF}' | sort -u)

[[ ${#FOREIGN_APS[@]} -eq 0 ]] && echo "  None detected"

# ── Clients on foreign networks ───────────────────────────────────────────────
echo ""
echo "=== CLIENTS ON FOREIGN NETWORKS ==="
FOREIGN_AP_PAT=""
if [[ ${#FOREIGN_APS[@]} -gt 0 ]]; then
  FOREIGN_AP_PAT=$(printf '%s\n' "${FOREIGN_APS[@]}" | paste -sd'|')
fi

if [[ -n "$FOREIGN_AP_PAT" ]]; then
  grep -iE "$FOREIGN_AP_PAT" "$TMP" | awk '{print $3; print $5}' \
    | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' | sort -u \
    | while read -r mac; do
      is_home_bssid "$mac" && continue
      is_own_mac "$mac" && continue
      vendor=$(oui_lookup "$mac")
      count=$(grep -ci "$mac" "$TMP" || true)
      printf "  %-20s  frames=%-5s  %s\n" "$mac" "$count" "$vendor"
    done
else
  echo "  No foreign APs seen — no associated clients"
fi

# ── Roving / unassociated devices (probe requests) ────────────────────────────
echo ""
echo "=== ROVING DEVICES & PNL LEAKS (probe requests) ==="
FOUND_PROBE=0
while IFS=" " read -r mac ssid; do
  is_own_mac "$mac" && continue
  # Skip probes from home AP or to home SSID
  is_home_bssid "$mac" && continue
  [[ "${ssid,,}" == *"${HOME_SSID,,}"* ]] && continue
  vendor=$(oui_lookup "$mac")
  printf "  %-20s  desired=%-30s  %s\n" "$mac" "$ssid" "$vendor"
  FOUND_PROBE=1
done < <(grep "Probe Request" "$TMP" | awk '{print $3, $NF}' | sort -u)
[[ "$FOUND_PROBE" -eq 0 ]] && echo "  None captured"

# ── All non-home unique stations ──────────────────────────────────────────────
echo ""
echo "=== ALL EXTERNAL STATIONS ==="
FOUND_STA=0
awk '{print $3; print $5}' "$TMP" \
  | grep -E '^([0-9a-f]{2}:){5}[0-9a-f]{2}$' \
  | sort -u | while read -r mac; do
  is_home_bssid "$mac" && continue
  is_own_mac   "$mac" && continue
  vendor=$(oui_lookup "$mac")
  count=$(grep -c "$mac" "$TMP" || true)
  printf "  %-20s  frames=%-5s  %s\n" "$mac" "$count" "$vendor"
  FOUND_STA=1
done
# (shell subshell means FOUND_STA won't propagate — just omit the "none" fallback)

# ── AWDL (Apple peer-to-peer) ─────────────────────────────────────────────────
echo ""
echo "=== AWDL (Apple AirDrop/AirPlay/Handoff) ==="
AWDL_MACS=$(grep "AWDL" "$TMP" | awk '{print $3}' | sort -u)
if [[ -n "$AWDL_MACS" ]]; then
  echo "$AWDL_MACS" | while read -r mac; do
    count=$(grep -c "AWDL" "$TMP" || true)
    printf "  %-20s  %s frames\n" "$mac" "$count"
  done
else
  echo "  None"
fi

# ── Deauth / Disassoc ─────────────────────────────────────────────────────────
echo ""
echo "=== DEAUTH / DISASSOC (attack indicator) ==="
COUNT=$(grep -cE "Deauthentication|Disassociation" "$TMP" || true)
if [[ "${COUNT:-0}" -gt 0 ]]; then
  echo "  ⚠ $COUNT frames detected"
  grep -E "Deauthentication|Disassociation" "$TMP" \
    | awk '{printf "  t=%-12s  %s → %s\n", $2, $3, $5}' | head -20
else
  echo "  None"
fi

# ── EAPOL ─────────────────────────────────────────────────────────────────────
echo ""
echo "=== EAPOL / WPA HANDSHAKES ==="
COUNT=$(tshark -r "$CAPFILE" -Y eapol 2>/dev/null | wc -l | tr -d '[:space:]')
if [[ "${COUNT:-0}" -gt 0 ]]; then
  echo "  ⚠ $COUNT EAPOL frames"
  tshark -r "$CAPFILE" -Y eapol 2>/dev/null \
    | awk '{printf "  t=%-12s  %s → %s\n", $2, $3, $5}' | head -20
else
  echo "  None"
fi

# ── Broadcast bursts ──────────────────────────────────────────────────────────
echo ""
echo "=== BROADCAST BURST ANOMALIES (>5 frames <50ms) ==="
awk '$5 == "Broadcast" {print $2, $3}' "$TMP" | awk '
{
  t=$1; mac=$2
  if (mac == prev_mac && t - prev_t < 0.05) {
    burst[mac]++
    if (burst[mac] == 5) printf "  %-20s  burst at t=%s\n", mac, t
  } else { burst[mac]=0 }
  prev_mac=mac; prev_t=t
}' 2>/dev/null || true

# ── Channel distribution ──────────────────────────────────────────────────────
echo ""
echo "=== CHANNEL DISTRIBUTION ==="
tshark -r "$CAPFILE" -T fields -e radiotap.channel.freq 2>/dev/null \
  | sort | uniq -c | sort -rn \
  | awk '{printf "  %5d frames  %s MHz\n", $1, $2}' | head -15

rm -f "$TMP"
echo ""
echo "[analyze] Complete"
