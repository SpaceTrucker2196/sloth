#!/usr/bin/env bash
# Passive AP + client survey — reports only FOREIGN networks and roving devices.
# Home network (SpacetruckerLink) is filtered out.
# Usage: ./01-survey.sh [interface] [duration_seconds] [outdir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

IFACE="${1:-$MONITOR_IFACE}"
DURATION="${2:-60}"
OUTDIR="${3:-$SIGINT_OUTDIR}"
STAMP=$(date +%Y%m%d-%H%M%S)
PREFIX="$OUTDIR/survey-$STAMP"

mkdir -p "$OUTDIR"

echo "[survey] Starting ${DURATION}s passive survey on $IFACE (2.4+5 GHz)"
echo "[survey] Home network excluded: $HOME_SSID  (${HOME_BSSIDS[*]})"

timeout "$DURATION" airodump-ng \
  --band abg \
  --output-format csv,pcap \
  -w "$PREFIX" \
  "$IFACE" >/dev/null 2>&1 || true

CSV="${PREFIX}-01.csv"
CAP="${PREFIX}-01.cap"

echo ""
echo "=== FOREIGN ACCESS POINTS ==="
awk -F',' '
  NR>2 && /[0-9a-fA-F]{2}:/ && !/Station MAC/ {
    gsub(/ /,"",$1); gsub(/ /,"",$4); gsub(/ /,"",$6); gsub(/ /,"",$14)
    print $1, $4, $6, $14
  }
' "$CSV" 2>/dev/null | while read -r bssid ch enc ssid; do
  # Skip home BSSIDs and malformed entries (ch < 0 = client rows leaked in)
  is_home_bssid "$bssid" && continue
  [[ "$ch" =~ ^-[0-9] ]] && continue
  printf "  %-20s  ch=%-4s  enc=%-18s  ssid=%s\n" "$bssid" "$ch" "$enc" "$ssid"
done

echo ""
echo "=== ROVING & UNASSOCIATED CLIENTS (not on home network) ==="
awk -F',' '
  /Station MAC/{found=1;next}
  found && NF>5 {
    gsub(/ /,"",$1); gsub(/ /,"",$6); gsub(/ /,"",$7)
    print $1, $6, $7
  }
' "$CSV" 2>/dev/null | while read -r mac ap probed; do
  is_own_mac "$mac" && continue
  is_home_bssid "$ap" && continue
  printf "  %-20s  ap=%-20s  probed=%s\n" "$mac" "${ap:-(unassociated)}" "$probed"
done

echo ""
echo "[survey] Files: $CSV  $CAP"
