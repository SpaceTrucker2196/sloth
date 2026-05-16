#!/usr/bin/env bash
# Channel-hopping full-spectrum tshark capture.
# Writes: capture-<timestamp>.pcapng
# Usage: ./02-capture.sh [interface] [duration_seconds] [dwell_seconds] [outdir]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

IFACE="${1:-$MONITOR_IFACE}"
DURATION="${2:-120}"
DWELL="${3:-$HOP_DWELL}"
OUTDIR="${4:-$SIGINT_OUTDIR}"
STAMP=$(date +%Y%m%d-%H%M%S)
OUTFILE="$OUTDIR/capture-$STAMP.pcapng"

mkdir -p "$OUTDIR"
chmod 777 "$OUTDIR"

echo "[capture] Starting ${DURATION}s channel-hopping capture on $IFACE"
echo "[capture] Channels: ${HOP_CHANNELS[*]}"
echo "[capture] Output: $OUTFILE"

channel_hop() {
  while true; do
    for ch in "${HOP_CHANNELS[@]}"; do
      iw dev "$IFACE" set channel "$ch" 2>/dev/null || true
      sleep "$DWELL"
    done
  done
}
channel_hop &
HOPPID=$!

tshark -i "$IFACE" -w "$OUTFILE" -a duration:"$DURATION" 2>/dev/null

kill "$HOPPID" 2>/dev/null || true

FRAMES=$(tshark -r "$OUTFILE" 2>/dev/null | wc -l)
SIZE=$(du -sh "$OUTFILE" | cut -f1)
echo "[capture] Done — $FRAMES frames, $SIZE  →  $OUTFILE"
