#!/usr/bin/env bash
# Put MONITOR_IFACE into monitor mode (or verify it already is).
# Never associates the interface — it stays passive.
# Usage: ./00-setup.sh [interface]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"
IFACE="${1:-$MONITOR_IFACE}"

check_tool() { command -v "$1" &>/dev/null || { echo "MISSING: $1"; exit 1; }; }
check_tool airodump-ng
check_tool tshark
check_tool iw

# If already in monitor mode, nothing to do
CURRENT=$(iw dev "$IFACE" info 2>/dev/null | awk '/type/{print $2}')
if [[ "$CURRENT" == "monitor" ]]; then
  echo "[setup] $IFACE already in monitor mode — leaving it alone"
  iw dev "$IFACE" info
  exit 0
fi

echo "[setup] Putting $IFACE into monitor mode"
ip link set "$IFACE" down
iw dev "$IFACE" set type managed 2>/dev/null || true
ip link set "$IFACE" up
ip link set "$IFACE" down
iw dev "$IFACE" set type monitor
ip link set "$IFACE" up
sleep 1

MODE=$(iw dev "$IFACE" info | awk '/type/{print $2}')
if [[ "$MODE" != "monitor" ]]; then
  echo "ERROR: $IFACE ended up in mode '$MODE', expected monitor"
  exit 1
fi

echo "[setup] $IFACE is now in monitor mode"
iw dev "$IFACE" info
