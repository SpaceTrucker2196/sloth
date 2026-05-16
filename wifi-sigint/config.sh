#!/usr/bin/env bash
# wifi-sigint configuration — sourced by all scripts.
# Edit this file to match your environment.

# Interface to use for external RF monitoring (always stays in monitor mode)
MONITOR_IFACE="wlan1"

# Your home network — excluded from external intel reports
HOME_SSID="SpacetruckerLink"
HOME_BSSIDS=(
  "82:78:41:3f:ec:12"   # SpacetruckerLink WPA2 BSSID
  "82:78:41:5f:ec:12"   # SpacetruckerLink WPA3 hidden BSSID
)

# Your own client MACs (excluded from roving device reports)
OWN_MACS=(
  "24:41:8c:30:97:a1"   # wlan0 Intel built-in
)

# Output directory for captures and reports
SIGINT_OUTDIR="${SIGINT_OUTDIR:-/tmp/wifi-sigint}"

# Channel hop list (2.4 + 5 GHz primaries)
HOP_CHANNELS=(1 6 11 36 40 44 48 100 149 153 157 161)

# Seconds to dwell per channel during tshark capture
HOP_DWELL=2

# ── helpers ───────────────────────────────────────────────────────────────────

# is_home_bssid <mac>  — returns 0 if mac is a home BSSID
is_home_bssid() {
  local mac="${1,,}"
  for b in "${HOME_BSSIDS[@]}"; do
    [[ "${b,,}" == "$mac" ]] && return 0
  done
  return 1
}

# is_own_mac <mac>  — returns 0 if mac is one of our own adapters
is_own_mac() {
  local mac="${1,,}"
  for m in "${OWN_MACS[@]}"; do
    [[ "${m,,}" == "$mac" ]] && return 0
  done
  return 1
}

# home_bssid_grep_pattern  — pipe-separated pattern for grep -Ev
home_bssid_pattern() {
  local IFS='|'
  echo "${HOME_BSSIDS[*]}" | tr 'a-z' 'A-Z'
}
