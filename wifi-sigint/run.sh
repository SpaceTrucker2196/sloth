#!/usr/bin/env bash
# External WiFi SIGINT runner — monitors RF environment outside home network.
# wlan1 stays in monitor mode throughout; never associates to any AP.
# Usage: ./run.sh [interface] [outdir] [survey_secs] [capture_secs]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/config.sh"

IFACE="${1:-$MONITOR_IFACE}"
OUTDIR="${2:-$SIGINT_OUTDIR}"
SURVEY_SECS="${3:-60}"
CAPTURE_SECS="${4:-120}"

mkdir -p "$OUTDIR"
chmod 777 "$OUTDIR"

STAMP=$(date +%Y%m%d-%H%M%S)
REPORT="$OUTDIR/sigint-report-$STAMP.txt"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$REPORT"; }

log "=== External WiFi SIGINT Run: $STAMP ==="
log "Interface: $IFACE  Survey: ${SURVEY_SECS}s  Capture: ${CAPTURE_SECS}s"
log "Excluding home network: $HOME_SSID"

# ── Pause kismet if it's using our monitor interface ──────────────────────────
KISMET_WAS_RUNNING=0
KISMET_SOURCE_IFACE=$(curl -s -u "$(awk -F= '/httpd_username/{gsub(/ /,"",$2);print $2}' \
  "$HOME/.kismet/kismet_httpd.conf" 2>/dev/null):$(awk -F= '/httpd_password/{gsub(/ /,"",$2);print $2}' \
  "$HOME/.kismet/kismet_httpd.conf" 2>/dev/null)" \
  "http://localhost:2501/datasource/all_sources.json" 2>/dev/null \
  | python3 -c "import json,sys; s=json.load(sys.stdin); print(s[0].get('kismet.datasource.interface','') if s else '')" 2>/dev/null || true)

if systemctl is-active --quiet kismet 2>/dev/null && [[ "$KISMET_SOURCE_IFACE" == "$IFACE" ]]; then
  KISMET_WAS_RUNNING=1
  log ""
  log "── Pausing kismet (releases $IFACE)"
  systemctl stop kismet
  sleep 2
fi

kismet_restore() {
  if [[ "$KISMET_WAS_RUNNING" -eq 1 ]]; then
    log ""
    log "── Resuming kismet"
    systemctl start kismet
  fi
}
trap kismet_restore EXIT

# ── Step 1: Monitor mode setup ────────────────────────────────────────────────
log ""
log "── Step 1: Interface setup"
if bash "$SCRIPT_DIR/00-setup.sh" "$IFACE" >> "$REPORT" 2>&1; then
  log "[setup] OK — $IFACE in monitor mode, not associated"
else
  log "[setup] FAILED — aborting"
  exit 1
fi

# ── Step 2: Passive survey ────────────────────────────────────────────────────
log ""
log "── Step 2: Passive survey (${SURVEY_SECS}s)"
bash "$SCRIPT_DIR/01-survey.sh" "$IFACE" "$SURVEY_SECS" "$OUTDIR" >> "$REPORT" 2>&1 \
  && log "[survey] OK" || log "[survey] completed with warnings"

# Prime a known-active channel before tshark
iw dev "$IFACE" set channel 40 2>/dev/null || true

# ── Step 3: Channel-hopping capture ──────────────────────────────────────────
log ""
log "── Step 3: Full-spectrum capture (${CAPTURE_SECS}s)"
bash "$SCRIPT_DIR/02-capture.sh" "$IFACE" "$CAPTURE_SECS" "$HOP_DWELL" "$OUTDIR" >> "$REPORT" 2>&1 \
  && log "[capture] OK" || log "[capture] completed with warnings"

# ── Step 4: Analyze ───────────────────────────────────────────────────────────
log ""
log "── Step 4: SIGINT analysis"
LATEST_CAP=$(ls -t "$OUTDIR"/capture-*.pcapng 2>/dev/null | head -1)
[[ -z "$LATEST_CAP" ]] && LATEST_CAP=$(ls -t "$OUTDIR"/survey-*-01.cap 2>/dev/null | head -1)

if [[ -n "$LATEST_CAP" ]]; then
  bash "$SCRIPT_DIR/03-analyze.sh" "$LATEST_CAP" | tee -a "$REPORT"
else
  log "[analyze] No capture file found"
fi

log ""
log "=== Run complete ==="
log "Report: $REPORT"
echo "$REPORT"
