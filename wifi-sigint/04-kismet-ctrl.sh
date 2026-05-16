#!/usr/bin/env bash
# Kismet service control and status.
# Usage: ./04-kismet-ctrl.sh [start|stop|restart|status|logs|tail]
set -euo pipefail

CMD="${1:-status}"
LOGDIR="/home/spacetrucker/kismet-logs"
KISMET_CONF="${HOME}/.kismet/kismet_httpd.conf"
KISMET_URL="http://localhost:2501"

# Read API credentials from user's config (service uses HOME=/home/spacetrucker)
_creds() {
  local user pass
  user=$(awk -F= '/httpd_username/{gsub(/ /,"",$2); print $2}' "$KISMET_CONF" 2>/dev/null)
  pass=$(awk -F= '/httpd_password/{gsub(/ /,"",$2); print $2}' "$KISMET_CONF" 2>/dev/null)
  echo "${user}:${pass}"
}

_api() {
  curl -s -u "$(_creds)" "${KISMET_URL}${1}" 2>/dev/null
}

case "$CMD" in
  start)
    echo "[kismet] Starting service"
    systemctl start kismet
    sleep 3
    systemctl status kismet --no-pager | head -15
    ;;
  stop)
    echo "[kismet] Stopping service"
    systemctl stop kismet
    ;;
  restart)
    echo "[kismet] Restarting service"
    systemctl restart kismet
    sleep 3
    systemctl status kismet --no-pager | head -15
    ;;
  status)
    systemctl status kismet --no-pager
    echo ""
    echo "=== Recent log files ==="
    ls -lht "$LOGDIR"/ 2>/dev/null | head -10
    echo ""
    echo "=== Web UI ==="
    echo "  http://$(hostname -I | awk '{print $1}'):2501"
    echo "  Credentials: spacetrucker / (see ~/.kismet/kismet_httpd.conf)"
    ;;
  logs)
    journalctl -u kismet --no-pager -n 50 | grep -E "INFO|WARN|ERROR|ALERT" | tail -50
    ;;
  tail)
    journalctl -u kismet -f | grep -E "INFO|WARN|ERROR|ALERT"
    ;;
  alerts)
    echo "=== Kismet Alerts (via API) ==="
    _api /alerts/all_alerts.json \
      | python3 -c "
import json, sys
alerts = json.load(sys.stdin)
if not alerts:
    print('  No alerts')
for a in alerts:
    print(f\"  [{a.get('kismet.alert.header','?')}] {a.get('kismet.alert.text','')}\")
" 2>/dev/null || echo "  Could not reach Kismet API"
    ;;
  sources)
    echo "=== Kismet Sources (via API) ==="
    _api /datasource/all_sources.json \
      | python3 -c "
import json, sys
sources = json.load(sys.stdin)
for s in sources:
    status = 'running' if s.get('kismet.datasource.running') else 'STOPPED'
    err    = ' [ERROR]' if s.get('kismet.datasource.error') else ''
    print(f\"  {s.get('kismet.datasource.name','?'):<12}  iface={s.get('kismet.datasource.interface','?'):<8}  pkts={s.get('kismet.datasource.num_packets','?'):<8}  ch={s.get('kismet.datasource.channel','hop'):<6}  {status}{err}\")
" 2>/dev/null || echo "  Could not reach Kismet API"
    ;;
  devices)
    echo "=== Kismet Devices (via API) ==="
    _api "/devices/views/all/devices.json?fields=kismet.device.base.macaddr,kismet.device.base.name,kismet.device.base.last_signal,kismet.device.base.type" \
      | python3 -c "
import json, sys
devs = json.load(sys.stdin)
print(f'  {len(devs)} devices total')
for d in sorted(devs, key=lambda x: x.get('kismet.device.base.last_signal', -999), reverse=True)[:40]:
    print(f\"  {d.get('kismet.device.base.macaddr','?'):<20}  sig={d.get('kismet.device.base.last_signal','?'):>5} dBm  type={d.get('kismet.device.base.type','?'):<20}  {d.get('kismet.device.base.name','')}\")
" 2>/dev/null || echo "  Could not reach Kismet API"
    ;;
  stats)
    echo "=== Kismet System Stats ==="
    _api /system/status.json \
      | python3 -c "
import json, sys, datetime
d = json.load(sys.stdin)
uptime = d['kismet.system.timestamp.sec'] - d['kismet.system.timestamp.start_sec']
print(f\"  version:  {d['kismet.system.version']}\")
print(f\"  uptime:   {datetime.timedelta(seconds=uptime)}\")
print(f\"  devices:  {d['kismet.system.devices.count']}\")
print(f\"  memory:   {d['kismet.system.memory.rss']} kB\")
" 2>/dev/null || echo "  Could not reach Kismet API"
    ;;
  *)
    echo "Usage: $0 [start|stop|restart|status|logs|tail|alerts|sources|devices|stats]"
    exit 1
    ;;
esac
