# Capture scope: Monitor / Hybrid / Local

**Summary**: slothweb's top bar carries a three-way switch, Monitor |
Hybrid | Local, that filters every view by how the data was captured:
the passive monitor-mode radio (and the BLE receivers), the host's own
connected interfaces, or both. sloth's records carry no capture path,
so slothweb decides each datum's scope from what it is (record type,
alert type, metric, interface name, a device's `DEV_SRC_*` bits) in one
table, `web/src/web_scope.c`, held by tests to the files it classifies.
Every `/api` route takes `scope=`; Hybrid is the answer without it,
byte for byte.

**Sources**: `web/src/web_scope.h`, `web/src/web_scope.c`,
`web/src/web_routes.c`, `web/src/web_live.c`, `web/src/web_query.c`,
`web/src/web_slothdb.c`, `web/src/web_metrics.c`, `web/ui/app.js`,
`web/tests/test_scope.c`, `src/jsonl.c` (`sensor_health`),
`src/device_risk.c`, `include/sloth.h` (`DEV_SRC_*`, `CAM_SIG_*`),
`include/sloth_alerts.def`, owner request 2026-10-26.

**Last updated**: 2026-10-26 (first version).

## The three scopes

| Scope | Shows | Never shows |
|---|---|---|
| **Hybrid** (default) | everything, as before the switch | - |
| **Monitor** | what the monitor-mode radio heard over the air (`src/capture/probe.c`): beacons, probes, PNLs, associations, EAPOL, deauths, the channel mix and every 802.11 detector; and the BLE receivers (`--bt-monitor`, `--bt-capture`), which are receive-only radio too | the IP capture, ARP, DHCP, DNS, mDNS, NBNS, SSDP, ONVIF, the flows, top hosts, `/proc`, the managed card's nl80211 dump and scans |
| **Local** | what the host's own connected interfaces carried: the IP capture (`src/capture/capture.c`) on Ethernet and the associated Wi-Fi card, ARP, DHCP, DNS, mDNS, NBNS, the flows, `/proc` connections and processes, each interface's throughput, and the managed card's own `wifi_sta` station dump and `wifi_ap` scan (Wi-Fi through the local network, not passive) | anything the monitor radio heard |

sloth's own state (`sensor_health`, `sensor`, `socket_gap`, and the two
own-state alerts `NO_MONITOR_MODE` and `BT_OWN_TRANSMIT`, the list
`tests/test_research_corpus.c :: test_own_state_kinds_are_named` pins)
appears in every scope.

## How a datum gets its scope

There is no per-record capture-path field in the JSONL stream, so the
tag is decided by what the record is:

- **Record type.** The 802.11 monitor stream's types (`beacon` through
  `wifi_merged`, the fifteen `MON_TYPES` app.js draws as monitor rows,
  plus `twin_episode` and `wifi_merged`) and `ble_device`/`ble_alert`
  are Monitor's; the IP capture's and the host's are Local's.
  `web/tests/test_scope.c` reads `web_live.c`'s `POLL_TYPES` and
  app.js's `MON_TYPES` from the source and fails on a type left out.
- **Alert type.** By the rule's input, not the file it is in: an
  explicit table in `include/sloth_alerts.def` order, held to the
  `.def` row by row. `CAPTIVE_PORTAL` sits in `rules_twin.c` but reads
  DNS, HTTP and TLS (Local); `CAM_SETUP_OUI` sits in `rules_camera.c`
  but reads beacon BSSIDs (Monitor); `BEACONING` is C2 beaconing over IP
  (Local).
- **Interface.** Monitor when its name has been named as a monitor
  radio: `sensor_health.monitor_iface`, or a `sensor` record of kind
  `wifi` (`src/poll.c` registers only the monitor adapters as
  `SENSOR_WIFI`). Every other interface is Local. The set is learned
  per run: after a restart a radio's old series counts as Local until
  sloth names it again (its next `sensor_health`, within the 300 s
  heartbeat).
- **Device.** By sloth's `DEV_SRC_*` bits: ARP, DHCP, mDNS, STA and an
  address are Local; BEACON and PROBE Monitor; CAMERA by which camera
  signals it has (`cam_signals`: setup SSID and setup OUI are beacons,
  WS-Discovery, mDNS, SSDP and RTSP are IP). A device seen both ways is
  in both.
- **Metric.** `dev.frames`, `wifi.*` and the channel mix are Monitor's;
  `host.*`, `dns.*`, `tls.*`, `http.*`, `flow.*` and `conns.total` are
  Local's; `iface.*` by the interface and `alerts.fired` by the alert
  type. `dev.present` is every source's (Hybrid's, and A3 and A4 keep
  scoring it); two new metrics split it: `dev.present.monitor` and
  `dev.present.local`.

### The IP capture on a radio

capture.c decodes IP from 802.11 data frames when its handle is a
radiotap one (#72), and `--monitor-only` puts the monitor radio on the
IP stream's allow-list. While sloth says its IP capture is itself a
monitor radio (`sensor_health.capture_linktype` 105, 119, 127 or 163;
with an older sloth that sends no link type, `capture_iface ==
monitor_iface`), the stream's IP-capture records and alerts count as
Monitor's, and a banner says so. `capture_linktype` and `monitor_only`
are new `sensor_health` fields for exactly this
([jsonl-schema](jsonl-schema.md)): raw facts, sloth classifies nothing.

sloth.db's rows carry no capture path, so its IP tables (ARP, DHCP,
names, flows, IP-derived alerts) count as Local's whatever the stream
says now. The legend states the limit.

## A device seen both ways

It appears in both scopes and in each shows only what that scope
captured. Under Monitor: no address, hostname, DHCP, mDNS or NBNS name,
no ARP bindings, no DHCP vendor class; its signal is the probe's, else
the beacon's. Under Local: no last SSID, AP bit, PNL SSIDs or
associations; its signal is `wifi_stas`'s. In both:

- **first and last seen** are the scope's own tables' (Monitor:
  `probe_clients`, `beacon_aps`, `assocs`, `pnl_clients`; Local: `arp`,
  `wifi_stas`, `dhcp_leases`), the row's own when they hold none;
- **membership** is the scope's tables holding the MAC, or the scope's
  bits in `devices.sources` (the latest tick only: sloth's upsert
  replaces them), so a device first seen by ARP and now only by probes
  stays in Local;
- **risk** is sloth's weights (`src/device_risk.c`: 1, 1, 1, 1, 3, 3;
  CRIT at 5, HIGH at 3, MED at 1, a test reads them from the source)
  over the signals the scope can see: RANDOM_MAC and UNKNOWN_VENDOR in
  both, NO_HOSTNAME, CLEARTEXT_CRED and ALERT_TAGGED Local's,
  PROBE_ONLY Monitor's;
- **the camera identity** is shown where the scope has a camera signal
  of its own; a not-camera verdict (from the IP vetoes) under Local
  only;
- **presence strips** read `dev.present.monitor` or `.local`.

The query language (`vendor:`, `ip:`, `ssid:`, `seen:`, `risk:`,
`src:`, `has:`, `pass:latest`, sorts) runs over the scope's columns: an
address term matches nothing under Monitor, an SSID term nothing under
Local, `pass:latest` is the latest pass's devices of the scope.

## Per view

| View | Monitor | Local |
|---|---|---|
| Overview tiles | devices of the scope in the latest pass; its open alerts; its records/s; the monitor radio's rx as throughput (frames heard) | the same of Local; the busiest Local interface |
| Ticker, latest alerts | the scope's records (each carries its tag `sc`) | the same |
| Activity | Monitor's metrics and keys | Local's |
| Devices, drawer, Lookup | as above; Lookup of an IP says Monitor holds no addresses | as above |
| Anomalies | A2, A1 on Monitor metrics, A3/A4 where the MAC has Monitor presence, A10 | A5-A9, A1 on Local metrics, A3/A4 with Local presence, A10 |
| WiFi | all of it | empty, saying why |
| Flows | empty, saying why | all of it |
| History | the scope's devices by its own first seen, its alerts; no flows | the same, with flows |
| Alerts, an alert's page | the scope's types (a direct link still opens and says when its type is not in the scope) | the same |
| Health | sloth's own state, every scope | the same |
| SQL box | unscoped: raw sloth.db, labelled so | the same |

## The API

Every `/api` route but `/api/health` and `/api/query` takes
`scope=monitor|hybrid|local`, taken out of the query by the shared
parameter parser (`web_scope_take()`, `web/src/web_series.c`) before the
route's own parser sees it; anything else is a 400 `bad_scope`, a
second one `repeated_parameter`. With a scope named the JSON answer's
first member is `"scope"`. Without one the answer is Hybrid's and
unchanged; `scope=hybrid` is that answer plus the echo, which
`test_scope.c` holds byte for byte on every route it asks. The server
does the filtering wherever it counts, pages or aggregates; the page
only keeps the scope's records on the ticker. A view a scope holds
nothing of answers `{"out_of_scope":true,"reason":...}`; a series or
baseline out of scope answers no points (`"out_of_scope":true`) or
`"fed":false`. `/api/live` under a scope adds `scope_facts`: whether
the IP capture is a radio, sloth's link type and `--monitor-only`, and
the monitor radios named so far.

## The page

The switch sits in the top bar before the theme toggle: a radio group,
arrow keys move it, it wraps at phone width; Monitor, when chosen,
wears the monitor radio's own ground (`CP_MON_ROW`, the ticker's
monitor rows). The choice is in the address (`#devices?scope=monitor`;
Hybrid left out) and kept in this browser (`slothweb.scope`, every
access in try/catch) for an address that names none. Every view opens
with a `scope:` chip, the status strip has a `scope`
pill, and under Monitor or Local a bar under the strip says what the
scope holds; a `?` beside the switch opens the legend.

## Related pages

- [[slothweb]] — the dashboard this switch is part of
- [[jsonl-schema]] — `sensor_health.capture_linktype` and `monitor_only`
- [[camera-detection]] — the camera signals a device's scope is read from
- [[alerts]] — the alert types and their rules
- `docs/views/devices.md` — sloth's device risk signals, which the scopes recompute
