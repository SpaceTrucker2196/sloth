# Interfaces  `[1]`

Per-interface stats: RX/TX rates, errors/drops, MTU, link speed,
NIC vendor (via OUI lookup), link-layer mode (ETH / WIFI / MON),
and rolling history sparklines.

## Source

`/sys/class/net/<iface>/statistics/*` for the byte/packet/error counters,
`/sys/class/net/<iface>/{mtu,speed}` for capacity,
`/sys/class/net/<iface>/address` for the MAC address (fed to
`src/oui.c` for vendor), and `/sys/class/net/<iface>/type` for the
ARPHRD_* value that classifies mode (`803`/`804` = monitor mode).
BSD/macOS reads MAC via `AF_LINK` `sockaddr_dl`; monitor-mode
detection there is a follow-up.

Rates are computed by diffing poll-to-poll. The 30-sample (= 30
seconds at 1 Hz) history feeds the sparkline graphs.

## View

```
 ── Interfaces ─────────────────────────────────────────────────
 iface      Mode Vendor        rx/s        tx/s      rx history        rx total   tx total
 eth0       ETH  Intel Corp    1.0 MB/s    200 KB/s  ▂▃▄▅▆▇█▇▆▅▃▂▂▁_   5.0 GB     1.0 GB
 wlan0      WIFI Apple         500 KB/s    50 KB/s   __▁_▁▁▂▂▁__▁_▁    200 MB     50 MB
 wlan0mon   MON  Alfa Networks 2.0 MB/s    0 B/s     _▁▂▃▄▅▆▇█▆▄▂▁_    600 MB     0 B     [monitor]
 lo         ETH  -             0 B/s       0 B/s     ________________  0 B        0 B
                 ^                                   ^
                 OUI-derived NIC vendor              heat-graded: cool→peak red
```

Monitor-mode rows render bright and carry a trailing `[monitor]`
marker — the operator can see at a glance whether at least one
radio is available for WiFi SIGINT.

Each sparkline stretches across the available row width (`HIST_LEN`
samples mapped to as many cells as fit). Heat colours scale per
interface: a quiet wlan still shows usable shape next to a saturated
eth.

## Keybindings

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate |
| `Enter` | Open detail panel (sparkline graph, errors, drops) |
| `m`     | Mark this iface as the probe-capture iface |
| `t`     | Toggle iface **visibility** (display-only; data still flows) |
| `y`     | Toggle iface **data-stream selection** (drops packets pre-decode) |

## What's normal

- One or two interfaces with real traffic; loopback usually idle.
- Errors / drops counters at 0 or growing very slowly.

## What's suspicious

- **Sudden saturation** of an iface that's normally quiet — could be
  legitimate (backup running), or exfiltration / DDoS amplifier.
- **High drop count** — link issues OR pcap can't keep up (overflow
  in the capture ring).
- **Promiscuous mode unexpectedly set** on an iface — something
  external put your card into capture mode. Check with `ip link
  show`. Common after misconfigured Docker bridges; less common,
  meaningful indicator of a sniffer running locally.
- **MTU mismatch** between paired interfaces in the same VLAN —
  performance hit, also a misconfig that's easy to miss.
- **No monitor-mode radio at startup** — the `NO_MONITOR_MODE` alert
  fires once at first-poll if no iface reports ARPHRD_IEEE80211_RADIOTAP
  (Linux type 803). Doesn't mean an attack; means WiFi SIGINT views
  (Probe, Beacons, EAPOL, Deauth) will stay empty this session. See
  [`alerts.md`](alerts.md).

## Data-stream selection (`y`) — issue #17

Independent of the hide election, `y` toggles whether the interface's
packets contribute to the capture pipeline. A deselected iface's
frames are dropped in the pcap callback *before* any decode / log /
alert runs — Connections, Packets, DNS, TLS, HTTP, QUIC, ICMP, NTP,
the JSONL log, and the alert engine all lose that iface's traffic
until it's toggled back.

Rows carry a `d` prefix and a trailing `(deselected)` marker so the
election is visible at a glance.

**How the filter works.** Ingress interface attribution requires
`DLT_LINUX_SLL2` (cooked capture v2) — its header carries an
`sll2_if_index` at offset 4. sloth opens `any` with `pcap_create` +
`pcap_activate`, then calls `pcap_set_datalink(handle,
DLT_LINUX_SLL2)`. libpcap ≥ 1.10 accepts this; ≥ 1.11 defaults to it
for `any`. If the call fails (older libpcap, kernel refuses), sloth
falls back to `DLT_LINUX_SLL` v1 or `DLT_EN10MB` — capture still
works, but the header doesn't identify an ingress iface, so the
data-stream toggle becomes a UI-only marker with no filter effect.
The iface view still shows the marker for consistency across
platforms.

**Scope.** Applies to the IP/TCP capture path only. The 802.11
monitor capture is a separate pcap handle bound to a specific
monitor interface — WiFi SIGINT views are already governed by the
`m` (monitor-iface) selection.

## See also

- Backend: [`src/platform/linux_parse.c`](../../src/platform/linux_parse.c).
- Stats baseline: [`src/views/stats.c`](../../src/views/stats.c).
