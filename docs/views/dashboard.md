# Dashboard  `[o]`

Tiled at-a-glance composite of seven bands stacked vertically. The
dashboard fills the whole terminal — bands grow proportionally with
available rows. Minimum recommended terminal is 100×33.

## Layout

```
 ┌─ header (2 rows) ──────────────────────────────────────────┐
 │ ── Interfaces ──   eth0  1.0MB/s  rx ▂▃▄▅▆▇█  tx _▁▂▃▄▅   │  ← iface band, expands to fit iface_count
 ├────────────────────────────────────────────────────────────┤
 │ ── Monitor radio ──  wlan1mon  ch 6  rx 1.2KB/s  12 clients│  ← only when a monitor-mode iface is set (Alpha dongle etc.)
 ├────────────────────────────────────────────────────────────┤
 │ Connections (= 2H, scrollable)   │  Top hosts (= 2H)       │  ← split 60/40
 │ local → remote  proto …          │  ip  host  owner  age   │
 ├──────────────────┬─────────────────┬───────────────────────┤
 │  WiFi APs        │ Summary         │ Beacons (H)           │
 ├──────────────────┼─────────────────┼───────────────────────┤
 │  mDNS services   │ DHCP events     │ SSDP / UPnP (H)       │
 ├──────────────────┼─────────────────┼───────────────────────┤
 │  ARP table       │ Deauth          │ Roaming clients (H)   │
 ├──────────────────┴────┬────────────────────────────────────┤
 │ DNS log               │ ICMP log (H, split 50/50)          │
 ├───────────────────────┴────────────────────────────────────┤
 │ Packets (live, = 2H, newest at top)                        │
 └────────────────────────────────────────────────────────────┘
```

Bands sum to LINES exactly — spare rows from the integer divide go
to conn / packets so the bottom band always reaches the last line.

## Color and typography

- **IPs** are hashed to one of 8 Fallout-phosphor colours. The same
  IP shows up in the same colour across every panel.
- **IPs in ≥ 2 panels** render bold — instant cross-reference cue.
- **Hostnames** with known brand names get brand colouring:
  - `google` → G-o-o-g-l-e in the Google logo's blue/red/yellow/blue/green/red.
  - `firefox` → orange.
  - `cloudflare` → red.
  - `example.org` → grey.
- **SSIDs** use the same hash palette as IPs (separate hash, so a
  hostname and an SSID won't accidentally share a colour).
- **Sparklines** are heat-graded — level 1–2 cool phosphor, 3–4
  amber, 5–6 orange, 7–8 peak red. `_` = zero.

## Top hosts panel

A live "who am I really talking to" rank. Built by
[`src/top_hosts.c`](../../src/top_hosts.c):

1. Aggregate `s->conns` + `s->conn_bw` by **remote IP** each poll.
2. Skip RFC1918 / loopback / link-local / multicast / IPv6
   link-local (this panel is about external traffic).
3. Hostname comes from the async DNS resolver (
   [`src/dns.c`](../../src/dns.c)); owner from the embedded CDN /
   cloud prefix table in [`src/ip_owner.c`](../../src/ip_owner.c).
4. `first_seen` is sticky across polls — the **age** column shows
   how long this destination has been around.
5. Sort by `rx_rate + tx_rate + conn_count`, snapshot top 32.

```
 ip               host                  owner          age      conn
 8.8.8.8          dns.google            Google DNS     1h23m       5
 104.16.132.229   *.cloudflare.com      Cloudflare      4m12s     12
 142.250.80.46    *.google.com          Google         12m         3
 17.253.144.10    *.apple.com           Apple          45m         2
```

## Keybindings

`↑` / `↓` scroll the connections panel (shares `conn_sel` with
the standalone `[2]` view).

## What's normal at a glance

- Sparklines mostly idle with occasional peaks.
- Top hosts dominated by CDN / cloud (Cloudflare, Google, AWS).
- Quiet alert summary in the bottom-right.

## What screams "look harder"

- A bold IP in the packet stream that's also bold in conns and ARP —
  cross-panel attention, probably interesting.
- A solid amber/red sparkline that came out of nowhere.
- An entry in Top hosts with a name in the brand colour list you
  weren't visiting.
- Any visible CRIT in the alerts panel.

## Monitor radio band

A single-row band that only appears when a monitor-mode iface is set
up (typically an external USB adapter like the Alfa AWUS036ACH parked
in monitor mode). Shows:

| col      | source |
|----------|--------|
| iface    | `s->probe_iface` — the netdev with ARPHRD type 803 (radiotap) |
| channel  | most-recently observed channel from `s->probe_clients[0].channel` (the list is sorted by last_seen desc) |
| rx       | rx rate of the monitor netdev from `/proc/net/dev` — every frame the radio captures shows up here |
| frames   | cumulative rx_packets on the monitor iface |
| clients  | `s->probe_count` — distinct STAs the harvester has seen |
| APs      | `s->ap_count` — APs derived from passively captured beacons |
| deauths  | `s->deauth_count` — cumulative deauth/disassoc frames |
| sparkline| rx history of the monitor netdev (same series the iface band uses) |

If the probe subsystem can't open a monitor iface (`s->probe_err` set),
the band shows the error message instead so the operator knows why no
SIGINT data is appearing in the other panels.

## Roaming clients panel

The bottom-right panel ("Roaming clients") is an enhanced version of
`[7] Probe` — same data source (`s->probe_clients[]`), more columns:

| col    | source |
|--------|--------|
| MAC    | the 802.11 probe-request source addr |
| Vendor | [`oui_lookup()`](../../src/oui.c) on the MAC, or `(random)` if the locally-administered bit (0x02 in the first octet) is set |
| ssid   | last SSID this device probed for (`(any)` for broadcast probes); colour-hashed via the SSID palette |
| sig    | RSSI in dBm; coloured by strength (bright ≥ -50, normal -50…-65, amber -65…-80, hot < -80) |
| dist   | Rough metres estimate via the log-distance path-loss model `P(d)=P(d₀)-10·n·log₁₀(d/d₀)`, defaults P(d₀)=-30 dBm at d₀=1m, n=3.0 (typical indoor with walls). Treat as an order-of-magnitude hint, not a metric measurement. |

## See also

- Each band is explained in its own doc:
  [`interfaces.md`](interfaces.md), [`connections.md`](connections.md),
  [`wifi.md`](wifi.md), [`probe.md`](probe.md) (Roaming clients is the
  enhanced version of this), [`beacons.md`](beacons.md),
  [`mdns.md`](mdns.md), [`dhcp.md`](dhcp.md), [`ssdp.md`](ssdp.md),
  [`arp.md`](arp.md), [`deauth.md`](deauth.md), [`stats.md`](stats.md),
  [`dns.md`](dns.md), [`icmp.md`](icmp.md), [`packets.md`](packets.md).
