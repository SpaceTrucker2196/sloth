# OSI Stack  `[l]`

A synthesis view that maps everything sloth observes onto the
seven-layer OSI model — one row per layer, each populated from the
relevant fields of `sloth_state_t`. Pure derivation: no new state,
no per-row navigation. Use it as the "where is my traffic
happening?" cheat sheet and the entry point into the deeper views.

## Protocol / data source

The OSI layers and the sloth state fields each layer reads from:

| Layer | Name | Drawn from |
|-------|------|------------|
| **L7** | Application  | `dns_log_count`, `http_log_count`, `tls_log_count`, `quic_log_count`, `mdns_count`, `nbns_count`, `ntp_log_count` |
| **L6** | Presentation | TLS version distribution computed from `tls_log[].tls_ver`; distinct JA3 fingerprints from `tls_log[].ja3` |
| **L5** | Session      | TLS session count, QUIC stream count, EAPOL handshakes (`eapol_count`) |
| **L4** | Transport    | `conns[].proto` / `conns[].state` split (TCP ESTABLISHED / LISTEN / other, UDP), `icmp_log_count` |
| **L3** | Network      | Distinct remote-IP count (IPv4 / IPv6 split from `conns[]`), `arp_count` |
| **L2** | Data Link    | `iface_count`, `ap_count`, `wifi_sta_count`, `device_count`, `beacon_count` |
| **L1** | Physical    | `probe_iface` (when monitor mode is active), or the first iface's name |

Sloth never injects anything to populate this view — every count is
the result of passive observation that another view also exposes in
more detail.

## What sloth captures

- One row per layer (7 rows), drawn top-down L7 → L1 so the rows mirror
  the way packets stack down toward the wire.
- Counts and pivots only: no per-record drill-down on this view; press
  the per-protocol view key to inspect individual records.
- The TLS-legacy count (L6) lights up red when `>0` — it's the same
  signal that drives `ALERT_TYPE_WEAK_TLS`. Visually echoes the alert
  palette so the operator sees a hot OSI row before they navigate.

## View

```
 OSI / TCP-IP stack — passive observation per layer   conns:24 ifaces:2

 ────────────────────────────────────────────────────────────────────
  L7 Application    │ DNS:142  HTTP:7  TLS:88  QUIC:12  mDNS:31  NBNS:0  NTP:3
  L6 Presentation   │ TLS 1.3:74  TLS 1.2:14  legacy:0   JA3:9 distinct
  L5 Session        │ TLS sessions:88  QUIC:12  EAPOL:1
  L4 Transport      │ TCP:22 (E:14 L:6 ?:2)  UDP:2  ICMP:3
  L3 Network        │ IPv4 hosts:18  IPv6 hosts:3  ARP mappings:14
  L2 Data Link      │ ifaces:2  APs:7  STAs:11  devices:21  beacons:43
  L1 Physical       │ probe iface: wlan0mon (monitor mode)
 ────────────────────────────────────────────────────────────────────

 Tip: this is a synthesis view — drill into any layer
      via its own view (DNS [r], HTTP [h], TLS [t], conns [2], ...).
```

## What's normal

- **Inverted pyramid.** Each layer's count is usually higher than the
  one below, because each L4 connection carries many L7 records and
  each L1 interface backs many L3 conversations. An L7 number lower
  than the L4 number is unusual (suggests dropped logs or a parser
  that isn't keeping up).
- **L6 legacy = 0.** Modern stacks negotiate TLS 1.3 by default,
  occasionally TLS 1.2. Anything below 1.2 means an embedded device
  or a deliberate downgrade test.
- **L4 TCP listen >> established** on a server, **TCP established >>
  listen** on a client.

## What's suspicious

- **L6 legacy > 0**: legacy TLS in the field — RFC 8996 deprecated.
  Pivot to the [TLS view](tls.md) and look at which client. The
  `ALERT_TYPE_WEAK_TLS` rule is already firing on this.
- **L7 protocol concentration**: 95% of L7 events being one protocol
  on a normal host is usually fine for a desktop (HTTPS) but odd for
  a server. DNS dominating L7 with no answers populated suggests a
  DGA / tunnel — pivot to the [DNS view](dns.md).
- **L4 `?:N` non-trivial**: TCP states other than ESTABLISHED /
  LISTEN at scale mean churn — SYN_SENT bursts can be outbound
  scanning; lots of TIME_WAIT means short-lived connections.
- **L3 IPv4 hosts >> total subnet size**: scanning out. Pair with
  the [Alerts view](alerts.md) — `PORT_SCAN` and `BEACONING` will
  be firing.
- **L2 STAs > APs * reasonable factor**: an evil-twin scenario
  often shows up here first (extra APs visible). Cross-check
  against the [Beacons view](beacons.md) and the `EVIL_TWIN` alert.
- **L1 no iface**: sloth was started without sufficient capability
  or no monitor-mode iface is up. Most other views will be empty.

## Implementation notes

- Pure synthesis: zero new state fields, no observers, no platform
  hooks. Reads `sloth_state_t` and re-renders every poll.
- Distinct-host counts use a small inline dedup table (bounded by
  `MAX_CONNS`); the cost is O(n²) per draw, which is fine for the
  bounded `conn_count` and runs once per poll-and-render cycle.
- The view never navigates — `view_osi_key` is a no-op. The global
  key router (Tab / `[1-0]` / `[a-z]`) is enough for an
  always-readable summary screen.

## See also

- [Architecture](../wiki/architecture.md) — the layered code structure
  that this view mirrors at runtime.
- [Dashboard](dashboard.md) — composite live view (multi-band tile).
- [Alerts](alerts.md) — what's flagged across all layers.
- Per-protocol views: [DNS](dns.md), [TLS](tls.md), [HTTP](http.md),
  [QUIC](quic.md), [ICMP](icmp.md), [Connections](connections.md),
  [ARP](arp.md), [Beacons](beacons.md), [WiFi](wifi.md),
  [Interfaces](interfaces.md).
