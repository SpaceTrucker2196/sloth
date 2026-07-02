# Devices  `[g]`

Synthesised device profile per MAC — joins ARP, DHCP, beacons,
probes, and WiFi-station state into a single record.

## Source

[`src/devices.c`](../../src/devices.c) runs each poll and builds an
in-memory device table by upserting one row per MAC across five
sources:

1. **ARP** — kernel ARP table → IP + MAC + interface.
2. **DHCP** — assigned IP and hostname (bridged to MAC via the
   matching ARP entry).
3. **Beacons** — 802.11 beacons identify access points by BSSID
   (which is a MAC).
4. **Probes** — 802.11 probe requests show unassociated clients
   by their source MAC.
5. **Stations** — currently-associated WiFi clients via nl80211.

Each source contributes a bit in the `Src` flag column.

## View

```
 ── Devices ────────────────────────────────────────────────────
 MAC                IP               Vendor            Hostname / SSID       Src     RSI  Hits
 b8:27:eb:11:22:33  192.168.1.100    Raspberry Pi      raspberrypi           AD----  -      0
 dc:a6:32:00:00:01  192.168.1.101    Raspberry Pi      -                     A-----  -      0
 a4:b1:c2:d3:e4:f5  -                ?                 (access point)        ---B--  -42    0
 de:ad:be:ef:00:01  -                ?                 ssid:Starbucks        ----P-  -55  127
 18:fe:34:11:22:33  192.168.1.50     Espressif         -                     A----S  -67    0
                                                                              │││││└─ Station
                                                                              ││││└── Probe
                                                                              │││└─── Beacon
                                                                              ││└──── mDNS
                                                                              │└───── DHCP
                                                                              └────── ARP
```

## Risk bucket

The `Risk` column shows a bucket derived from independently observable
signals — no ML, no black box. Bucket = weighted sum of signals:

| Signal | Weight | Meaning |
|--------|-------:|---------|
| `RANDOM_MAC`     | 1 | Locally-administered bit set (Apple/Android privacy MAC, monlib randomization) |
| `UNKNOWN_VENDOR` | 1 | OUI not in the embedded table |
| `NO_HOSTNAME`    | 1 | No DHCP/mDNS/NBNS hostname resolution |
| `PROBE_ONLY`     | 1 | Probe frames observed, no beacon/STA association |
| `CLEARTEXT_CRED` | 3 | This device leaked a credential in the clear (see `[v]` Alerts, `CLEARTEXT_CRED`) |
| `ALERT_TAGGED`   | 3 | An active alert names this device's IP as its target |

Score → bucket:

| Score | Bucket | Colour |
|-------|--------|--------|
| 0     | LOW    | dim |
| 1–2   | MED    | phosphor-heat 0.4 |
| 3–4   | HIGH   | phosphor-heat 0.7 |
| 5+    | CRIT   | phosphor-heat 1.0 |

The signal bitmask is exported in the JSONL `risk_signals` field so
external consumers can reproduce the score and show a per-signal
breakdown.

## What's normal

- Each known device shows multiple source flags — e.g. `AD----` for
  a wired host (ARP + DHCP) or `A----S` for a wireless client.
- Vendor column matches your inventory.

## What's suspicious

- **Unknown vendor `?`** on a device with an IP — randomised MAC or
  an OUI not in the embedded table. Worth a manual whois.
- **`---B--` only**: a beacon-only entry is just an AP. **`----P-`
  only**: someone in radio range probing but not connecting (could
  be passing through, could be casing the place — see
  [`probe.md`](probe.md)).
- **New device** appearing in the list without DHCP — probably
  manually-configured. Rogue hosts often skip DHCP to avoid the audit
  trail.
- **One IP, two MACs** within a few minutes — MAC spoofing or
  legitimate failover. Reconcile with `[8] ARP` and `[d] DHCP`.

## See also

- [`arp.md`](arp.md), [`dhcp.md`](dhcp.md), [`beacons.md`](beacons.md),
  [`probe.md`](probe.md), [`wifi.md`](wifi.md) — the five upstream
  sources.
