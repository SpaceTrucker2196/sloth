---
name: dashboard
description: The seven-band composite dashboard view — what each band shows and how panels are laid out
type: reference
---

# Dashboard

**Summary**: The `[o]` view tiles seven bands vertically into one terminal. Bands grow proportionally with available rows; minimum recommended terminal is 100×33.

**Sources**: `docs/views/dashboard.md`, `docs/views/top_hosts.md` (embedded in dashboard.md), `CLAUDE.md`.

**Last updated**: 2026-05-25.

---

## Layout

```
header (2 rows)
Interfaces band            (height = iface_count)
Connections + Top hosts    (= 2H, split 60/40)
Packets                    (= 2H)
WiFi APs | Summary | Beacons               (H)
mDNS     | DHCP    | SSDP                  (H)
ARP      | Deauth  | Roaming clients       (H)
DNS log  | ICMP log                        (H, 50/50)
```

Bands sum to LINES exactly — spare rows from the integer divide go to
conn / packets so the bottom band always reaches the last line.

## Top hosts panel

Built by `src/top_hosts.c`:

1. Aggregate `s->conns` + `s->conn_bw` by **remote IP** each poll.
2. Skip RFC1918 / loopback / link-local / multicast / IPv6 link-local
   (this panel is about external traffic).
3. Hostname comes from the async DNS resolver (`src/dns.c`); owner
   from the embedded CDN / cloud prefix table in `src/ip_owner.c`.
4. `first_seen` is sticky across polls — the **age** column shows how
   long this destination has been around.
5. Sort by `rx_rate + tx_rate + conn_count`, snapshot top 32.

## Roaming clients panel

Enhanced version of `[7] Probe` — same data source
(`s->probe_clients[]`), more columns: MAC, vendor (via `oui_lookup()`,
or `(random)` when locally-administered bit is set), last-probed SSID,
signal in dBm (coloured by strength), and a rough distance estimate
via the log-distance path-loss model. Treat distance as
order-of-magnitude only.

## Cross-panel cues

- IPs use the 8-colour hash palette — same IP, same colour everywhere.
  See [[ip-palette]].
- An IP appearing in **≥ 2 panels** renders **bold**. Instant
  cross-reference cue: a bold IP in packets that's also bold in conns
  and ARP wants your attention.
- Sparklines are heat-graded (cool → peak red). `_` = zero sample.

## "Look harder" signals

- Bold IP in the packet stream that's also bold in conns and ARP.
- Sudden solid amber/red sparkline on a previously quiet flow.
- Top-hosts entry in a brand colour you weren't visiting.
- Any visible CRIT in the alerts panel.

## Related pages

- [[ip-palette]] — colour conventions used across every panel.
- [[views-catalog]] — links to each band's standalone view.
- [[alerts]] — the alert summary in the bottom-right.
