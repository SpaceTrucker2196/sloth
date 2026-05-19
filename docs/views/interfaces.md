# Interfaces  `[1]`

Per-interface stats: RX/TX rates, errors/drops, MTU, link speed,
rolling history sparklines.

## Source

`/sys/class/net/<iface>/statistics/*` for the byte/packet/error counters,
`/sys/class/net/<iface>/{mtu,speed}` for capacity, rtnetlink for the
list. Rates are computed by diffing poll-to-poll.

The 30-sample (= 30 seconds at 1 Hz) history feeds the sparkline graphs.

## View

```
 ── Interfaces ─────────────────────────────────────────────────
 iface        rx/s        tx/s         rx total       tx total   rx graph         tx graph
 eth0       1.0 MB/s    200 KB/s     5.0 GB         1.0 GB     ▂▃▄▅▆▇█▇▆▅▃▂▂▁_   _▁▂▂▃▄▅▅
 wlan0      500 KB/s     50 KB/s     200 MB         50 MB      __▁_▁▁▂▂▁__▁_▁    __▁__
 lo            0 B/s       0 B/s     0 B            0 B        ________________  ________________
                                                                ^                  ^
                                                                heat-graded: cool→peak red
                                                                '_' = zero sample
```

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
| `t`     | Toggle iface visibility |

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

## See also

- Backend: [`src/platform/linux_parse.c`](../../src/platform/linux_parse.c).
- Stats baseline: [`src/views/stats.c`](../../src/views/stats.c).
