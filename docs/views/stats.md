# Stats  `[6]`

Session-totals view: bytes / packets / rates per interface, top
remote endpoints by bandwidth, top processes by transfer.

## Source

Snapshots `/sys/class/net/*` and the bw tables. Baseline captured on
first poll; everything is rendered as a delta from the baseline.

## View

```
 ── Session stats ──────────────────────────────────────────────
 Uptime:  1h 23m 04s
 Started: 2026-05-18 09:14:22

 ── per-iface totals ─
 iface   rx                tx                rx/s avg   tx/s avg
 eth0    5.0 GB ▇▇▇▇▇▇▇    1.0 GB ▇▇         800 KB/s  150 KB/s
 wlan0   200 MB ▂          50 MB             40 KB/s    8 KB/s

 ── top remote by bandwidth ─
   142.250.80.46    google           2.1 GB    420 KB/s
   104.16.132.229   cloudflare       1.0 GB    200 KB/s
   17.253.144.10    apple              500 MB   80 KB/s

 ── top processes ─
   chrome           3.0 GB
   firefox          500 MB
   ssh              50 MB
```

## Keybindings

`r` — reset the baseline (start a new session).

## What's normal

- Bandwidth concentrated in a few CDN endpoints.
- Process distribution that matches what you're actually doing.

## What's suspicious

- **Top-bandwidth remote you don't recognise** — investigate via
  `[r] DNS` or `[g] Devices`. Sometimes legitimate (an OS-update
  CDN), sometimes the long tail of a slow data exfil.
- **High traffic to a "Top hosts" row whose owner is unknown** —
  hosting org wasn't in the embedded `ip_owner` table. Manual
  whois / shodan look-up.
- **Process you didn't run** dominating the bandwidth chart.

## See also

- Per-process bandwidth: [`src/bandwidth.c`](../../src/bandwidth.c).
- Top hosts panel on the dashboard ([`dashboard.md`](dashboard.md))
  surfaces a live version of the "top remote by bandwidth" table with
  hostname + hosting-org enrichment.
