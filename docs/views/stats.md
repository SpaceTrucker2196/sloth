# Stats  `[6]`

Session-totals view: bytes / packets / rates per interface, top
remote endpoints by bandwidth, top processes by transfer, and the
collection gaps: which alert rules cannot fire, or miss part of their
evidence, and why (#242 item 3).

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

## Collection gaps

Under the interface totals: the coverage assessment
([coverage-assessment](../wiki/coverage-assessment.md) § 8), the same
grouping the `--report` section uses. It reads the status the daemon
already derives each tick (`cov_live_*`), nothing new.

```
 ── Collection gaps ──
  96 rules: 55 observable  37 partly  4 blind    radios 1  channels 11  hopping  bands 2.4,5
  blind no_own_net (3)  dot11: MY_NETWORK_RECON UNKNOWN_DEVICE TPC_ABSENT_HIGH_BAND
  blind band (1)  dot11: DFS_MASKING
  partly hop (37)  dot11: DEAUTH_FLOOD EVIL_TWIN_PROXIMITY PROBE_FLOOD BEACON_FLOOD AUTH_FLOOD
      MGMT_FUZZ ROGUE_RADIUS RECURRING_TRANSIT RF_DEGRADED ASSOC_FLOOD BTM_ABUSE ...
  SENSOR_SUPPRESSED open: suppressed:drop
  Observable means: on the channels the radios visit. A transmitter on a channel in no
    radio's plan is not heard, and the status does not say so.
  The status is about the sensor, not the site. Observable with no finding is "looked and
    found nothing", not "nothing is there".
```

- The first line: the counts of this daemon's rules, then the radio
  figures the 802.11 statuses come from.
- One line per reason, blind before partly, in the order the reason is
  chosen (the first thing to fix first); within it the kinds grouped
  by the input they read. A long line is broken between words at the
  terminal's width and indented under the reason: the list flexes with
  the screen and no name is cut. A kind that is observable is in no
  line; with none blind or partly the line reads `none: every rule is
  observable`.
- Open `SENSOR_SUPPRESSED` incidents by key (a resolved one is not
  shown).
- The two limits.

The view does not scroll, and the traffic sections under this one
(Connections, Top 5, the geography, the capture count) were there
first. When the whole list would push them below the last row (a
100x33 terminal on a hopping sensor: the hop group alone wraps to six
rows), the reasons are one line of counts and the names and limits are
left to `--report`:

```
  blind no_source 30, no_own_net 3, no_db 1, band 1   partly hop 37   (kinds and limits: --report)
```

The open `SENSOR_SUPPRESSED` lines are kept in both forms.

Before the first status sample, and on a `--replay` run, the section
reads `not assessed: <why>` and shows no count: zero blind rules would
read as full coverage.

This view, and not the Interfaces view's health strip, because the
strip is one fault-only line under a paged table; this view is the
session's own figures in titled sections.

## Keybindings

`r` — reset the baseline (start a new session).

## What's normal

- Bandwidth concentrated in a few CDN endpoints.
- Process distribution that matches what you're actually doing.

## What's suspicious

- **A rule you rely on in a blind line** — the reason says what to
  add: `no_source` an input (`--iface`, a monitor radio, `--bt-monitor`),
  `no_own_net` `--my-ssid`, `band` a channel in that band on `--hop`.
- **`SENSOR_SUPPRESSED open`** — the sensor is losing evidence while its
  sources read up; the rules it costs read `partly suppressed`.

- **Top-bandwidth remote you don't recognise** — investigate via
  `[r] DNS` or `[g] Devices`. Sometimes legitimate (an OS-update
  CDN), sometimes the long tail of a slow data exfil.
- **High traffic to a "Top hosts" row whose owner is unknown** —
  hosting org wasn't in the embedded `ip_owner` table. Manual
  whois / shodan look-up.
- **Process you didn't run** dominating the bandwidth chart.

## See also

- Collection gaps: [coverage-assessment](../wiki/coverage-assessment.md),
  [`src/rule_coverage_live.c`](../../src/rule_coverage_live.c).

- Per-process bandwidth: [`src/bandwidth.c`](../../src/bandwidth.c).
- Top hosts panel on the dashboard ([`dashboard.md`](dashboard.md))
  surfaces a live version of the "top remote by bandwidth" table with
  hostname + hosting-org enrichment.
