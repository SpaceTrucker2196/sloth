> **Committed 2026-10-21 from #102.** The body below is the 2026-09-30 draft,
> unchanged. Where a ruling made after it disagrees with the text, **the
> ruling wins**. They are listed here so a cold reader does not build the
> superseded version.
>
> | Topic | Ruling | Supersedes |
> |---|---|---|
> | Charter | `MISSION.md` §2 rule 1 (81f792b, 2026-10-14): optional services may use the network from the host; the one absolute is no injection onto a monitored segment. A local HTTP surface is in charter. | §2 table, "never resolves" row |
> | Location | In-tree under `web/` (owner, 2026-10-19). `agents/AGENTS.md` permits the directory. | §4.2 is kept |
> | Access | An allowed-IP list **defaulting to localhost only**; remote access is a separate explicit opt-in flag, the `--data-socket-allow-remote` pattern (owner, 2026-10-04). The first slice is the allow-list and its refusals **with tests, before any route exists**. | §2 table, #86 row; §10.3 `--web-bind` |
> | Read-only | No POST, PUT, DELETE and no control endpoint, ever; slothweb never writes to `sloth.db` (§13.7 confirmed). | — |
> | Active reverse DNS | **Cut.** slothweb never resolves anything; it shows names already in the JSONL stream. Resolution policy belongs to sloth's `--allow-active`. | §9.3, §10.3 `--web-active-rdns`, §13.4 |
> | SQL box | Kept behind `--web-allow-sql`, **default off**, `sqlite3_set_authorizer` read-only, 5 s timeout, 10k-row cap. | §13.5 |
> | Fonts | **System monospace stack**; no font binaries are checked in and no external font request is made. | §3, §8.2, M0 "with FiraCode" |
> | Design | The owner's **Spacetrucker** system for the chrome (2026-10-23): tokens in `web/ui/theme.css`, radius 14 px, a cream light theme behind a toggle. Every data colour (addresses, SSIDs, host names, info text, severity, heat, monitor rows, alert-hot addresses) is **the TUI's**, generated from `src/tui_palette.c` into `build/web/palette.css`, never hand-copied. The `--t-*` record hues are gone. | §8.1, §8.12 |
> | OUI table | **2026-10-26 (reverses 2026-10-21):** the IEEE registry CSVs (`oui.csv`, `mam.csv`, `oui36.csv`, `iab.csv`) are downloaded and **kept in the repo** in `web/data/`, with `web/data/SOURCE.md` (origin URLs, ieee-data version, SHA-256, refresh via `make update-oui`, by hand only). The table generated from them at build time stays build output, never committed. The 2026-10-21 ruling (developer fetches locally, nothing committed) is superseded. | §9.2 file layout (`web/data/oui_table.c`) |
> | Data socket | sloth's default is now `unix:/run/sloth/sloth.sock` (#136); `--socket` follows it. | §4.1 diagram |
> | Port, name, language | `8770`, `slothweb`, C99 in-tree server (decided under decide-and-flag; no objection across three rounds). | §13.1–13.3 |
> | Baseline half-life | Four weeks (§13.6 default stands until the owner says otherwise). | — |
> | Milestones | One child issue per milestone (W0 allow-list, then M0–M6); #102 is the tracker. | §12 |

# sloth web UI: specification

**Working name:** `slothweb`
**Repo location:** `sloth/web/` (one folder, separate from `src/`)
**Status:** draft for review, 2026-09-30

---

## 1. Purpose

`slothweb` is a browser dashboard for sloth data. It shows what the sensor sees now, and it lets the operator load and search what the sensor saw before. It is a read-only consumer. It does not change how sloth works.

The operator uses it to answer four questions fast:

1. Is anything on fire now?
2. Is the current activity normal for this time of day and this day of the week?
3. Which device or host is the outlier?
4. Who or what is this device?

## 2. Constraints that this design must respect

These come from `MISSION.md`, `SECURITY.md`, `docs/wiki/sqlite-schema.md` and the open security issues (#84, #86). They are not optional.

| Rule | Source | Effect on this design |
|---|---|---|
| sloth is passive. It never sends a packet. It never resolves a host it did not see. | MISSION §2.1 | sloth stays unchanged. All lookups run in `slothweb`, and active lookups are off by default (see §9.3). |
| The SQLite file is a sink, not a query surface. sloth gives it no RPC. | `sqlite-schema.md`, `db.h` | `slothweb` opens the file itself, read-only, as a second WAL reader. sloth does not serve it. |
| The data socket is the wire format. JSONL is the contract. | MISSION §4.3 | `slothweb` is a data-socket client, like `examples/consumer/sloth-stream.py` and sloth-ios. No new emitter is added to sloth. |
| Remote-control surfaces are out of scope. | MISSION §4 | `slothweb` has no endpoint that changes sloth state, the database, or the host. All HTTP methods that write are rejected. |
| The TCP socket has no authentication yet (#86). | issue #86 | `slothweb` binds `127.0.0.1` by default. A shared token is optional. LAN exposure is an explicit flag, documented as a risk. |
| Zero dependencies is a sloth value. `make embedded` must stay clean. | `Makefile`, README | `slothweb` is C99 and links only `libsqlite3`, which `WITH_SQLITE=1` already links. It is a separate binary and a separate make target. `make embedded` does not build it. |
| Secrets never persist. | MISSION §2, `test_db.c` | `slothweb` stores no new secret columns. Its own database copies the same guardrail test. |

## 3. What the study of rubric and second brain gave this design

Read: `rubric/templates/*` (scaffold, flows, skill-trees, crons, agents), `rubric-second-brain/public/*` and the two agentic-os installs. These are the parts that carry over.

**Carry over**

- One server, one HTML file, one port. Tabs are folders that the server auto-detects. `slothweb` keeps this: one binary, one embedded page, one port, and each view is a self-contained module.
- All colour lives in one `:root` token block plus one JS `THEME` object for canvas code. REDESIGN.md says: "swap these six values and 90% of the OS follows." `slothweb` follows this rule exactly, so the skin can change without touching a view.
- Canvas 2D for dense drawings, DOM for tables and controls. Second brain draws thousands of nodes at 60 fps with plain Canvas, no library. The heatmaps and sparklines here use the same approach.
- The accent is a budget. One accent colour, spent only on the few things that matter (the live alert, the selected row, the outlier). Muted text carries the design.
- Layout controls stay live: second brain exposes sliders (fog, glow, spin) that persist in `localStorage`. `slothweb` does the same for density, time window, and baseline sensitivity.
- Security posture from rubric README: bind loopback, no CORS, optional `x-token` header, 1 MB body cap, no external requests from the server.
- Search everything with `/`. Results surface while you type.

**Do not carry over**

- Node.js. The rubric servers are zero-dep Node, and that is a fine choice for a personal board. For sloth the runtime is C99 and the sensor often runs on a small Linux box or an SBC. Adding Node to that box is a dependency. See §10 for the MVP server.
- Google Fonts links. Rubric loads Outfit and JetBrains Mono from `fonts.googleapis.com`. That is an outbound request from the operator's browser to a third party every load. `slothweb` embeds FiraCode and makes no external request at all.
- The force-directed graph as the home view. It is beautiful in second brain, but the sloth question is "is anything on fire," and a table plus a baseline chart answers that faster. A relationship graph is a later view (§8.9).

## 4. Architecture

### 4.1 Processes and data flow

```
                        +------------------------------+
  wire / air ---------> | sloth (unchanged)            |
                        |  --data-socket unix:/run/sloth.sock
                        |  --db /var/lib/sloth/sloth.db |
                        +------+--------------+---------+
                               | JSONL         | SQLite WAL (writer)
                               v               v
                        +------------------------------+
                        | slothweb  (web/)              |
                        |  ingest   : data-socket client|
                        |  rollup   : 10s / 1m / 1h     |
                        |  baseline : hour-of-week      |
                        |  store    : slothweb.db (own) |
                        |  reader   : sloth.db RO       |
                        |  lookup   : OUI, names        |
                        |  http     : REST + SSE        |
                        +--------------+---------------+
                                       | 127.0.0.1:8770
                                       v
                               browser (one page)
```

Two databases, two owners:

| File | Owner | Mode in slothweb | Content |
|---|---|---|---|
| `sloth.db` | sloth | `SQLITE_OPEN_READONLY`, WAL reader | entity state, flows, findings (41 tables, schema v4) |
| `slothweb.db` | slothweb | read/write | time-series rollups, baselines, anomaly scores, lookup cache, UI prefs |

`sloth.db` holds `first_seen` / `last_seen` and high-water counters. It does not hold a time series. That is by design (the 38 GB/day problem). So "current vs average" cannot come from `sloth.db`. `slothweb` builds its own time series from the JSONL stream and keeps it in `slothweb.db`. This is the main new thing this project adds.

### 4.2 Folder layout

```
sloth/
  src/            unchanged
  tests/          unchanged
  web/                         <- everything for the web UI lives here
    README.md                  how to build, run, secure
    SPEC.md                    this document
    Makefile                   builds ./slothweb; called by top-level `make web`
    src/
      main.c                   args, wiring, signal handling
      http.c / http.h          HTTP/1.1 subset, static routes, SSE
      ingest.c / ingest.h      data-socket client, JSONL parse, reconnect
      json.c / json.h          small JSON reader and writer (C99, no deps)
      rollup.c / rollup.h      10s / 1m / 1h buckets
      baseline.c / baseline.h  hour-of-week EWMA, z-score, MAD
      anomaly.c / anomaly.h    device and host outlier rules
      store.c / store.h        slothweb.db schema and upserts
      reader.c / reader.h      read-only queries against sloth.db
      lookup.c / lookup.h      OUI, passive names, optional active PTR
      assets.c                 GENERATED: embedded ui/ files as byte arrays
    ui/
      index.html               one page, one <style>, one <script type=module>
      theme.css                :root tokens (the only place colour lives)
      app.js                   router, SSE client, state
      views/
        overview.js  activity.js  devices.js  anomalies.js
        wifi.js  alerts.js  flows.js  history.js  lookup.js
      lib/
        chart.js               canvas sparkline, band chart, bars
        heatmap.js             canvas grid heatmap
        table.js               virtualised sortable table
        color.js               palette, hash colour, heat ramp
      fonts/                   (not built: the Fonts ruling, no font file ships)
        FiraCode-Regular.woff2   FiraCode-Medium.woff2
        FiraCode-Bold.woff2      OFL.txt
    data/
      oui.csv                  IEEE MA-L (build input, not shipped)
      oui_table.c              GENERATED: sorted binary table
    tools/
      embed.py                 ui/ -> assets.c  (python3 stdlib, build only)
      build_oui.py             oui.csv -> oui_table.c (build only)
    tests/
      test_http.c  test_json.c  test_rollup.c  test_baseline.c
      test_anomaly.c  test_store.c  test_lookup.c  test_reader.c
```

Rules for the boundary:

- Nothing in `web/` includes anything from `src/` except `include/sloth.h` for constants (`MAX_DEVICES`, `DEV_SRC_*`, `ALERT_TYPE_*`). No sloth `.c` file is compiled into `slothweb`.
- Nothing in `src/` references `web/`. sloth builds and tests exactly as today when `web/` is deleted.
- Top-level `Makefile` gains two targets only: `web` and `web-test`. Both call `web/Makefile`.
- CI runs `make web-test` as a separate job.

### 4.3 Threads

`slothweb` uses three POSIX threads and one mutex-protected shared state block. This mirrors how sloth itself separates capture from render.

| Thread | Job | Cadence |
|---|---|---|
| ingest | read JSONL from the data socket, decode, update live state, feed rollup | as data arrives |
| tick | close the 10 s bucket, update baselines every 1 m, compact hourly, run anomaly rules, publish an SSE `tick` event | 1 Hz |
| http | accept, route, serve, hold SSE clients | as requests arrive |

## 5. Time series and baselines

### 5.1 Metrics

Each metric is a named counter or gauge with an optional key. The ingest thread derives them from JSONL records. This is the MVP set.

| Metric | Key | Source record | Type |
|---|---|---|---|
| `iface.rx_rate`, `iface.tx_rate` | iface name | `iface` | gauge |
| `host.rx_rate`, `host.tx_rate`, `host.conns` | ip | `top_host` | gauge |
| `dev.frames` | mac | `probe_client`, `assoc`, `seqnum_client` (`frame_count` delta) | counter |
| `dev.present` | mac | any record with that mac | presence (0/1 per bucket) |
| `dns.queries`, `dns.nxdomain` | src ip | `dns` | counter |
| `tls.handshakes` | src ip | `tls` | counter |
| `http.requests` | src ip | `http` | counter |
| `alerts.fired` | alert type | `alert` | counter |
| `wifi.ap_count`, `wifi.ctrl_total` | channel | `channel_summary` | gauge |
| `wifi.deauth` | bssid | `deauth` (`count` delta) | counter |
| `wifi.probe_clients` | (global) | `probe_client` distinct macs per bucket | gauge |
| `conns.total` | (global) | `connections` | gauge |
| `flow.ssh`, `flow.rdp`, `flow.smb`, `flow.snmp`, `flow.mqtt` | src ip | the `*_flow` records (count deltas) | counter |

Counters that arrive as high-water marks (`frame_count`, `count`) are turned into deltas by the ingest thread, with a floor at zero so an eviction and restart does not produce a negative value.

### 5.2 Rollup tiers

| Tier | Bucket | Retained | Rows per metric-key |
|---|---|---|---|
| fine | 10 s | 24 h | 8,640 |
| minute | 1 m | 30 d | 43,200 |
| hour | 1 h | 400 d | 9,600 |

Each row stores `sum`, `count`, `min`, `max`. A gauge's value for the bucket is `sum/count`. Compaction runs once an hour, after the write, like `db_maintain()`.

Cardinality is bounded the way sloth bounds it. `slothweb` tracks at most 512 device keys and 256 host keys for keyed metrics, LRU by `last_seen`. Global metrics are always kept. A `--web-max-keys N` flag adjusts this.

Estimated size at defaults: about 40 MB for a home network, about 300 MB for a busy office. A `--web-max-mb` ceiling drops the oldest fine-tier rows first, and never drops baselines.

### 5.3 Baseline model

The question is "is this normal for a Tuesday at 14:00." So the baseline is indexed by hour of week.

For each metric-key there are 168 baseline cells (7 days x 24 hours). Each cell holds an exponentially weighted mean and variance:

```
alpha = 1 - 2^(-1/N)      N = 4 samples (about four weeks per cell)
mean  = mean + alpha * (x - mean)
var   = (1 - alpha) * (var + alpha * (x - mean_old)^2)
```

Once an hour, when the hour bucket closes, the tick thread feeds its value to the matching cell. A cell with fewer than 3 samples is marked `warming` and the UI draws it grey, not green. This copies the `DB_AKM_SUSTAIN_S` idea: sloth is silent until it has a basis for the claim.

Two scores are computed for the current hour:

- **z**: `(x - mean) / sqrt(var + eps)`. Good for rates.
- **MAD ratio**: `|x - median| / MAD` over the last 28 same-cell samples, kept as a small ring. Good for bursty counters where one loud week would pull the mean.

The UI shows the band `mean ± 2 sd` behind the live line, and colours the live line by the heat ramp when it leaves the band.

Sensitivity is one slider in the UI (`1.5 sd` to `4 sd`). It changes drawing and the anomaly list. It does not change what is stored.

## 6. Anomaly rules

Rules run once a minute in the tick thread. Each produces zero or more `anomaly` rows with `kind`, `key`, `score` (0 to 100), `evidence` (text), `first_seen`, `last_seen`. Anomalies are episodes, like sloth alerts: one row that advances, not one row per minute.

| # | Rule | Kind | What it looks at |
|---|---|---|---|
| A1 | Activity out of band | `rate` | any keyed metric with `abs(z) >= threshold` for 3 consecutive minute buckets |
| A2 | New device | `new` | mac whose `first_seen` in `sloth.db` is inside the last 24 h |
| A3 | Off-hours presence | `hours` | device present in an hour-of-week cell where its `dev.present` baseline is below 0.1 and has 4 or more samples |
| A4 | Vendor unknown | `vendor` | OUI not in the full IEEE table (`DEV_RISK_UNKNOWN_VENDOR` also set by sloth against its small table; the web table is larger, so this is a stricter re-check) |
| A5 | Randomised MAC with a stable name | `ident` | `mac_random = 1` and a DHCP or mDNS hostname that also appears against another mac |
| A6 | Name disagreement | `ident` | DHCP hostname, mDNS host and NBNS name for the same ip do not agree |
| A7 | Talks to many | `fanout` | `host.conns` distinct peers in a 10 m window above the host's own p95 |
| A8 | Chatty DNS | `dns` | `dns.nxdomain` share above 30 percent with 20 or more queries in 10 m |
| A9 | Protocol first use | `proto` | a host produces its first `flow.ssh` / `flow.rdp` / `flow.smb` / `flow.snmp` / `flow.mqtt` ever |
| A10 | Sensor silence | `sensor` | no record of any type for 60 s while the socket is connected |

Rules A2, A4, A5, A6, A9 are lookups against `sloth.db` and the lookup module. Rules A1, A3, A7, A8 are baseline rules. A10 is health.

Every rule has a seeded-state test in `web/tests/test_anomaly.c`, following the `tests/test_alerts.c` pattern.

## 7. HTTP API

All routes are `GET`. Any other method returns `405`. Responses are JSON unless stated. Query times are Unix seconds. Bind is `127.0.0.1:8770` unless `--web-bind` says otherwise.

| Route | Returns |
|---|---|
| `/` | the embedded page |
| `/assets/...` | embedded CSS, JS, fonts, with `Cache-Control: immutable` and an ETag from the build hash |
| `/api/health` | socket state, last record age, `sloth.db` schema version, rows, uptime |
| `/api/live` | the current in-memory snapshot: devices, hosts, alerts, channels (what the TUI shows) |
| `/api/series?metric=&key=&from=&to=&tier=` | buckets `[t, avg, min, max, n]` plus the baseline band for the same range |
| `/api/baseline?metric=&key=` | the 168 cells, for the hour-of-week heatmap |
| `/api/anomalies?since=&kind=` | open and recent anomaly episodes |
| `/api/devices?q=&sort=&limit=&offset=` | joined view of `devices`, `pnl_clients`, `arp`, `dhcp_leases`, vendor lookup, name lookup |
| `/api/device/{mac}` | one device with everything known: PNL SSIDs, assocs, probe history, presence heatmap, anomalies, alerts that name it |
| `/api/host/{ip}` | one host: flows, DNS it asked, TLS SNI it used, ports seen, presence heatmap |
| `/api/alerts?since=&sev=` | from `sloth.db alerts` joined with `slothweb` anomaly context |
| `/api/wifi/channels?from=&to=` | channel x time grid for the channel heatmap |
| `/api/wifi/aps` | `beacon_aps` with SSID history and KARMA score |
| `/api/lookup?mac=` and `/api/lookup?ip=` | vendor, passive names with their source and time, and active PTR only if enabled |
| `/api/search?q=` | one box that searches mac, ip, hostname, vendor, ssid, alert title; returns typed hits |
| `/api/query?sql=` | **disabled by default.** With `--web-allow-sql`, runs a read-only `SELECT` against `sloth.db` with `sqlite3_set_authorizer` denying everything except `SQLITE_READ` and `SQLITE_SELECT`, a 5 s timeout, and a 10,000 row cap. For the operator's own recipes from `sqlite-schema.md`. |
| `/events` | SSE stream (see below) |

### 7.1 SSE events

Server-Sent Events, not WebSocket. Reasons: one direction is all this needs, the protocol is plain HTTP text with no framing or masking to implement in C, browsers reconnect for free, and `Last-Event-ID` gives replay.

| event | cadence | payload |
|---|---|---|
| `tick` | 1 s | `{ts, rx, tx, conns, devices, alerts_open, anomalies_open}` for the header strip |
| `record` | as they arrive, coalesced to at most 20 per second | raw JSONL records the client asked for with `?types=dns,tls,alert` |
| `bucket` | every 10 s | closed fine buckets for metrics the client subscribed to |
| `anomaly` | on change | one anomaly episode opened, updated or closed |
| `alert` | on change | one alert row |
| `health` | on change | socket connect, disconnect, schema mismatch |

The client keeps a 24 h fine-tier ring in memory per visible metric and asks `/api/series` for anything older. That keeps the page smooth and the server cheap.

## 8. User interface

### 8.1 Design tokens

> **Amended 2026-10-26** (the Design ruling above, 2026-10-23). The
> 2026-09-30 draft's token block (the "Dark Factory" skin: `--bg`
> `#0a0a0a`, `--radius: 0`, square corners, the eight `--t-*`
> record-type hues) is retired and no longer printed here, so it cannot
> be built by mistake. What the page serves:

- **Chrome:** `web/ui/theme.css`. The Spacetrucker tokens (`--void`,
  `--dim`, `--brass`, `--amber`, `--ice`, `--paper`, ...) mapped onto
  the page's semantic names (`--bg`, `--panel`, `--rule`, `--ink`,
  `--muted`, `--faint`, `--signal`, `--data`), `--radius: 14px`,
  `--gap: 8px`, and the light theme under `:root[data-theme="light"]`.
  `web/tests/test_routes.c :: test_design_tokens_are_spacetrucker`
  pins the served values.
- **Data:** `build/web/palette.css` and `palette.js`, written at build
  time by `web/tools/palette.c` from the TUI's colour-pair table
  (`tui_pair_colors()`) and `find_brand()`'s table: `--k-*` (address and
  SSID hash), `--br-*` (brands), `--info-*`, `--tui-bright/normal/dim`,
  `--heat-*` (with `--sev-*` on them), `--hot-*` (the alert-hot
  override), `--mon-bg`/`--mon-fg` (monitor rows). The light theme
  darkens each by one recorded rule to 4.5:1. `web/tests/test_tui_colors.c`
  compares them with what `src/tui.c` writes.
- **Chart hues** with no TUI counterpart (`--f-*`, the Flows chord)
  are in `theme.css`, each named in the legend; the generator fails the
  build if two come within 15 (CIEDE2000) in either theme.

`web/README.md`'s Design section has the mapping table and the computed
contrast tables (`make web-contrast`).

### 8.2 Typography

> **Amended 2026-10-26** (the Fonts ruling above): no font file is
> embedded and none is fetched. The stack is `"Fira Code", ui-monospace,
> "SF Mono", Menlo, "DejaVu Sans Mono", monospace`, so Fira Code is used
> only where the operator has it installed. The paragraph below is the
> superseded draft.

FiraCode is the only typeface. It is embedded as three `woff2` files (Regular, Medium, Bold, about 100 KB each) with the OFL licence text beside them, and declared with `@font-face` and `font-display: swap`. The stack falls back to the system monospace so nothing breaks if a font fails to decode. FiraCode is under the SIL Open Font License 1.1, which permits bundling and redistribution with the licence file included. Version 6.2 is current in the distro packages.

Ligatures are on for code and off in tables (`font-variant-ligatures: none` on `td`), so `->` in a hostname does not render as an arrow. Tabular figures are on everywhere (`font-variant-numeric: tabular-nums`), so columns of numbers line up.

Sizes: 11 px labels, 12 px table body, 13 px body, 20 px KPI numbers, 28 px hero number on Overview. Nothing smaller than 11 px.

### 8.3 Layout

Rubric scaffold bones: a 220 px left sidebar with the view list and a status footer, a top strip, and a main area. The sidebar collapses with `[`. `/` focuses search from any view. Keyboard `1`..`9` switch views. Every view fits a 1280 x 800 window without horizontal scroll and stacks to one column below 900 px.

```
+----------+--------------------------------------------------------+
| SLOTH    | * connected  rx 2.4 MB/s  tx 310 KB/s  devs 42  alerts 1|  <- tick strip
| web      +--------------------------------------------------------+
|          |                                                        |
| 1 Overview                                                        |
| 2 Activity|                    view area                          |
| 3 Devices |                                                       |
| 4 Anomalies                                                       |
| 5 WiFi    |                                                       |
| 6 Alerts  |                                                       |
| 7 Flows   |                                                       |
| 8 History |                                                       |
| 9 Lookup  |                                                       |
|          |                                                        |
| ---------|                                                        |
| window v |                                                        |
| 1h 6h 24h|                                                        |
| 7d 30d   |                                                        |
| sens --o-|                                                        |
| sock ok  |                                                        |
| db  v4   |                                                        |
+----------+--------------------------------------------------------+
```

The time window and sensitivity controls are global and persist in `localStorage`, second-brain style.

### 8.4 View: Overview

The "is anything on fire" screen. Two seconds to read.

- Row 1, four KPI tiles: throughput, active devices, open alerts, open anomalies. Each tile has a 24 h sparkline with the baseline band behind it and the live value coloured by the heat ramp when out of band.
- Row 2, left: **Now vs normal** band chart for total throughput over the selected window. Right: the **hour-of-week heatmap** for total activity, 7 rows x 24 columns, with the current cell outlined in `--signal`.
- Row 3, left: the five highest-scoring anomalies as compact cards. Right: the most recent alerts, coloured by severity.
- Row 4: a live record ticker (the last 50 records, coloured by record type) that can be paused.

### 8.5 View: Activity

The current-vs-average workbench.

- Metric picker (from §5.1) and key picker (interface, host, device, channel).
- Main band chart: live line, `mean ± 2 sd` band, `warming` cells hatched. Hover gives the bucket value, the baseline mean, the z-score.
- Under it, a **small-multiples grid**: one sparkline per key, sorted by `abs(z)` descending, so the outlier is top left. Each sparkline is colour-coded by key with the hash colour from §8.12, and its frame turns heat-coloured when out of band.
- Toggle: absolute values, or ratio to baseline (`x / mean`), which puts a 10 KB/s IoT device and a 50 MB/s NAS on the same axis.

### 8.6 View: Devices

The device database. Data comes from `sloth.db` joined with `slothweb` lookups.

- Search box with a small query language (§9.1).
- Virtualised table, 60 fps at 512 rows. Columns: mac (with a colour swatch), vendor, ip, name (best passive name, with a source glyph: `D` DHCP, `m` mDNS, `N` NBNS, `p` PTR seen on the wire, `P` active PTR), last SSID, signal, sources (bit glyphs: `A`RP `D`HCP `P`robe `B`eacon `S`TA), risk, first seen, last seen, `z` now, anomaly count.
- Row colour: the mac's hash colour on the swatch only. Text stays `--ink` and `--muted`. Rows with `risk_level > 0` get a left border in the severity colour. Rows with `mac_random = 1` show the mac in `--muted` with a `~` prefix.
- Presence strip: a 24 h mini heatmap per row (144 cells of 10 minutes) showing when the device was present. This is the fastest way to spot the device that only appears at 3 AM.
- Click a row: a drawer slides in (second-brain viewer style) with the full `/api/device/{mac}` record: PNL SSIDs, associations with evidence grade, probe history, the 168-cell presence heatmap, anomalies, alerts, and the lookup panel.

### 8.7 View: Anomalies

Open episodes first, then closed ones in the selected window. Each card: kind glyph, key, score bar in the heat ramp, evidence text, sparkline of the metric that fired, first and last seen. Filter chips by kind. A click opens the device or host drawer.

### 8.8 View: WiFi

- **Channel x time heatmap**: rows are channels (2.4, 5, 6 GHz grouped with a rule between bands), columns are time buckets. Cell colour is `ap_count` or `ctrl_total` (toggle). Reads like a spectrum waterfall.
- **AP table**: `beacon_aps` with SSID history, AKM bits, downgrade flags, MFP, KARMA score. SSID count above 1 is highlighted in `--sev-warn`.
- **Deauth timeline**: bars per bssid, flood episodes in `--sev-crit`.
- **Probe clients**: count over time with band.

### 8.9 View: Flows

Protocol flow tables from `sloth.db` (`ssh_flows`, `rdp_flows`, `smb_sessions`, `snmp_flows`, `mqtt_flows`, `ldap_events`, `kerb_events`, `bgp_sessions`) in one tabbed table, plus a **chord or arc diagram** of src to dst pairs, coloured by protocol hue, drawn on canvas. SMB1 rows are `--sev-crit`. This is the one place a relationship drawing earns its space. It is a post-MVP view.

### 8.10 View: History

The time-travel browser.

- A range picker (drag on a 30 d overview strip) sets `from` and `to`.
- The **who was here** query as a UI: devices whose `[first_seen, last_seen]` overlaps the range, with the presence heatmap restricted to that range.
- Alerts, anomalies and flows in the range.
- Survey sessions from `sessions` as markers on the strip, with "new since previous session" as one click (the `--report` logic, in the browser).
- An **SQL box** appears only when the server was started with `--web-allow-sql`. It prefills the recipes from `sqlite-schema.md`.

### 8.11 View: Lookup

One input. Paste a mac or an ip. Output is a card: vendor (with the OUI block and whether the mac is locally administered or randomised), every passive name with its source and when it was seen, and the device or host record if sloth has one. Active PTR shows only if enabled, with the label `ACTIVE QUERY` in `--signal` so the operator knows a packet went out.

### 8.12 Visual motifs, summarised

| Motif | Where | Rule |
|---|---|---|
| Baseline band | every time chart | `mean ± 2 sd` in 12 percent `--data`, live line in `--ink`, out-of-band segments coloured by heat ramp |
| Hour-of-week heatmap | Overview, device drawer, host drawer | 7 x 24 grid, heat ramp, current cell outlined in `--signal`, warming cells hatched grey |
| Presence strip | Devices table | 144 x 1 grid, `--phosphor` for present, `--bg` for absent |
| Channel waterfall | WiFi | channels x time, heat ramp |
| Record-type hue | tickers, logs, flow tables | retired 2026-10-23 (§8.1): a record's info text takes the TUI's `--info-*` tone, its addresses their hash colour, and a monitor-radio record the TUI's monitor row (`--mon-bg`); the type is always a word |
| Client hash colour | swatches, small-multiple frames | `ip_color_index` port: djb2 over the key's UTF-8 bytes, modulo 8, into the TUI's own 8 hues (`--k-*`, generated; §8.1). Same key, same colour, in TUI and web. |
| Severity | alerts, borders, anomaly scores | low `#d7af00`, warn `#ff8700`, crit `#ff0000`, matching TUI and sloth-ios |
| Signal orange | selection, live alert, active-query label | one at a time; if two things are orange, one is wrong |

Every colour meaning is also carried by a glyph or a word, so the page still reads in greyscale.

## 9. Search and lookup tools

### 9.1 Device query language

Free text matches mac, ip, hostname, vendor, SSID. Prefixes narrow it:

```
vendor:apple            mac:b8:27:eb           ip:192.168.1.
ssid:CorpWiFi           name:printer           random:yes
seen:>2026-09-29        seen:<24h              first:<7d
risk:>0                 z:>3                   src:probe
has:pnl                 has:alert              anomaly:hours
```

Terms combine with AND. `-` negates. The parser is 200 lines of C with a fuzz test. Results come from one prepared statement against `sloth.db` with parameters, never string-built SQL.

### 9.2 Vendor lookup (OUI)

sloth ships a 123-entry OUI table in `src/oui.c`. That is right for a 14k-line embedded binary. `slothweb` ships the full IEEE MA-L registry (about 37,000 assignments) compiled at build time from `oui.csv` into a sorted array of `{uint32 oui, uint16 name_index}` plus a string pool, about 700 KB in the binary, binary-searched like `oui.c`. The build tool also folds in MA-M (28-bit) and MA-S (36-bit) blocks so small vendors resolve.

`oui.csv` is downloaded by the developer, not at build time on the sensor, and is checked into `web/data/` with its date. Refreshing it is a documented manual step. The sensor never fetches anything.

The card also reports: locally administered bit set (randomised or software mac), multicast bit set, and whether the block is a registered vendor or a private range.

### 9.3 Name lookup (reverse DNS and friends)

Passive first, always. Sloth already sees most names on the wire:

| Source | sloth table or record | Confidence |
|---|---|---|
| DHCP hostname | `dhcp_leases.hostname` | high, self-declared |
| mDNS | `mdns_services.host` | high on Apple and IoT |
| NBNS | `nbns_names.name` | high on Windows |
| PTR answers seen on the wire | `dns` records with `qtype = PTR` and `is_resp = 1`, kept in `slothweb.db passive_ptr` | medium |
| TLS SNI the host connected to | `tls.host` | not a name for the host, but shown as "talks to" |
| sloth's own `hostname` field | `devices.hostname`, `top_hosts.hostname` | as sloth graded it |

`slothweb` records PTR answers it sees in the stream so that, over time, the passive PTR cache fills without sending a query.

**Active reverse DNS is off by default.** MISSION §2.1 says sloth never resolves hosts it did not see. `slothweb` is a separate program, and the device it looks up was seen, but a PTR query is still a packet on the network, to a resolver the operator may not control, that reveals the operator is asking about that ip. So:

- `--web-active-rdns` enables it. Off, the UI never shows the button.
- On, it runs only on click, never in bulk, never on page load.
- The query uses `getnameinfo()` with `NI_NAMEREQD`, a 2 s timeout, and results are cached in `slothweb.db` with a 24 h TTL and the `active` flag.
- Every active result is labelled `ACTIVE QUERY` in the UI and logged to stderr.

This keeps sloth passive, keeps `slothweb` passive by default, and gives the operator the option with full knowledge. The README says this in the same words.

There is no WHOIS, no GeoIP, no external API. If GeoIP is wanted later, it is the same pattern: an offline database checked in, never a network call.

## 10. The MVP web server

### 10.1 Why write one

Options considered:

| Option | Dependencies on the sensor | Fit |
|---|---|---|
| Node zero-dep (rubric pattern) | Node 18+ runtime, about 100 MB | Fine on a Mac. Not fine on an SBC beside a C99 sensor that prides itself on `make embedded`. |
| Python stdlib `http.server` | python3, present on most Linux | Simple, but a second language in the repo, slow SSE fan-out, and the GIL fights the ingest thread. |
| libmicrohttpd or civetweb | one C library | Good servers, but a new dependency and a new licence to track. |
| **C99, in-tree, about 1,500 lines** | `libsqlite3` only, already linked | One language, one test harness, `make web-test` alongside `make test`. Matches how sloth already wrote its own JSON, JSONL, data socket and SQLite layers. |

The last one is the recommendation. The subset of HTTP that this needs is small, and sloth already has the habits (fixed buffers, bounded arrays, hand-crafted protocol tests from RFC bytes).

### 10.2 What the server implements

- HTTP/1.1 `GET` and `HEAD` only. `405` for the rest. No request body is read past 1 KB of headers.
- Request line and headers parsed into fixed buffers, 8 KB max, `431` on overflow.
- Routes: exact-match table, plus `/assets/` prefix and `/api/device/` and `/api/host/` prefixes.
- Static assets served from `assets.c` byte arrays with correct `Content-Type`, `ETag`, `Cache-Control`. `If-None-Match` gives `304`.
- JSON responses built with the small writer in `json.c`, which escapes per RFC 8259 the way `jsonl.c` does.
- SSE: `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: keep-alive`, a 15 s `: ping` comment, up to 32 concurrent clients, slow clients dropped after 64 KB of unsent data.
- `poll()` loop on one thread, non-blocking sockets, `SO_REUSEADDR`, `TCP_NODELAY`.
- Bind `127.0.0.1` default. `--web-bind ADDR:PORT` to change. Binding a non-loopback address prints a warning that names issue #86.
- `--web-token TOKEN`: when set, every `/api/*` and `/events` request must carry `x-sloth-token` or `?token=`, or gets `401`. The page stores the token in `sessionStorage` after the first prompt.
- No CORS headers. Same-origin only.
- `Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'`. No external origin can load.
- Runs as the invoking user. It does not need root. The README recommends a dedicated user with read access to `sloth.db` and the socket.

### 10.3 Command line

```
slothweb [options]
  --socket SPEC          data socket to consume: unix:/path or tcp:HOST:PORT (required)
  --db PATH              sloth.db to read (optional; history views need it)
  --store PATH           slothweb.db (default: ./slothweb.db)
  --web-bind ADDR:PORT   default 127.0.0.1:8770
  --web-token TOKEN      require a shared token on /api and /events
  --web-allow-sql        enable the read-only SQL box
  --web-active-rdns      allow on-click PTR lookups (sends DNS queries)
  --web-max-keys N       keyed metric cardinality (default 512)
  --web-max-mb N         store ceiling (default 256)
  --web-retain-days N    minute tier retention (default 30)
```

### 10.4 Tests

`make web-test` builds `slothweb_test` with the same `main_test.c` style as sloth.

- `test_http.c`: hand-written request bytes, including a split header across two reads, an oversize header, a `POST`, a missing token, a `HEAD`, `If-None-Match`, and an SSE client that disconnects mid-write.
- `test_json.c`: RFC 8259 escaping, nesting depth cap, malformed input.
- `test_rollup.c`: bucket boundaries, counter deltas with eviction reset, compaction.
- `test_baseline.c`: EWMA against a known sequence, warming state, z and MAD.
- `test_anomaly.c`: one seeded state per rule, fires, then does not fire when the state is normal.
- `test_store.c`: schema, upsert semantics, the secret-column guardrail copied from `test_db.c`.
- `test_lookup.c`: OUI hits and misses, locally administered bit, passive name precedence, active PTR disabled by default.
- `test_reader.c`: opens a fixture `sloth.db` read-only and runs every prepared statement.

Coverage target: the same bar as sloth, and `make mutate` runs on `web/` too.

## 11. Non-goals

- No writes to sloth, `sloth.db`, the network, or the host from the browser. Ever.
- No user accounts. One token, or none.
- No TLS in `slothweb`. Put it behind Tailscale or an SSH tunnel, the same advice sloth gives for the data socket. Issue #100 tracks TLS for the socket; if that lands, `slothweb` follows the same pattern.
- No mobile layout beyond stacking. sloth-ios is the mobile client.
- No plugin system. Views are files in `web/ui/views/`; adding one is a code change with a test.
- No light theme in the MVP.

## 12. Milestones

Each milestone is a shippable state with an acceptance check, in dark-factory style: one production order per milestone, green on first converge.

| # | Milestone | Acceptance |
|---|---|---|
| M0 | Skeleton: `web/` folder, Makefile, `slothweb` binds, serves the embedded page with FiraCode, `/api/health`, SSE `tick` with a fake counter. `make web-test` green. | Open `http://127.0.0.1:8770`, see the tick strip move, no external requests in the browser network tab. |
| M1 | Ingest and live: data-socket client with reconnect, live state, `/api/live`, Overview KPI tiles and record ticker. | Run beside `sloth --data-socket unix:/tmp/sloth.sock`; Overview shows the same device count as the TUI within 5 s. |
| M2 | Time series: rollup tiers, `slothweb.db`, `/api/series`, band charts without baselines, Activity view, small multiples. | After 1 h of running, the 24 h chart shows the last hour at 10 s resolution and the store is under 5 MB. |
| M3 | Baselines and anomalies: hour-of-week cells, z and MAD, rules A1 to A10, Anomalies view, heatmaps on Overview. | Replay a 7 d JSONL fixture at speed; A3 fires for a device that appears only at night; A1 fires for a synthetic burst; nothing fires on the quiet fixture. |
| M4 | Devices and lookup: `sloth.db` read-only reader, Devices table with presence strips, query language, OUI table, passive names, drawer, Lookup view. Active PTR behind the flag. | `vendor:apple random:yes seen:<24h` returns the right rows against the fixture database; a mac from a small vendor resolves that sloth's 123-entry table misses. |
| M5 | WiFi and History: channel waterfall, AP table, deauth timeline, range picker, who-was-here, sessions, SQL box behind the flag. | The `sqlite-schema.md` recipes run from the SQL box and match the `sqlite3` CLI output. |
| M6 | Flows view, chord diagram, polish, README with the security section, screenshots for the sloth README. | A stranger with the README can run it in five minutes. |

M0 to M4 are the MVP. A part-time estimate for M0 to M4 in the dark-factory loop is four to six weeks, with the C server (M0) and the baseline engine (M3) as the two largest orders.

## 13. Decisions that need the operator

1. **Port.** `8770` is proposed (sloth's data-socket example uses `8765`). Rubric is on `5050`, agentic OS on `50000`, second brain on `5210` and `5211`. Any of those are avoided.
2. **Name.** `slothweb` as the binary and folder name, or `web/` folder with binary `sloth-web`. The spec uses `slothweb`.
3. **C99 server** versus a zero-dep Node server in the rubric pattern. The spec recommends C99 (§10.1). Node would be faster to write and slower to own on the sensor.
4. **Active reverse DNS** as an opt-in flag (§9.3), or left out entirely to keep the passive claim absolute. The spec proposes the flag with the `ACTIVE QUERY` label.
5. **The SQL box** (§7, `/api/query`). It is powerful and it is a query surface. Behind a flag it is the operator's own `sqlite3` in a browser. Keep or cut.
6. **Baseline half-life.** Four weeks per cell is proposed. Two weeks adapts faster and alarms more; eight is calmer.
7. **Should `slothweb` write anything back into `sloth.db`?** The spec says never. Confirm.

## 14. Sources

In-tree and local, read on 2026-09-30:

- `MISSION.md`, `SECURITY.md`, `src/db.h`, `src/db_schema.c`, `src/oui.c`, `src/ip_color.h`, `docs/wiki/sqlite-schema.md`, `docs/wiki/jsonl-schema.md`, `examples/consumer/README.md`, `docs/views/*`, open issues #84, #86, #91, #100
- `sloth-ios`: `App/Theme.swift` (phosphor and heat hues), `App/Charts/*`, `App/Views/*`
- `rubric`: `README.md`, `templates/scaffold/index.html` (tokens, layout, polling), `templates/flows`, `templates/skill-trees`
- `rubric-second-brain`: `README.md`, `public/index.html` (skin object, themes), `public/_core.css`, `public/_core.js` (layouts, canvas), `server.js` (endpoints)
- `rubric-agentic-os` and `river-agentic-os`: `README.md`, `REDESIGN.md`

Web:

- Fira Code, SIL OFL 1.1: https://www.fontsquirrel.com/fonts/Fira-Code and https://salsa.debian.org/fonts-team/fonts-firacode/-/blob/master/LICENSE
- Fira Code 6.2 packaging: https://archlinux.org/packages/extra/any/woff-fira-code and https://packages.guix.gnu.org/packages/font-fira-code/6.2/
- IEEE registry CSVs, committed in `web/data/` (2026-10-26 ruling; `web/data/SOURCE.md`): https://standards-oui.ieee.org/oui/oui.csv, https://standards-oui.ieee.org/oui28/mam.csv, https://standards-oui.ieee.org/oui36/oui36.csv, https://standards-oui.ieee.org/iab/iab.csv
