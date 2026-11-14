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
> | Capture scope | **2026-10-26 (owner request):** a Monitor / Hybrid / Local switch in the top bar filters every view by how the data was captured: Monitor the passive monitor radio (and BLE), Local the host's own interfaces (managed Wi-Fi scans included), Hybrid everything (the default). Every `/api` route but `/api/health` and `/api/query` takes `scope=`; a datum's scope is decided by its type in `web/src/web_scope.c`; a device seen both ways shows each scope's own fields; the SQL box is unscoped. `sensor_health` gains `capture_linktype` and `monitor_only`. `docs/wiki/capture-scope.md` is the reference. | §7, §8 (every view) |
> | Radar view | **2026-11-06 (owner request):** a Radar tab, one half-dome of every radio heard (§8.14). Its dome and its ◇ ▲ ○ marks have no character-cell form (the TUI's `[#]` sky plot is the nearest relative), so the view is **exempt from R12** of `docs/web-visual-spec.md` as an owner ruling, not an oversight; the marks still carry shape and word (R10), the chrome has no gradient, shadow or fill (R8), the selection is the one accent (R1). | visual spec R12, for this view only |
> | APRS and ADS-B radar scopes | **2026-11-13 (owner request):** "i want the positions view in aprs to look like an air traffic control radar with our GPS loctioin in the center." The APRS tab's positions canvas is a plan position indicator centred on the sensor: range rings, a bearing rose, a sweep that re-lights each blip (stepped alpha steps, no gradient, so R8 holds; still under reduced motion), velocity leaders and data blocks. **2026-11-14 (owner request):** "we were supposed to be adding a radar type display to ads-b like aprs has": the ADS-B positions canvas is the same scope (`web/ui/ppi.js`), in nautical miles, aircraft as ▲ on their track coloured by altitude (the tab's existing heat ramp). Like the Radar dome neither scope has a character-cell form, so this canvas is **exempt from R12** by owner ruling; its marks keep the Radar's APRS ○ (R10), the selection stays the one accent (R1). | visual spec R12, for the two scopes only |
> | Radar Wi-Fi hues | **2026-11-13 (owner request):** "instead of on the n/s axis in the radar use the data to plot the most probably point location. color code the wifi points and light transparent polygons for the shape of the estimated location polygon." On the Radar dome only, each Wi-Fi device's mark and its fleet polygon take one of five categorical hues (`--rw-0..4`, `web/ui/theme.css`) by a hash of its MAC, so a point and its area read as a pair. This **overrides R10 ("shapes not hues") for Wi-Fi colour in this view**; the shapes still carry the meaning (■ station, ◆ access point, ● BLE; solid located, hollow distance only), `web/tools/palette.c` holds the hues apart and off the selection, heat, BLE and ink hues in both themes, and the selection stays the one accent (R1). The devices leave the north axis (§8.14). | visual spec R10, for the Radar's Wi-Fi marks and areas only; §8.14's north axis (2026-11-06) |
> | Vendor research's place | **2026-11-11 (owner request):** in the device drawer (the detail view of a WiFi client or access point, and of every other device) the vendor research section is the last block, after the record, the lists, presence, signal, the week, anomalies and the FRRS record. The Lookup card keeps it under the OUI card. | §8.6's drawer order |
> | SSID detail | **2026-11-11 (owner request):** every SSID the page writes is selectable and opens a detail drawer built as the device drawer is (§8.8), from `/api/wifi/ssid?ssid=`, the name as the base64url of its octets. Read-only, the existing column allow-list, Monitor's and Hybrid's. | §8.8 (no SSID view), §7's route list |
> | Probes view | **2026-11-11 (owner request):** a Probes tab (§8.15): the stations heard probing with the SSIDs each asked for and what sloth ties each to, the SSIDs searched for, and the stations probing for the same uncommon SSIDs. sloth.db only, nothing stored; Monitor's and Hybrid's. | §8.8's "Probe clients" line is the WiFi tab's and stays |

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

**Triage and links (added 2026-11-11, owner request).** An anomaly is triaged exactly as an alert is (`docs/web-frrs-spec.md` §15): the same states (`untriaged`, `false`, `noise`, `incident`, `known`), the same optional 240-byte note, the same append-only history, through the same write route and its guards. Its subject is the finding, `tid` = `a` + FNV-1a 64 of (rule name, metric name, key), every episode of it, as an alert's is every incident of its key; each row records the episode (`first_seen`) it was made on and a state from an earlier episode is marked *carried*. An anomaly can be linked by the operator to an alert, another anomaly or a device, the link read from both ends; findings on the same MAC or IP address within 10 minutes are offered as "possibly related" and stored only when accepted. slothweb.db v9 (`anom_subject`, `relation`).

## 7. HTTP API

All routes are `GET`. Any other method returns `405`. Responses are JSON unless stated. Query times are Unix seconds. Bind is `127.0.0.1:8770` unless `--web-bind` says otherwise.

| Route | Returns |
|---|---|
| `/` | the embedded page |
| `/assets/...` | embedded CSS, JS, fonts, with `Cache-Control: immutable` and an ETag from the build hash |
| `/api/health` | socket state, last record age, `sloth.db` schema version, rows, uptime |
| `/api/live` | the current in-memory snapshot: devices, hosts, alerts, channels (what the TUI shows) |
| `/api/series?metric=&key=&from=&to=&tier=` | buckets `[t, avg, min, max, n]` plus the baseline band for the same range |
| `/api/series/all?metric=&tier=&from=&to=&cols=&after=` | every key of one metric in the window (the rollup's and the store's; `total` on the first answer), each merged into at most `cols` cells (8..480) as a sparse `[i, v, ...]`, keys in byte order, at most 128 to an answer and fewer once it is full or has run 100 ms, with `more` / `next` (2026-11-11, the Activity chart's `keys: all`) |
| `/api/baseline?metric=&key=` | the 168 cells, for the hour-of-week heatmap |
| `/api/anomalies?since=&kind=` | open and recent anomaly episodes, each with `tid`, the id its triage and links are filed under (2026-11-11) |
| `/api/frrs/related?id=` | an alert's, an anomaly's or a device's links, the other end's triage, and the candidates (2026-11-11); `POST /api/frrs/relate` adds or removes a link (the write surface is `docs/web-frrs-spec.md` §5.2 and §15) |
| `/api/devices?q=&sort=&limit=&offset=` | joined view of `devices`, `pnl_clients`, `arp`, `dhcp_leases`, vendor lookup, name lookup |
| `/api/device/{mac}` | one device with everything known: PNL SSIDs, assocs, probe history, presence heatmap, anomalies, alerts that name it |
| `/api/host/{ip}` | one host: flows, DNS it asked, TLS SNI it used, ports seen, presence heatmap |
| `/api/alerts?since=&sev=` | from `sloth.db alerts` joined with `slothweb` anomaly context |
| `/api/wifi/channels?from=&to=` | channel x time grid for the channel heatmap |
| `/api/wifi/aps` | `beacon_aps` with SSID history and KARMA score |
| `/api/lookup?mac=` and `/api/lookup?ip=` | vendor, passive names with their source and time, and active PTR only if enabled |
| `/api/search?q=` | one box that searches mac, ip, hostname, vendor, ssid, alert title; returns typed hits |
| `/api/query?sql=` | **disabled by default.** With `--web-allow-sql`, runs a read-only `SELECT` against `sloth.db` with `sqlite3_set_authorizer` denying everything except `SQLITE_READ` and `SQLITE_SELECT`, a 5 s timeout, and a 10,000 row cap. For the operator's own recipes from `sqlite-schema.md`. |
| `/api/ble?sort=&dir=&limit=&offset=&q=` | the BLE advertisers slothweb keeps from the stream's `ble_device` records (2026-11-01; §8.13); `sloth.db` has no BLE table |
| `/api/ble/alerts` | the `ble_alert` findings, standing first |
| `/api/ble/{addr}?type=&iface=` | one advertiser's rows (one per sensor), its rate points, its 24 h presence strip and the findings naming it |
| `/api/ble/classes?from=&to=&cols=&metric=advertisers\|adv` | the BLE Devices view's class x time grid of `ble.class.advertisers` (gauge) or `ble.class.adv` (counter), the WiFi channel grid's tiers and cells, Trackers always a row (2026-11-02; §8.13) |
| `/api/ble/classes?from=&to=&cols=&mix=1` | the class mix: `/api/wifi/channels?mix=1`'s answer with `rows` for `channels` and a BLE advertiser per `tx` entry, anonymous advertising one `anonymous` entry in `b:unk` |
| `/api/ble/proximity?from=&to=&cols=&n=12\|24\|48` | the advertisers heard in the window (at most 256 read, every tracker first), trackers first then nearest by signal less the row's announced power, each with its mean `rf.rssi.ble` per cell, its P_tx and band edges; no anonymous row and no read slot for one (`anonymous_heard` says one was left out) |
| `/api/gnss?limit=`, `/api/gnss/fixes?since=&limit=` | the GPS Sat tab's receiver, satellites and kept fixes (2026-11-02) |
| `/api/adsb?limit=` | the ADS-B tab's decoder health and aircraft with their kept tracks (2026-11-05); Monitor's and Hybrid's |
| `/api/gnss/tracks?hours=` | the GPS Sat sky plot's trails from `gnss_sightings` (2026-11-05) |
| `/api/gnss/seen?days=&limit=`, `/api/gnss/sat?gnssid=&prn=&days=` | the GPS Sat tab's history from sloth.db's `gnss_sightings`: satellites seen over a window, one satellite's records (2026-11-05) |
| `/api/adsb/seen?days=&limit=&offset=&q=`, `/api/adsb/aircraft?hex=&days=` | the ADS-B tab's history from sloth.db's `adsb_aircraft` / `adsb_sightings` (v12): aircraft seen over a window, one aircraft's row and sightings (2026-11-05); Monitor's and Hybrid's |
| `/api/spectrum`, `/api/spectrum?status=1` | the Spectrum tab: `sloth-sdrsweep`'s status and its latest sweep, re-serialised (2026-11-13, docs/wiki/sdr-sweep.md); the sweep is Monitor's and Hybrid's, the status every scope's |
| `POST /api/spectrum/run` | the Spectrum tab's one control: an empty request file for `sloth-sdrsweep.path`, behind the write gate; 409 while running or queued, 429 in the cooldown (2026-11-13, owner-approved; the second reversal of "no control endpoint", after triage) |
| `/api/aprs?limit=&call=` | the APRS tab's decoder health and stations, or one station with its track and recent packets (2026-11-05); Monitor's and Hybrid's |
| `/api/aprs/seen?days=&limit=&offset=&q=`, `/api/aprs/station?call=&days=` | the APRS tab's history from sloth.db's `aprs_stations` / `aprs_packets` (v13): stations heard over a window, one station's row and packets (2026-11-05); Monitor's and Hybrid's |
| `/api/aprs/tracks?hours=` | the Radar tab's APRS entities from sloth.db's `aprs_packets` over 1..24 h: stations and, by name, objects and items, each with its newest packet's time, newest position, motion, status, comment and a moving one's trail (≤ 48 points) (2026-11-06); Monitor's and Hybrid's |
| `/api/sys` | the Sensor health view's host status (2026-11-11): the newest `sys_status`, its `sys_sensor` rows, every `source_status` and `receiver_hw` (JSONL 1.1.0), `null` for a figure the host does not have; no parameter; every scope's |
| `/api/radar` | the Radar tab's Wi-Fi and BLE distance-band census: totals, the rows without an estimate, per band the count and eight strongest rows, and `devs`, each family's 50 most recently heard rows with an estimate (metres, band, trend) (2026-11-06); Monitor's and Hybrid's, no parameter |
| `/api/wifi/ssid?ssid=` | one SSID's detail (2026-11-11): its BSSIDs now and once with vendor, channel, security, signal, KARMA score and twin links; the stations associated to it and asking for it; its 24 h presence; the alerts naming it or a BSSID of it. `ssid` is the base64url of its octets, `-` for the hidden SSID; compared with `=`, never a pattern |
| `/api/probes/clients?days=&sort=&limit=&offset=` | the Probes tab's stations (2026-11-11): each MAC of `probe_clients` or `pnl_clients` last seen in the window with its named SSIDs, frames and directed probes, signal, presence strip, and what it is tied to (a `devices` row, an association, a `seqnum_correlations` sibling) |
| `/api/probes/ssids?days=&sort=&limit=&offset=` | the SSIDs asked for by name in the window: stations asking, how many randomised, the APs beaconing it, first and last seen |
| `/api/probes/shared?mac=&days=&min=`, `/api/probes/groups?days=&min=` | the stations whose named SSIDs overlap `mac`'s, ranked by `sum of w over the shared / sum of w over either's`, `w(s) = ln(N / df(s))`, on at least `min` shared uncommon SSIDs; and the groups such pairs form |
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
- **`keys: one` / `keys: all`** on the main chart (owner request and ruling, 2026-11-11; `docs/web-visual-spec.md` §6.2 and its rulings). One, the default, is the chart above. All draws every key of the metric in the window (the rollup's and the store's, not the key picker's 256: owner ruling "lift the cap"; read a page at a time and drawn as it arrives under `loading N of M keys`; the graph holds 8,192 and a read stops at 60 s, either said as `N of M keys`) as its own line on one shared y-scale in the key's hash colour of §8.12, with a legend of every key drawn (rank, swatch, key, latest value; largest first), a filter box and 200 entries at a time once there are many, hover or focus to bring one line forward (the rest `--faint`), a pick to hold it and return, past 256 keys the 256 largest as lines and the rest as their range a cell, the picked key's band only, and a device's drawer from its entry. A presence metric stacks its strips, a row a key. Kept per browser as `act.allkeys`. Data: `/api/series/all`.

### 8.6 View: Devices

The device database. Data comes from `sloth.db` joined with `slothweb` lookups.

- Search box with a small query language (§9.1).
- Virtualised table, 60 fps at 512 rows. Columns: mac (with a colour swatch), vendor, ip, name (best passive name, with a source glyph: `D` DHCP, `m` mDNS, `N` NBNS, `p` PTR seen on the wire, `P` active PTR), last SSID, signal, sources (bit glyphs: `A`RP `D`HCP `P`robe `B`eacon `S`TA), risk, first seen, last seen, `z` now, anomaly count.
- Row colour: the mac's hash colour on the swatch only. Text stays `--ink` and `--muted`. Rows with a risk level above 0 (scored by slothweb from `risk_signals`, #191; the stored `risk_level` is not read) get a left border in the severity colour. Rows with `mac_random = 1` show the mac in `--muted` with a `~` prefix.
- Presence strip: a 24 h mini heatmap per row (144 cells of 10 minutes) showing when the device was present. This is the fastest way to spot the device that only appears at 3 AM.
- Click a row: a drawer slides in (second-brain viewer style) with the full `/api/device/{mac}` record: PNL SSIDs, associations with evidence grade, probe history, the 168-cell presence heatmap, anomalies, alerts, and the lookup panel.

### 8.7 View: Anomalies

Open episodes first, then closed ones in the selected window. Each card: kind glyph, key, score bar in the heat ramp, evidence text, sparkline of the metric that fired, first and last seen. Filter chips by kind. A click opens the device or host drawer.

**Triage on the card (2026-11-11).** Every card, here and wherever else one is drawn (the Overview's top five, the drawer, an alert's page), carries the anomaly's triage chip and a *triage* / *notes* button (`web/ui/notes.js`, one guarded call in `card()`). The button opens the anomaly's panel, a `<dialog>`: the state buttons and *clear*, the note with its byte counter, every change newest first with the episode it was made on, the operator's links (each with *open* and *remove*, or "no longer held"), the candidates ("possibly related", each with its basis and one *link* button) and a "link to" field. A triaged-out card (`false`, `noise`, `known`) is dimmed, never hidden, whether the state is this episode's or carried from an earlier one (the "earlier episode" mark stays on it; a carried `incident` is not dimmed). The table form of this view carries the same chip and button on every row; the presence strip's episode marks do not.

### 8.8 View: WiFi

- **Channel x time heatmap**: rows are channels (2.4, 5, 6 GHz grouped with a rule between bands), columns are time buckets. Cell colour is `ap_count` or `ctrl_total` (toggle). Reads like a spectrum waterfall.
- **AP table**: `beacon_aps` with SSID history, AKM bits, downgrade flags, MFP, KARMA score. SSID count above 1 is highlighted in `--sev-warn`.
- **Deauth timeline**: bars per bssid, flood episodes in `--sev-crit`.
- **Probe clients**: count over time with band.
- **SSID detail (added 2026-11-11)**: any SSID on the view (the AP table and its SSID history, the hidden word, the card's scan, the channel mix's list) is selectable by click or keyboard and opens a drawer like the device drawer's: the SSID in its display form with the non-printable marker; every BSSID beaconing it (vendor, channel, security and AKM, signal, first and last seen, the new mark), each opening the device drawer; the clients associated to it and the clients probing for it, each opening the device drawer; the 24 h presence strip (any of its BSSIDs present) in G5; the twin and KARMA findings on its BSSIDs; the alerts naming it or its BSSIDs, each opening the alert's page. Whether the operator designated it (`--my-ssid`) is not known to slothweb and the drawer says so. Empty states per R5. Under Local: out of scope, said.

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

### 8.13 View: BLE (added 2026-11-01)

The TUI's `[*]` view, at data and colour parity. One table, one row per advertiser as one sensor heard it (the host controller and an Ubertooth hearing the same address are two rows; their counts are never summed), the TUI's columns and cells (address, T, sensor, rssi, dist (est), adv, age, hws, advertises) plus the address in words (random static, RPA, NRPA), the Bluetooth SIG's names for the company, service and appearance, the best RSSI, the rate between records, first heard, the PDUs heard and the watch category; a row is one colour, `--tui-bright` for a HID or watchlisted advertiser and `--tui-normal` otherwise, with no swatch, no hash hue, no RSSI heat and no monitor ground (the TUI puts no BLE row on `CP_MON_ROW`). Above it the TUI's header line and, with `--ble-rotation-hints`, its rotation-hints block verbatim (the estimate is not on the stream, only the hint count as a decade band); below it the TUI's legend and the findings (`ble_alert`), standing first. A click opens a drawer in the TUI detail's order, then the PDUs heard, the PHYs and SID, a 24 h presence strip of quarter hours (G5), the row's advertising rate between its records (G1) and the `hid_oui` findings naming the address. Served from slothweb's own tables (`web/src/web_ble.h`, persisted in slothweb.db v6): `sloth.db` has no BLE table. Monitor's: out of scope under Local, saying why. Hotkey `0`. The Health view gains a `bluetooth` block (the `sensor_health` members), the Overview a `ble advertisers` tile, the strip a `ble` pill. Full description: `web/README.md` (BLE).

**BLE Devices (2026-11-02).** The nav button reads `BLE Devices` (the id, the view and the hotkey are unchanged), and above the table sits a waterfall in the WiFi view's style (owner: "show a waterfall similar to wifi for bluetooth devices"; "visualize in the best way to convey ble in a similar style"). Its rows are not channels: an HCI advertising report carries none, so every host-controller row is channel -1, and an Ubertooth's hop 37/38/39 every event. Two panels instead, one window select (1 h to 30 d), all three selects kept in the browser.

- **Header strip**: advertisers heard in the last 60 s, the trackers among them, the nearest (current signal less its announced power, with sloth's band or the grade below) and sloth's advertising reports per second. With no BLE sensor (sloth's `sensor_health` names neither source; `now.sensor`) the strip says so and both panels are hidden; with `--bt-capture` alone the class note says the one-channel samples are not credited.
- **Who is around** (`/api/ble/classes`): rows are device classes, columns time buckets; a cell is the class's five busiest advertisers by advertising reports as stacked bands (a named device in its name's hash colour, else its address's) plus grey for the rest, the WiFi channel mix's engine and idiom (`web_chmix.h`, a second instance keyed by class slug, rows in chmix as kind 3); a cell the mix no longer holds keeps the series' heat, dimmed (advertisers, a gauge, or reports, a counter: the cells select). The strip at a row's left is its busyness. Trackers is always a row. **Anonymous advertising** (2026-11-03; Address_Type 0xFF, an extended advertisement with no AdvA, which sloth zeroes, so a sensor keeps every anonymous advertiser it hears as one row) is Unknown's, whatever its row's fields read as (sloth keeps the row's first manufacturer pair for good and only ever adds HID bits and a watch category, so the fields are several advertisers' and class none of them), as one `tx` entry there, `{id: "anonymous", kind: "anon", class: "b:unk"}` (chmix kind 4, `WEB_TX_BLE_ANON`, the zero address: no `WEB_TX_BLE` entry can have it, since an address reaches the mix only through `web_key_mac()`, which refuses all zeros, and the kind is in every key anyway), drawn `--muted`, listed as "anonymous" in the cell detail and not openable; `ble.class.advertisers` counts it as one advertiser in Unknown, so for it a row's advertiser count, its reports and its drawn bands agree and never move class (a named advertiser whose fields change class can still be drawn in both rows in the bucket where it moves). The classes, one closed list in `web_bledev.c` and its copy in `bledev.js`, first match wins in this order: Trackers (a watch category, Appearance Tag or Keyring, a UUID the SIG registry assigns to Tile or CHIPOLO), Input (sloth's HID bits), Beacons (Eddystone 0xFEAA), Wearables & audio (Apple Proximity Pairing and Magic Switch, Fast Pair service data, Samsung's buds and watch packets, worn, audio and health Appearances), Phones & computers (Apple AirDrop, Handoff, Instant Hotspot, Nearby Action and Nearby Info, the MS-CDP beacon, Appearance Phone or Computer), Vehicles & IoT (HomeKit, fixed, home, vehicle and industrial Appearances), Unknown. Displayed Phones, Wearables, Trackers, Input, Beacons, Vehicles & IoT, Unknown. Sources: `research/bluetooth/ble-device-classes.md`; iBeacon, AltBeacon, Find My and SmartTag are left out there with the reason.
- **How close** (`/api/ble/proximity`): one row per advertiser heard in the window (12, 24 or 48; trackers first, then signal less announced power in the window, then reports), columns the same buckets, a cell the mean `rf.rssi.ble` graded hot-is-near by the band sloth's estimator gives that signal for an advertiser announcing no power (P_tx 0 dBm, L(1 m) = 20 log10(2440) - 28, N 2.8): immediate above -39.75 dBm (`--heat-3`), near above -53.11 (`--heat-2`), room above -67.75 (`--heat-1`), building above -81.11 (`--heat-0`), far `--faint`, not heard the page's ground. The footnote says what the grade is not (announced power, a tuned N, the band's hysteresis and hold; not a location) and that a rotating random address is its own row, rotations not linked. Anonymous advertising has no row and is never the strip's nearest: with no address there is no `rf.rssi.ble` series to key, and its one row per sensor carries whichever anonymous advertiser was heard last, so a line of it would be several devices' signals at once; it takes none of the 256 read, so "of the 256 read" stays 256 under a cut; the answer's `anonymous_heard` says one was left out, the note says so, and the class panel counts it (2026-11-03). Pointer, tap or arrow keys pick a cell in either panel and the list under it names it; a click on a row's name opens the drawer. Since the 2026-11-02 review: every tracker in the window is read before the newest of the rest (at most 256 read, and the note says "of the 256 read" under a cut), each row is graded at its own announced power in `rf_ctx_ble()`'s order (extended header TxPower, else TX Power Level, else 0 dBm) so the cell and the dist column name one band, rows and the strip's nearest rank by signal less that power, and a name opens its drawer on a primary click, not on pointerdown. Past 30% of the canvas the class panel's labels are their glyphs alone.
- **The drawer** gains the address's signal over the waterfall's window (`/api/series` `rf.rssi.ble`, fine or minute tier), each point in the grade's colour with faint lines at its edges, the row's class, and for an Ubertooth row the LL channels slothweb has seen it on. It is graded at the row's P_tx; opening another address clears it and drops a late answer, and a theme change redraws it.

sloth's side: `ble_device` is re-sent once a 10 s slot while sloth keeps hearing the advertiser (the slot is in its change-only signature; `docs/wiki/jsonl-schema.md`), so both panels have a point a fine bucket rather than one per 300 s heartbeat. No schema step: the class mix reuses slothweb.db v7's `chmix` under `b:` keys, and each view reads its own namespace.

### 8.14 View: Radar (added 2026-11-06)

Owner request: a master "radar / CIC" view. One half-dome centred on the sensor, drawn as vector graphics on Canvas 2D with a hand-written orthographic camera (nothing external can load under the page's policy, and nothing is wanted), that places every radio sloth observes and can be turned, tilted and zoomed. Each family contributes what it honestly has: GNSS satellites (`/api/gnss`) at their azimuth and elevation on the rim shell as ◇ (filled when in the solution, C/N0 on the heat ramp over 50 dB-Hz, an unhealthy one ringed `--heat-3`, the `/api/gnss/tracks` trail fading behind it); ADS-B aircraft (`/api/adsb`) as ▲ rotated to the track at the true bearing and elevation angle, a `--faint` drop line to the ground foot, the kept track through the same mapping, altitude on the heat ramp over 45,000 ft, on the ground dim, an emergency or a 7500 / 7600 / 7700 squawk ringed and worded; APRS stations (`/api/aprs`) as ○ at the true bearing, `--heat-2` when heard direct, the selected station's kept track; Wi-Fi APs and stations and BLE advertisers (`/api/radar`, the band census) as one translucent ring per distance band on the ground plane (Wi-Fi solid, BLE `[6, 4]` dashed, `globalAlpha` 0.25, `lineWidth` 1, no fill), labelled with the word and the count (`Wi-Fi room 7` at screen right, `BLE room 12` at screen left), because a single passive sensor has no bearing for them. Gone or stale (over 600 s) is alpha 0.35; the selection is `--signal`, the one accent.

**True direction, compressed distance.** Every object sits at its true (azimuth, elevation) with the slant range through one log scale, `rn(m) = clamp((log10 m − log10 0.3) / (log10 300000 − log10 0.3), 0, 1)`: 0.3 m at the centre (so the immediate ring is not the centre point), 300 km at the rim, labelled rings at 1 m, 10 m, 100 m, 1 km, 10 km, 100 km. A satellite is the r = 1 case of the same rule, so a 10 km-away aircraft 10 km up sits at 45° as in the sky and an airliner 100 km out near the horizon; beyond 300 km an object is on the rim, dimmed, with its true range in the label. Ground range and bearing are the haversine (R 6371008.8 m) and forward azimuth from the centre (an equirectangular approximation drifts 3 % at 300 km). The rings sit at `rn(1)`, `rn(3)`, `rn(10)`, `rn(30)` and, nominally, `rn(100)` for far (the band has no outer edge; the caption says so). The camera is orthographic: yaw ψ (0 north up), pitch θ in [10°, 90°] (90° the plan / PPI view), zoom 0.5 to 4; `xr = x cosψ − y sinψ; yr = x sinψ + y cosψ; sx = cx + S·xr; sy = cy − S·(yr sinθ + z cosθ)`; depth only dims a far-side dome mark. Equal ranges stay equal on screen, so picking is two-dimensional. The rim is the ellipse (S, S sinθ), the dome silhouette the upper semicircle, twelve bearing spokes with N E S W, the 30° and 60° parallels and the 30° meridians in `--faint`. Labels go right-above, else right-below, else are skipped; aircraft before APRS before used satellites before the rest; satellites lose their labels below zoom 0.7.

**The dome is the page** (owner request, 2026-11-06, "everything else secondary to the radar"). The view is one stage that fills the window below its own top edge (`fit()` sets its height from `innerHeight` and its page offset, at least 320 px); the canvas fills the stage, and the rest sits over it as small solid panels (`--panel`, a `--rule` border, no shadow): top left the header line, the camera line and the five buttons with the explanation folded under "about this view"; top right the picked panel when something is selected (at the bottom, full width, on a narrow screen); bottom left the R9 caption. Other views are unchanged and the page still opens on Overview. A sixth button, **full screen** (and `f` on the focused dome), puts the stage alone into the browser's full screen through the Fullscreen API with every panel hidden (`.radar-stage:fullscreen .radar-ov`), "only the dome visible" as the owner asked; Esc leaves; the button is hidden where the API is absent.

**Interaction and state.** Pointer drag turns and tilts (0.5°/px, `setPointerCapture`, `touch-action: none`), the wheel zooms ×1.1 (`passive: false`), the canvas is focusable (`tabIndex 0`) and takes ← → ↑ ↓ (Shift ×3), `+` `-`, `0` reset, `n` north up, `t` top down, `Escape` deselect (the digits are the page's view hotkeys, but that handler fires only on `document.body`). Six plain buttons mirror the keys for touch (`f` full screen the sixth); the view holds no `<select>` or `<input>` and no ARIA state. The camera is kept as `radar.yaw`, `radar.pitch`, `radar.zoom` ([Kept settings](../web/README.md#kept-settings)), validated on read and removed by reset; the selection is never kept. The dome is drawn through one `requestAnimationFrame` when something changed, never on an idle loop.

**Data, centre, scope.** `/api/gnss`, `/api/adsb` and `/api/aprs` every 5 s, `/api/radar` every 30 s, `/api/gnss/tracks?hours=6` every 60 s, each through the page's scoped `getJSON` with generation counters and a visibility guard. The centre is `gnss.fix` when `mode ≥ 2` and `fix.ts` is within 60 s, else `gnss.loc` (the position `sensor_health` carries: the last fix or `--location`), else the header reads "no sensor position: aircraft and APRS not placed" with the satellites and rings still drawn. The satellites are the host's own receiver's, every scope's, so the view has no `scoped-out` state (a comment beside the ADS-B and APRS toggles says why); under Local the three passive fetches are skipped and the header reads "Local: only the host's own receiver (satellites). Aircraft, APRS, Wi-Fi monitor and BLE are the passive radios' — switch to Monitor or Hybrid".

**Picking and the side panel.** Every drawn mark is a pick target; a tap (under 4 px of travel) takes the nearest within 8 px, else the nearest ring by its ellipse distance within 8 px. The panel (textContent only): identity; exact bearing, ground range, altitude and elevation angle; signal; lat/lon for an aircraft or a station; last seen; for a ring the family, the band word and its metre edges (`src/rf_distance.h`'s constants restated), the count, up to eight devices and "k of n". "open in GPS Sat / ADS-B / APRS / BLE Devices / Devices" shows the tab, then the family's own `select()` (`SlothGnss`, `SlothAdsb`, `SlothAprs`, each applying the pick after its next load when the row is not yet there) or the drawer (`openBleDrawer`, `openDrawer`).

**Device labels, ruled after the first look (2026-11-06).** Fifty labels a family stacked into two text columns that covered much of the dome and ran under the caption panel. Now only the 10 most recently heard of each family are labelled (`LABEL_N`), any other device while hovered or selected; labels are compact (a name or SSID cut to 12, else the last three octets, `~metres`, the trend glyph); and the panels floating over the dome are seeded into the placer as occupied boxes (`overlayBoxes()`), so no label lands under one. **Devices, labels, motion (2026-11-06, owner request).** Of each family the 50 most recently heard rows with a distance estimate (`/api/radar` `devs`) sit on the **north axis** (azimuth 0, on the ground, at their own estimated metres through `rn()`; the band's nominal radius when the record carried none): ■ Wi-Fi, ● BLE, each with its own ring (`globalAlpha` 0.15, `lineWidth` 1, Wi-Fi solid, BLE dashed); the per-band rings stay at 0.09. The axis is a convention, not a bearing; the panel says "distance from signal strength; no bearing: drawn on the north axis" and the label carries sloth's trend glyph (↘ → ↗), the only motion those emitters have. Labels never overlap: one layout pass a frame places N E S W, then the selected, aircraft and APRS labels greedily (eight directions at two radii, then a third with a leader), then the devices in two stacked columns with `--rule` leaders (Wi-Fi right, BLE left; one-dimensional stacking relaxed upward at the bottom), then the rest greedily; one function draws every label and refuses a box off the canvas or touching a placed one, so a label with no room is left out, never drawn over another. An aircraft (gs, track) or APRS station (speed, course) moving gets a velocity tick along its ground-projected heading, `6 + 14·log10(1 + kt/10)` px capped at 30, and `250 kt 090°` in its label. `/api/radar` is read every 10 s. *(The north axis and the two label columns are superseded by the next paragraph, 2026-11-13.)*

**Devices at their most probable point (2026-11-13, owner request: "instead of on the n/s axis in the radar use the data to plot the most probably point location. color code the wifi points and light transparent polygons for the shape of the estimated location polygon").** No device sits on the north axis any more. A Wi-Fi or BLE device that another sloth also heard has a fleet area (`/api/fleet/locate`; `web/README.md`, Radar, fleet areas): its mark is **solid** at that area's most probable point. Each area is drawn as an explicit **polygon**: a fix's disc in 72 points; an overlap of bands or a nearer-side wash traced from the same grid by marching squares into closed rings, filled and hit-tested even-odd, so a hole (the region round a site whose band starts metres out) stays a hole and two lobes stay two. A traced boundary, not a convex hull: with the sites 8.6 m apart and bands of 3–10 m and 5–15 m the region is an annulus with a bite out of it, and a hull would cover the two places both readings rule out. Fill at the shared alpha (0.4 over the areas, at most 0.08), outline 1 px at 0.25 in the same ink, stronger when hovered, picked or linked. A least-squares fix's point is its centre; where the sites' bands overlap, the region is sampled on a grid over its bounding box (48 cells on the longer side, finer to 64 when a band is narrower than three cells, so at most 67² samples, computed once an answer, not once a frame), each sample inside scored by the product of one Gaussian a site about the range its reading gives (`range_m`, else the band's middle) with sigma half the band's width; the point is the server's candidate when it lies inside the region, else the score-weighted mean when it lies inside and scores within 0.5 (log) of the best sample, else the best sample (two lobes, whose mean would fall between them); with two sites the mirror point across their line is as likely, and the panel says so. A nearer-side wash's point is half its radius into the nearer site's side. A device only this sensor heard has no bearing at all: a **hollow** mark on its own faint distance ring at an angle from a hash of its address, so a solid mark always means located and a hollow one's angle is arbitrary (only its distance is an estimate); the panel and the caption say so. Every other located emitter (not among the 50 listed) gets the same solid mark at its point, picked as its area. Marks: ■ Wi-Fi station, ◆ access point, ● BLE, filled or outlined as above. **Colour**: a Wi-Fi mark and its polygon take one of `--rw-0..4` by FNV-1a of the lower-case MAC, stable across polls (the ruling table's 2026-11-13 row overrides R10 for this); BLE keeps `--tui-normal` and its areas `--data`; the selection is `--signal`. Labels are placed free beside their mark by the same greedy placer (a device's label may take a leader at the third radius); `put()` still refuses any box touching another. The panel's placement rows: located, "the most probable point of its fleet area, from N sites" with the form and the point's range and bearing from this sensor; unlocated, "a hollow mark on its distance ring at an arbitrary angle (from its address); only the distance is an estimate".

**APRS window, objects, trails (2026-11-06, owner request).** One control, `APRS for` (`radar-aprs-win`, 15 min / **1 h** / 3 h / 6 h / 24 h, kept by `keepCtl`): an APRS entity is drawn while its newest packet of any kind (a status-only one too) is younger than the window, at its last known position. Entities are stations by source call (○) and objects and items by their own name (✕, `NAME (obj via CALL)`), from sloth.db over 24 h (`/api/aprs/tracks`, every 60 s) merged with the live stations, live winning for the position; each with its newest status and comment (panel; the label's suffix cut to 16 when there is room). A moving entity draws its 24 h trail (≤ 48 points, fading to the oldest, broken over gaps of more than two buckets, `--muted`, `--signal` when selected).

**Caption (R9)**: the sources and their windows; the position's source and age; "range log 0.3 m–300 km; height is true elevation angle"; each family's placed and unplaced counts; the devices listed of those with an estimate; how many Wi-Fi and BLE are located (solid, at the most probable point of a fleet area, from N sites) and how many unlocated (hollow, this site only, at an arbitrary angle: only the distance is an estimate); the Wi-Fi hue rule and the shapes; "N Wi-Fi, M BLE without a distance estimate"; "distance from signal strength is an estimate; a ring is where the device may be, not where it is". R12 is waived for this view by the ruling in the table above; the glyph-set rules it does meet are R1, R8, R9 and R10. Full description: `web/README.md` (Radar).

### 8.15 View: Probes (added 2026-11-11)

**Purpose**: who is searching for which networks, what each searcher is tied to, and which searchers ask for the same uncommon networks.

**Sources**: sloth.db only (`probe_clients`, `pnl_clients`, `pnl_ssids`, `assocs`, `seqnum_correlations`, `devices`, `beacon_aps`) through the existing allow-list; nothing is stored by slothweb, so the view is what sloth.db retains across restarts. Monitor's and Hybrid's; under Local the tab says why it is empty, as BLE does.

**Controls**: the window (24 h, 7 d, 30 d default, all retained) and the minimum of shared uncommon networks (1 to 4, default 2); an order for each table. Kept per browser.

**Panels**, top to bottom:

- **Clients heard probing**: MAC (randomised marked), vendor, the SSIDs asked for by name (each opens the SSID detail, §8.8), their count, frames (all probe requests) and directed probes as the two counters sloth keeps (no wildcard count exists, and a wildcard is never listed as an SSID), signal, G5 over 24 h, last seen, and "tied to": a device row for the same MAC (opens the drawer), an association seen for it, or sloth's sequence-number correlation with another MAC, worded as a hypothesis with its basis. A row is picked by click or Enter.
- **Probing for the same networks**: the picked station's SSIDs with df and weight, then the stations sharing its uncommon ones, ranked by the similarity; the formula in the caption.
- **Networks searched for**: SSID, stations asking, randomised among them, whether an AP in sloth.db beacons it, first and last. Designated networks are not marked (not exported by sloth).
- **Groups**: stations linked by at least the minimum of shared uncommon networks.

**Similarity**: `w(s) = ln(N / df(s))`; `sim(A,B) = sum of w over A and B / sum of w over A or B`; uncommon is `2 <= df <= U`, `U = N / 20` within 2..16. Worded "probe for the same networks", never an owner.

**Caption (R9)**: the tables, the window, n; N of M wherever a cap or a page cut the list; the empty states in words (R5).

**TUI form (R12)**: the PNL view's rows (client, names, OS, PHY). No new glyph: G5 only.

## 9. Search and lookup tools
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
