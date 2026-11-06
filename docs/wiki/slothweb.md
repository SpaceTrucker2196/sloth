# slothweb

The browser dashboard's server, a separate binary under `web/`. This
page tracks what has shipped; the design is
[`docs/web-ui-spec.md`](../../docs/web-ui-spec.md), whose rulings table
overrides its body.

**Summary**: slothweb is at M6 (#164), the last milestone of #102, on
top of M5 (#163), M4 (#162), M3 (#161), M2 (#160), M1 (#159), M0 (#158)
and W0 (#157). How to build and run it in five minutes, every start-up
message with its remedy, and the security model are in
[`web/README.md`](../../web/README.md). M6 adds the Flows view (sloth.db's
protocol tables, one tab each, through the M4 allow-list, SMB1 sessions
in the critical colour, and a chord diagram of the busiest source to
destination pairs with what was folded stated; `/api/flows` and
`/api/flows/graph`), a polish pass over every view (keyboard order,
360 px, a light colour-scheme preference, a memory-only build), a
synthetic demo (`make web-demo`), a five-minute check
(`make web-quickstart-check`) and screenshots. M5 adds the WiFi view
(a channel x time waterfall of `wifi.ap_count` or `wifi.ctrl_total`,
bands grouped; sloth.db's `beacon_aps` with AKM bits and downgrade flags
by name, MFP, SSID history and KARMA score; a deauth timeline per bssid
with DEAUTH_FLOOD episodes; probe clients over their band), the History
view (a 30 d strip with a drag range picker, who was here with presence
restricted to the range, the alerts, anomalies and flows in it, survey
sessions with `--report`'s "new since the previous session" ported),
and the SQL box: `/api/query` only with `--web-allow-sql` (off by
default, refused by `--strict`), one read-only `SELECT`/`WITH` at a
time on its own thread under an authorizer, 5 s, 10,000 rows, the
credential columns withheld as from every reader, with
`sqlite-schema.md`'s recipes extracted at build time. M4 reads `sloth.db` strictly
read-only (`--sloth-db`; `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW`,
an immutable open where that is what makes no side file, a column
allow-list enforced by an authorizer), compiles the §9.1 device query
language to one prepared statement with bound parameters, builds the
full IEEE vendor table at build time from the registry CSVs committed
in `web/data/` since the 2026-10-26 ruling (the generated table is
never committed; a `WEB_OUI_DIR` without them gives sloth's own table
and A4 off), shows
passive names only (active reverse DNS is cut), adds rule A4 and a
durable A2 from `devices.first_seen`, and serves `/api/devices`,
`/api/device/{mac}` and `/api/lookup` behind the Devices view, the
device drawer and the Lookup view. M3 keeps 168 local hour-of-week baseline cells
per (metric, key) with the MAD ratio, runs nine of §6's ten anomaly
rules (A4 moves to M4 with the OUI table) as episodes on the buckets
that just closed, keeps both in `slothweb.db` (schema v3) across
restarts, serves them as `/api/anomalies`, `/api/baseline` and an
`anomaly` event, and draws the Anomalies view and the Overview's band,
hour-of-week heatmap and top anomalies. M2 derives the spec §5.1 metrics from the records M1
decodes, rolls them into 10 s, 1 min and 1 h buckets (sum, count, min,
max), keeps them in its own `slothweb.db` (never `sloth.db`), serves
them as `/api/series`, and draws the Activity view's band chart and
small multiples. M1 reads sloth's data socket (`--socket`, default
`unix:/run/sloth/sloth.sock`) on its own thread with a capped
reconnect back-off, decodes each JSONL line with a strict bounded
reader that treats every byte as untrusted, keeps a live state (record
counts by type, the device count of sloth's latest pass, open alerts by
severity, `sensor_health` liveness, recent records), serves it as
`/api/live` and on the `/events` stream, and draws the Overview: KPI
tiles and a record ticker. Below it, W0 is a
listener with an allowed-peer list: loopback-only bind by default
(`127.0.0.1:8770`); a non-loopback bind or allow entry needs
`--web-allow-remote` and is announced on stderr; `--strict` refuses
both. Peers outside the list are closed at accept() and counted. M0
adds three routes behind it: one embedded page with an ETag and `304`,
`/api/health`, and an `/events` Server-Sent Events stream with a 1 s
tick counter. Every method other than `GET`/`HEAD` is `405` on every
path, a header block over 8 KB `431`, and idle or slow clients time out
on an absolute budget.

**Sources**: `web/README.md` (Design), `web/ui/theme.css`, `web/ui/page.css`, `web/tools/palette.c`, `web/tests/test_tui_colors.c`, `src/tui.c` (`tui_ip_addstr()`, `tui_ssid_addstr()`, `find_brand()`, `tui_brand_addstr()`, `tui_info_color()`), `src/tui_palette.c`, `src/ip_color.c`, `src/views/dashboard_primitives.c` (`draw_sparkline_at()`), www.river.io/jeff (the Spacetrucker design system), `web/src/web_flows.c`, `web/tools/demo.c`,
`web/tools/quickstart_check.sh`, `web/tests/test_flows.c`,
`web/tests/test_readme.c`, `docs/assets/slothweb/`, `include/sloth.h`
(`smb_session_t`'s dialect), `web/src/web_slothdb.c`,
`web/src/web_query.c`, `web/src/web_oui.c`, `web/src/web_ptr.c`,
`web/src/web_devices.c`, `web/tools/oui_gen.c`, `web/tools/oui_csv.c`,
`tests/fuzz/fuzz_web_query.c`, `src/db_schema.c` (the tests' sloth.db),
`web/src/web_wifi.c`, `web/src/web_history.c`, `web/src/web_sqlbox.c`,
`web/src/web_sqlguard.c`, `web/src/web_secret.c`, `web/tools/recipes.c`,
`tests/fuzz/fuzz_web_sqlbox.c`, `src/rsn_ie.c` (`rsn_akm_name()`),
`src/posture.c` and `src/db.c` (`--report`'s new-since section),
`src/alerts/rules_wifi_mgmt.c` (the DEAUTH_FLOOD key),
`src/alerts/rules_wired.c` (what an alert's key and detail carry),
`src/dns_log.c` (what a PTR answer's `answer` holds), `src/oui.c`,
`tests/test_db.c` (the guardrail the allow-list is held to),
`web/src/web_baseline.c`,
`web/src/web_anomaly.c`, `web/src/web_ident.c`, `web/src/web_metrics.c`, `web/src/web_rollup.c`,
`web/src/web_store.c`, `web/src/web_tsdb.c`, `web/src/web_series.c`,
`web/src/web_ingest.c`, `web/src/web_jsonl.c`,
`web/src/web_live.c`, `web/src/web_json.c`, `web/src/web_acl.c`, `web/src/web_config.c`,
`web/src/web_http.c`, `web/src/web_routes.c`, `web/src/web_server.c`,
`web/src/main.c`, `web/ui/*`, `web/tools/embed.c`, `web/tests/*.c`,
`Makefile` (`web`, `web-test`, `cppcheck`), `docs/web-ui-spec.md`,
`src/jsonl.c` (`jsonl_emit_devices()`, `jsonl_emit_state_snapshots()`),
`src/db.c` and `src/secure_file.c` (the open and migration rules M2
re-implements), `src/top_hosts.c` (what `conn_count` counts),
`src/probe_pnl.c` (what `mac_random` is),
`packaging/systemd/slothweb.service`, `packaging/default/slothweb`,
`packaging/bin/sloth-migrate-sensor`, `tests/test_unit_file.c`, issues
#102, #153, #157, #158, #159, #160, #161, #162, #163, #164 and #168;
and for the Alerts page, `web/src/web_alerts.c`, `web/src/web_alertdb.c`,
`web/src/web_alertfmt.c`, `web/tools/alertkb.c`, `src/alerts/` (the
detail formats audited), `include/sloth_alerts.def`,
`docs/views/alerts.md`, `research/` and [[alert-remediation]]; and for
the vendor research section, `web/data/vendors/*.md`,
`web/tools/vendorkb.c`, `web/src/web_vendorkb.h`,
`web/src/web_vendorkb.c`, `web/tests/test_vendorkb.c` and
[[vendor-research]].

**Last updated**: 2026-11-06 (the Radar tab's APRS window, `APRS for`, 1 h by default and kept per browser, counted from each entity's newest packet of any kind; APRS objects and items drawn as entities of their own keyed by name; each entity's newest status and comment; a moving entity's 24 h trail; all from the new `/api/aprs/tracks` over sloth.db's `aprs_packets`); 2026-11-06 (the Radar tab's devices: of each family the 50 most recently heard Wi-Fi and BLE rows with a distance estimate on the north axis at their own distance with a faint ring, from `/api/radar`'s new `devs` (metres, band, trend); labels laid out so none overlaps another (stacked columns with leaders for the devices, greedy placement for the rest); a speed-and-heading tick for aircraft and moving APRS stations; the band rings fainter; `/api/radar` every 10 s); 2026-11-06 (the Radar view is the page: the dome fills the window and the header, controls, picked panel and caption float over it); 2026-11-06 (the Radar tab after APRS: one orthographic half-dome centred on the sensor placing GNSS satellites at their az/el, aircraft and APRS stations at their true bearing and elevation angle with the range on a log scale (0.3 m to 300 km), and the Wi-Fi and BLE distance bands as counted rings from the new `/api/radar` census (`web/src/web_radar.c`, `web_frrs_rf_census()`); drag, tilt, zoom, pick, a side panel with "open in" each family's tab through the new `SlothGnss` / `SlothAdsb` / `SlothAprs` `select()` hooks; the camera kept as `radar.yaw|pitch|zoom`; satellites only under Local; exempt from the visual spec's R12 by owner ruling); 2026-11-05 (the APRS tab after ADS-B: `/api/aprs`, `/api/aprs/seen`, `/api/aprs/station`, `web/src/web_aprs.c`, `web/src/web_aprshist.c`, `web/ui/aprs.js`, [[aprs]]; sloth.db v13 read); 2026-11-05 (the GPS Sat tab names each satellite - RINEX id and, from the IGS metadata in `web/data/gnss/`, the vehicle - and draws sky trails from `/api/gnss/tracks`); 2026-11-05 (GNSS and ADS-B history: "satellites seen" and "aircraft seen" from sloth.db's `gnss_sightings` and v12 `adsb_aircraft` / `adsb_sightings`, `/api/gnss/seen`, `/api/gnss/sat`, `/api/adsb/seen`, `/api/adsb/aircraft`, a satellite's C/N0 and elevation and an aircraft's altitude profile and recorded track; `WEB_SDB_SCHEMA_MAX` 12); 2026-11-05 (the ADS-B tab: `/api/adsb`, the aircraft kept in memory from `adsb_aircraft` and the `adsb_*` health block, a table, a north-up position plot with altitude-coloured tracks and a detail panel; Monitor's and Hybrid's, as BLE is; [[adsb]]); 2026-11-03 (#171 V4: G8, the chain timeline, on the WiFi view's chains panel for each bssid with more than one stage, on the alert page for the BSSID the alert names and in the drawer, from the new `/api/wifi/chain` (sloth.db's EVIL_TWIN, KARMA_AP and DEAUTH_FLOOD incidents and associations, the stream's `twin_episode` links kept in memory); the Flows view's matrix first and the chord second, from `/api/flows/graph?form=matrix`; `/api/alert`'s `device.bssid`); 2026-11-03 (#171 V3: the WiFi view as four panels, channels as G3 horizon strips on each channel's own 30 d scale or as z against its hour-of-week baseline with a stacked top-5 drill-in per column, emitters nearest first, the chains panel's deauth rug, probing clients with G2 and G5; History's 30 d strip as a G7 rug on one scale); 2026-11-03 (#171 V2: G2 in the Devices and AP tables' signal column, the drawer and the Lookup card, from the existing `rf.rssi.*` series through each row's `"rf"` member, bold and worded by sloth's own distance band and trend rather than a slope of its own; the new mark and G5's first-seen cell; G6 on risk, karma, the anomaly score and the anom and flow total counts); 2026-11-03 (#171 V1: G1 on every Overview tile, the strip's network facts and the footer's drops, from `live.*`, `records.total`, `sensor.drops` and `ble.devices`, with G1's band words and arrow; the tiles in urgency order; anomaly cards' G1 with the episode shaded and `series unavailable` on a failed read; the hour-of-week grid as G4, warming cells plain grey with no hatch, counted in the caption; the small multiples on one shared scale with a `scale: own` toggle and the |z| sort); 2026-11-03 (#175: sloth.db v11's `alert_incidents` allow-listed, its key and incident_id predicate-only, `WEB_SDB_SCHEMA_MAX` 11; `/api/history/alerts` per incident in the range; the alert page's runs per incident and its `db_incident`); 2026-11-03 (#179: the alert page leads with observations, incidents, the times, confidence and the rule's phrase, count last as evaluations; the list sorted by severity then observations, a muted floor under 20% for a row below CRIT; `/api/alert`'s members in that order); 2026-11-03 (#181: a triage note over its 240 bytes refused beside the buttons with both numbers, counted in bytes as typed, never drawn before the server confirms it); 2026-11-03 (the fourth triage verdict `known`, known good, drawn green); 2026-11-03 (BLE Devices: anonymous advertising one entry and one advertiser, always in Unknown, no proximity row and no read slot; A1 across the 10 s slot measured, quiet, no change); 2026-11-02 (the BLE Devices waterfall's review fixes: its own high-water table, trackers read first, the grade at each row's announced power, the no-sensor and Ubertooth-only states); 2026-11-02 (the BLE Devices waterfall: device classes by time as the WiFi channel mix draws channels, advertisers by time graded by sloth's distance bands, the drawer's signal over the window; the `BLE Devices` and `GPS Sat` labels; `ble_device` re-sent once a 10 s slot while heard); 2026-11-02 (copy JSON's `location` filled: a device's `/api/positions` answer, an alert's page `loc` stamp, both spliced, never re-rendered); 2026-11-02 (copy JSON, first landed 2026-10-27 as `/api/bundle` and a copy and download button on every detail view: rebased onto triage, FRRS, BLE, vendor research and the alert's proof; kinds `ble` and `platform` through the views' own hooks; `frrs`, an alert's `triage`, `vendor_research`, `assessment` and `evidence` filled from their routes' answers; records matched on address members, the alert id parsed once, a 10 s prefetch back-off after a failure, `server.slothweb.build_version`); 2026-11-02 (evidence pcaps withheld unless `--web-serve-evidence-pcap`, refused with `--web-allow-remote` unless `=remote`; a file with several manifest lines verified by any matching line, conflicts said; the snaplen named only when it cut the record; non-regular names marked unreadable); 2026-11-02 (the FRRS Report's RSSI series, `rf.rssi.sta` / `.bssid` / `.ble`, owner ruling on Q7); 2026-11-02 (the BLE view rebased onto triage: slothweb.db v7 after triage's v6, a flood evicting plain rows before HID and watchlisted ones, counts that only move up, the `bundle-btn-ble` hook); 2026-11-02 (the BLE view: the TUI's `[*]` at parity, slothweb's own tables from the stream, slothweb.db v7, the Bluetooth SIG assigned numbers under `web/data/btsig/`; on review, sloth's own count in the header, `standing floods` for what the web can count, a seeded finding whole and resolved in place, the BLE rows inside `--web-max-mb`); 2026-11-02 (vendor research review: affiliates, every
listed source cited and read, the generator's refusals tested, the
reference list without device counts); 2026-11-02 (triage second review: folding not refusing, the recommendation's bar, the import bounded and prepared, the installed assessments); 2026-11-02 (triage and TACDB review fixes: "follow recommended" reads the assessments' real vocabulary, the import refuses a file without its header and end line and never leaves a transaction open, deleted rows and imported triage bounded); 2026-11-01 (alert triage and the FRRS emitter record: slothweb's first write routes, POST and same-origin only, `--web-read-only` and `--web-assessments`, slothweb.db v6, the TACDB tab, [`docs/web-frrs-spec.md`](../web-frrs-spec.md)); 2026-11-01 (the vendor research
set: <!-- count:vendors -->276<!-- /count --> entries, most of the
reference host's vendors covered and the rest pending, `COVERAGE.md`); 2026-10-27 (sensor location: the alert page's "where the sensor was", the drawer's scatter, `/api/positions` with GeoJSON and GPX, the stream decoder keeping sloth's `loc` object, sloth.db v9 read; [[location]]); 2026-10-27 (an alert's proof: `--pcap-dir`, the capture decoded and hash-checked, the assessment and bibliography, the drawer's rows as tap targets); 2026-10-27 (the sloth icon in the header and as the favicon, inline data: PNGs admitted by `img-src data:`); 2026-10-27 (the vendor
research section under the drawer's and Lookup's OUI card, one cited Markdown file per OUI holder
in `web/data/vendors/` compiled in at build time, `{found:false}` and
"no research yet" for a vendor without one, [[vendor-research]]; the
glyph layer, slice V0 of `docs/web-visual-spec.md`, below; kept
settings: every control a viewer
can change kept per browser under `slothweb.v1.*`, each table's widths
and sort among them, the address still winning, a reset per table and
one for everything, and its review: a link's filters and scope applied
but not kept, `show all` clearing, the kind chip on its own list only,
no other build's keys touched; the capture scope's review: the host's
ARP table, leases and scan entries stay Local, scoped anomaly counts, z
and open-anomalies tile, the Records view's scoped counts, the WiFi
view's Local half from `/api/wifi/local`, [[capture-scope]]),
2026-10-26 (the capture scope: Monitor, Hybrid and Local
in the top bar, [[capture-scope]]), 2026-10-26 (the Alerts page on the current tree: its
titles and details in the display form beside the gate, its lists
sortable and resizable, its incident totals tested, the drawer's
slices newest first; the Alerts page's review: one row per key
from the stream too, slothweb's own incident handle in place of sloth's
invertible `incident_id`, the filters inside the bounded reads, History
and the drawer counting past the scan, one count on the list and the
alert's page, a short "what it is"; before it the Alerts page, an
alert's page, the Overview's tiles as links; earlier the same day #153 third review: signal syscalls denied, `ReadOnlyPaths=-`; #168: the date on a freshness line that is not today's; #153: `slothweb.service` and `--with-slothweb`; #168: sloth.db freshness on the DB-backed views; the channel mix's review: assoc out of the mix, late transmitters tracked exactly, alert text and blank lookalikes escaped, addresses sorted by number on the server; the History strip on a large sloth.db: its own 1500 ms budget, per-cell counts by sloth's new first_seen indexes or a last_seen-bounded read without them, a 60 s cache per file state, a timeout that names its read; the IEEE registry CSVs committed in `web/data/` by owner ruling, `make update-oui`, the generator's multi-file hang fixed; #170: `/api/history/alerts` and the deauth episodes overlap a range from the latest incident's start; the restyle's review: the alert-hot override, every monitor-radio record on the monitor rows, closed anomaly cards at full contrast, the spec's §8.1 amended; 2026-10-23 the Spacetrucker restyle: the owner's design system for the chrome, the TUI's colours for the data, a light theme behind a toggle; before it the same day M6, #164: the Flows view, the polish pass, the README's five minutes, troubleshooting and security, the demo data and screenshots).

---

## Where it sits

slothweb is a consumer of sloth, never part of it. It is built by
`make web`, tested by `make web-test`, and is not in `make`, `make
embedded` or the `sloth` binary. No `src/` file is compiled into it and
nothing in `src/` references `web/`. It links libc and pthreads, and
`libsqlite3` when built with `WITH_SQLITE=1` (the default, the same
switch sloth uses); `make web WITH_SQLITE=0` builds it without a store.

The charter basis is `MISSION.md` §2 rule 1: an optional service may
use the network from the host, and a local HTTP surface is in scope.
slothweb still never injects anything onto a monitored segment, never
resolves a name (its bind address included) and never writes to
`sloth.db`.

## Milestones

| Slice | Issue | State |
|---|---|---|
| W0: allow list and refusals, no routes | #157 | shipped |
| M0: embedded page, `/api/health`, SSE tick | #158 | shipped |
| M1: data-socket client, live state, `/api/live`, Overview | #159 | shipped |
| M2: rollups, `slothweb.db`, `/api/series`, Activity view | #160 | shipped |
| M3: baselines, anomaly rules and episodes, Anomalies view, heatmaps | #161 | shipped (A4 moved to M4) |
| M4: sloth.db read-only, query language, OUI table, passive names, A4, durable A2, Devices, drawer, Lookup | #162 | shipped (active reverse DNS cut by the rulings) |
| M5: WiFi and History views, sessions and new-since, SQL box behind `--web-allow-sql` | #163 | shipped (three of the eight recipes are refused: two read a withheld column, one `dbstat`) |
| M6: Flows view, polish, README security section, screenshots | #164 | shipped (`mqtt_flows` not read; Kerberos' preauth counts off the allow-list) |
| F0-F4: alert triage, the FRRS emitter record, the TACDB tab (owner request 2026-10-27) | - | shipped 2026-11-01; F5 (the vendor KB's certification data, the compiled assessment table) waits on the other sessions' files |

## W0: the access boundary before any route

The owner's ruling (2026-10-04) was that the allow list and its
refusals land, with tests, before there is anything behind them to
protect. W0 is that slice and nothing else.

### Bind

- Default `127.0.0.1:8770`. `--web-bind ADDR:PORT` takes a literal
  `A.B.C.D:PORT` or `[V6]:PORT`; a name such as `localhost` is an error,
  because nothing is resolved.
- A non-loopback address (`0.0.0.0`, `[::]`, a LAN address) is refused
  before `socket()` unless `--web-allow-remote` is given, and the
  refusal names the flag and the `ssh -L` alternative. With the flag,
  startup prints a `WARNING` naming the address. This is the
  `--data-socket-allow-remote` pattern from [[data-socket-exposure]].
- `web_server_open()` applies the same check again, so code that builds
  a config by hand gets the same refusal as the command line.
- `[::]` is bound `IPV6_V6ONLY`, so which peers can reach it does not
  depend on a sysctl.

### Allowed-peer list

- Default: `127.0.0.0/8` and `::1`. A v4-mapped peer (`::ffff:a.b.c.d`)
  is matched as IPv4, and a v4-mapped `--web-allow` entry is stored as
  IPv4, so dual-stack reporting cannot slip a peer past an entry.
- `--web-allow CIDR` (repeatable, 30 entries) extends the list; it never
  removes loopback. Host bits past the prefix are an error rather than a
  guess.
- A non-loopback entry needs `--web-allow-remote` and is announced. The
  flag on its own authorises the bind, not the peers: a remote bind
  with no `--web-allow` still admits loopback only.
- The check runs on the address `accept()` returns, before any read or
  write. A refused peer is closed and counted; the counters are printed
  on shutdown.

### Requests

| Request | Answer |
|---|---|
| `GET` / `HEAD` with no `Host`, or two | `400` (RFC 9112 §3.2) |
| `GET` / `HEAD` whose `Host` is not `localhost` or an IP literal | `421`, before the route table |
| `GET` / `HEAD` of a route (M0, below) | the route's answer (`HEAD` without the body) |
| `GET` / `HEAD`, any other path | `404` (`HEAD` without the body) |
| any other method, any path | `405` with `Allow: GET, HEAD`, permanently |
| header block over 8 KB | `431` |
| malformed request line or header | `400` |
| HTTP major version other than 1 | `505` |
| no complete header block in 10 s | `408`, best effort, then close |

Error responses carry `Connection: close`, `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff` and `Content-Security-Policy:
default-src 'none'`. A request body is never read; after the response
the server half-closes and drains for up to 1 s, so unread bytes end
the connection with a FIN rather than a reset. That is defensive: on
some stacks, and on real links, a reset can discard a response the
client has not read yet. Linux loopback cannot show that loss (the
response is queued before the RST arrives and is still delivered), so
the test asserts only the FIN, not a rescued response.

### Host, and DNS rebinding

The allow list judges the TCP peer, and a browser on the operator's own
machine is a loopback peer whatever page it is showing. A site that
points its own name at `127.0.0.1` (DNS rebinding) makes the browser
treat slothweb as same-origin with that site, and its script could then
read `/api/health` and `/events`; "no CORS headers" does not stop a
request the browser thinks is same-origin. What such a request cannot
hide is its `Host`, which carries the attacker's name. So a routed
request is answered only when `Host` (or an absolute-form target's
authority) is `localhost`, a literal IPv4 address or a bracketed IPv6
literal, each with an optional port; anything else is `421 Misdirected
Request`, before the route table, so the page cannot even learn which
paths exist. An IP literal cannot be rebound, which is why any literal
is accepted rather than only the bind address: `ssh -L` forwards and a
`0.0.0.0` bind reached by the host's LAN address both work, and no name
is resolved to decide. Reaching a remote bind by DNS name is therefore
refused; use its address. `405` for writing methods comes first and is
unaffected.

### Timeouts and limits

The header budget is absolute from `accept()`, not reset per byte, so a
slow-trickle client is cut off on the same schedule as an idle one. The
response has its own budget. 32 connections are held at once; an
admitted peer beyond that is closed and counted as busy. If `accept()`
runs out of descriptors or kernel memory, the listener is left unpolled
for 100 ms instead of spinning on a backlog it cannot drain, and the
back-off is counted.

### Strict

`--strict` refuses a non-loopback `--web-bind` and any non-loopback
`--web-allow`, whatever `--web-allow-remote` says, matching sloth's
`--strict` refusal of a routable `--data-socket`.

## M0: the page, health and the tick stream

M0's acceptance (spec §12) is opening `http://127.0.0.1:8770`, watching
the tick strip move, and seeing no external request in the browser's
network tab.

### The page

`/` is one HTML document with its CSS and JS inline. The sources are
`web/ui/index.html`, `theme.css` (the spec §8.1 tokens, the only place
colour lives), `page.css` (layout and the §8.2 sizes) and `app.js`.
`web/tools/embed.c` fills in the `@include` lines at build time and
writes `build/web/web_assets.c`: the page as a byte array, an ETag (the
first 128 bits of its SHA-256) and a Content-Security-Policy. The
generated file is never committed, and the embedder is C99 built with
the same compiler, so the build gains no tool.

The policy is `default-src 'none'` with `script-src` and `style-src`
naming the SHA-256 of the page's one `<script>` and one `<style>`, `img-src data:` for the two inline PNGs (the sloth in the header, the
favicon: bytes in the page, never a fetch), and `connect-src 'self'`
for the health read and the stream. A browser
therefore refuses any fetch the page did not already make, and an
injected inline block would not run either. `'unsafe-inline'` is never
used.

The fonts are the system monospace stack (rulings header, superseding
§8.2's embedded FiraCode): no font file is in the tree and no font is
requested. The page loads with `Cache-Control: no-cache` and revalidates
with `If-None-Match`, answered `304` until a rebuild changes the page.

### `/api/health`

JSON with `service`, `milestone`, `uptime_s`, `sse_clients` and
`tick_seq`, plus `socket`, `last_record_age_s`, `db`, `db_schema` and
`db_rows`, which are `"none"` or `null` until M1 and M4 have something
to report. `Cache-Control: no-store`.

### `/events`

Server-Sent Events, spec §7.1. The stream opens with `retry: 3000` and
the current tick, then sends a `tick` event (with `id:`) every second
and a `: ping` comment every 15 s. The tick's payload in M0 is
`{seq, ts, uptime_s, sse_clients}`; the spec's `rx`, `tx`, `devices` and
counts arrive with ingest. The ticks come from the poll loop's own
timer, so there is still one thread and one lock.

A client that stops reading is dropped once 64 KB is waiting for it
(spec §10.2), with its socket send buffer capped at 16 KB so a stalled
peer also pins little kernel memory. Every accepted socket has
`TCP_NODELAY` (spec §10.2), so a tick is not held behind the previous
one's ACK. At most 24 streams are held; the
25th `GET /events` is `503`, which keeps 8 of the 32 slots for the page
and the API.

## M1: ingest and the live view

M1's acceptance (spec §12) is running slothweb beside sloth and seeing
the Overview's device count match the TUI's within 5 s. The full route
and field reference is in `web/README.md`; what follows is the design.

### The client

One thread connects to `--socket` (`unix:PATH`, or `tcp:` with a literal
address; names are refused, not resolved), reads, and never writes: the
stream is one-way and sloth never reads from a client. A failed connect
or a closed stream is retried after 250 ms, doubling to a 4 s cap, so a
restarted sloth reappears within 5 s. Only a connection that delivered a
whole line resets the wait, so a peer that accepts and closes at once
(sloth's per-peer cap, #135) is not redialled in a loop. `--strict`
refuses a non-loopback `tcp:` address; without it one is announced.
`/api/health` reports the socket's state, attempts, connects,
reconnects, closes, the current back-off, the last error (slothweb's own
words), bytes, lines, decode errors by reason and sloth's `socket_gap`
markers.

### Untrusted input

Every byte from the socket is untrusted: a different sloth build,
someone else's socket, and strings that carry whatever was on the air.
Lines are capped at 16 KB and an overlong one is discarded through its
newline. The decoder (`web/src/web_jsonl.c`) is a strict
recursive-descent reader with fixed caps (384 members, depth 8) that
refuses a line whole for any syntax error, ill-formed UTF-8 raw or
escaped (lone surrogates, overlongs, `\u0000`), a raw control byte, a
duplicated member or a missing string `type`. `research/mcp/json.c` was
not reused: it decodes `\u` only to Latin-1 and does not validate raw
UTF-8.

Output goes through one writer (`web/src/web_json.c`) that escapes per
RFC 8259 and also writes `<`, `>`, `&`, `'`, DEL, C1 and U+2028/9 as
`\uXXXX`, so markup in a hostname or SSID is never markup in what
slothweb sends; the page renders every stream value with `textContent`
and has no HTML or code sink at all. Names are shown only as the stream
carries them (active reverse DNS is cut, rulings header).

### The device count

sloth's poll thread rebuilds its device table each poll and writes one
`device` record per row (`jsonl_emit_devices()`), so the number of
device rows in one pass is the TUI's `device_count` (rows, not distinct
MACs). The pass is contiguous only among the poll thread's records: the
capture thread's `dns`, `tls`, `quic`, `http`, `ntp`, `icmp` and
`cleartext_cred` records go through the same writer concurrently, with
no lock spanning the pass, and can land inside it. So slothweb lets
only the poll thread's record types steer the count, passes over every
other type, and publishes a run's length when the first poll-thread
record of another type ends it. A run that a `socket_gap`, an undecodable line or
an implausible `type` may have shortened is not published and the
previous count stands. The snapshot batch begins with the `iface`
records (`jsonl_emit_state_snapshots()`), so a batch with no device
run publishes 0 at the next batch's start, unless it lost records. The
count is marked stale while the socket is down and until the new
connection delivers a run.

### Alerts and sensor health

Open incidents are tracked from `alert.create` / `.update` /
`.escalate` / `.resolve` by `incident_id`, starting empty on each
connection: sloth replays nothing, and a resolve missed while away must
not hold an incident open forever, so the count can only under-report,
and heals as incidents update or resolve. `sensor_health` is change-only
with a 300 s heartbeat; its state is `ok`, `degraded` (a handle open
behind a stopped thread, or the launch scope not enforced, #85/#91),
`not_observing`, `stale` after 330 s without one, or `unknown`.

### The page

The Overview has four tiles (devices, open alerts by severity,
records/s, sensor health) fed by the 1 s `tick` event, the latest alerts
from `/api/live` every 5 s, and a ticker of the last 50 records fed by
`record` events (at most 20 per tick, spec §7.1), which can be paused.

## M2: time series

M2's acceptance (spec §12) is that after an hour of running the 24 h
chart shows the last hour at 10 s resolution and the store is under
5 MB. The route and flag reference is in `web/README.md`; what follows
is the design.

### Metrics

Every §5.1 metric has a source sloth writes today, so none was left
out. Three are adapted to what the stream actually carries:
`dns.nxdomain` is keyed by the record's `src`, which on a response is
the resolver (sloth's `dns` record names no client for an answer);
`wifi.ctrl_total` is sloth's running per-channel total, so it is a
counter of deltas rather than the spec's gauge; and `dev.present` counts
a MAC as present only when the record's `last_seen` is within the last
10 s, since sloth re-sends a table row every pass for as long as it
keeps it.

Keys are canonical forms checked by type (a MAC, an IP written back by
`inet_ntop()`, an interface name, a channel with a `6g` prefix on
6 GHz, an alert type number), so nothing a peer wrote becomes a key
verbatim. Counters that sloth reports as running totals become deltas
per row, floored at zero; the first sight of a row on a connection is a
baseline unless the row's own `first_seen` is no earlier than the
connection's first record, so a reconnect is not one enormous burst.
Bucketing uses slothweb's clock, never a record's `ts`.

### Tiers and bounds

10 s for 24 h, 1 min for `--web-retain-days` (30), 1 h for 400 days,
each bucket with sum, count, min and max. Keys are bounded per class:
`--web-max-keys` device MACs (512), half that many host IPs and, since
#177, as many BLE advertiser addresses in a class of their own
(`rf.rssi.ble`), least recently seen out first, evictions counted on
`/api/health`;
interfaces (32), channels (64) and alert types (128) each have a class
sized from sloth's own bounds; global metrics are always kept. Those
three come from catalogues no peer can churn, so their keys count as
established from the first sample: a one-off alert type has its minute
and hour rows written when they end. Device and host keys are judged
on the key's whole life: until a key's samples span a minute its 1 min
and 1 h buckets are held in memory, written once it spans one (or at
shutdown) and dropped if it is evicted first (`churn_dropped`), however
many samples it took. An evicted key's first sighting and whether it
was established are remembered (four entries per key slot, established
keys preferred) and given back when it returns, so a host evicted
between every two of its samples under LRU pressure still keeps its
minute and hour rows after its first minute. So a scan whose keys are
each seen for under a minute writes 10 s rows only while slothweb runs;
keys seen across a minute or more reach the long tiers under churn too,
bounded only by `--web-max-mb`. A key evicted and back is a new series in memory;
its earlier rows come from the store, or are gone without one. The
store queue holds six rows per series the classes can hold (at least
32,768), so an hour boundary or a shutdown at `--web-max-keys` 8192
drops nothing; past it, under churn, 10 s rows go before minute and hour
rows. Closed fine buckets also go to a 131,072-row ring in memory
(about 3 h at 117 series, shared with the rows of evicted keys), which
is all `/api/series` has without SQLite.

### The store

`slothweb.db` is opened by descriptor with `O_NOFOLLOW`, created 0600,
and refused (never repaired) if it is not a regular file of the
effective uid with no group or other bits and one link; the WAL and
shared-memory files are checked the same way, and SQLite then opens it
with `SQLITE_OPEN_NOFOLLOW` and `DEFENSIVE`: sloth's own rules for
`sloth.db`. The file is identified before anything is written, on a
read-only connection (a read-write one closing last on a WAL database
checkpoints and deletes its WAL, which would rewrite a refused
sloth.db; a WAL-mode file with no `-wal` is read as an immutable URI,
so that connection makes no `-wal` or `-shm` beside a refused, cleanly
closed sloth.db): empty (no object, `application_id` and `user_version`
0) is new and is stamped with slothweb's own `application_id`, a file
with any other non-zero one is refused, a `meta` table naming it a slothweb store is ours, anything else
(sloth.db included) is refused untouched, and so is a schema newer than
the build. Schema changes follow the 2026-10-21 owner rule: a chain of
additive steps from v0, each in one `BEGIN IMMEDIATE` with its own
stamp, so a failed step leaves the file at the version it reached. A
new file is stamped v0 and takes the same chain. v1 creates the tables;
v2 indexes each tier on `t`, which the retention and ceiling deletes
select on.
No column can hold a credential (sloth's `test_db.c` guardrail, copied).

The store thread, never the HTTP one, closes due buckets every second
and writes them every 10 s (sooner once 16,384 are queued), 4,096 to a
transaction. After every write, while the used size is over
`--web-max-mb` (256), it drops the oldest fine rows, then keyed minute
and hour rows, and the global series' rows last, 2,048 to a
transaction, so the ceiling holds within one flush interval even under
key churn; orphaned series rows are swept once after. A trim at the
64 MB ceiling takes about 59 ms (209 ms with the earlier 5-minute
slices), and the ceiling holds about 36% fewer fine rows for the v2
index's pages. Once an hour it also drops rows past retention, in
tiles of 256 series by 256 buckets (one transaction each), then returns
free pages 256 at a time and truncates the WAL. `--web-max-mb` bounds
the main file, not the WAL; the WAL is kept small by keeping every
transaction small: about 1 MB between transactions and, at 4 KB pages,
about 32 MB at worst during one (a start-up compaction after a long
stop measured 2.0 to 7.1 MB, where one delete of everything expired had
grown it to the size of the file). `store_rows` counts rows stored, not merges. Queries use a
second, read-only connection with every parameter bound.

### `/api/series` and the Activity view

`/api/series?metric=&key=&tier=&from=&to=` answers at most 900 buckets
(`[t, value, min, max, n]`, oldest first) with `more` and `next_to` for
paging. Every parameter is validated first: known names only, each
once, percent-decoded to printable ASCII, the key through the metric's
canonicaliser, the range non-empty, at most a day ahead and no longer
than the tier keeps. `/api/keys` and `/api/metrics` feed the pickers.
The Activity view draws the selected series as a line on Canvas 2D,
over its M3 baseline band where there is one and its per-bucket min..max
band where not, with a small multiple per key (the loudest top left)
coloured by the TUI's IP hash palette. The `abs(z)` ordering and the
ratio toggle are not built yet.

## M3: baselines and anomalies

The full account, with every departure from the spec's body and its
reason, is in [`web/README.md`](../../web/README.md#baselines-and-anomalies-m3).
In short:

- **Rows, not the store.** The engine reads every minute and hour bucket
  as it leaves the rollup's queue, and a store-thread step that crosses
  a minute boundary flushes first. The first M3 slice asked the store
  whether the bucket had arrived, which depended on the 10 s flush
  phase: the hour feed ran about one hour in ten, and a minute bucket
  could be scored twice or not at all.
- **Baselines.** A cell is the local hour of the week (Monday 00:00
  first), so a routine survives daylight saving; a minute is scored
  against the cell its own UTC hour bucket was filed under, so a
  half-hour zone (IST) compares like with like. A counter is per
  minute. An hour with no row is 0 for a counter and for presence and
  not a sample for a gauge. A cell learns two spreads: how much the
  hour's value moves from week to week, and how much the minutes inside
  the hour spread about it (from the minute rows the engine scores). A
  minute is scored with both, sqrt(var + wvar), the within term at
  least the mean for a counter (Poisson); scored with the week-to-week
  spread alone, a host whose connection count was 2 to 8 every minute
  fired A1 all week. The sd is floored at 10% of the mean and one unit,
  and counters must also pass the MAD ratio over the last 28 same-hour
  rows on disk, with the same within-hour term. Only hours with at
  least 45 observed minutes are fed; unobserved minutes are not scored.
  `/api/baseline` serves `[mean, sd, n, sd_hour]` per cell, and the
  band uses `sd_hour` for buckets of an hour or more.
- **Rules.** A1 rate, A2 new device (the stream's own `first_seen`
  within 24 h and nothing older about the MAC in slothweb's baselines
  or store, since sloth resets `first_seen` when it restarts; once per
  MAC while slothweb remembers it: a full reported set forgets its
  oldest `first_seen` (`reported_evicted`), and a MAC forgotten may be
  reported a second time, at most once per eviction, since a duplicate
  "new device" is better than a hidden one; more than eight at once, or
  sixteen in a rolling hour, are one episode keyed `""` whose evidence
  counts exactly the MACs judged new in that minute or hour and names
  two, and a real device arriving inside such a spoofed trickle is
  folded into it, not reported on its own: the stated cost of the
  fold), A3 off-hours presence, A5 a randomised MAC sharing another's
  DHCP or mDNS name, A6 DHCP, mDNS and NBNS names disagreeing, A7 a
  host's 10-minute peak flow count far above its own p95 (the stream has
  flow counts, not peer lists), A8 a client's NXDOMAIN share (answers
  joined to the client by qname: sloth's answers name only the
  resolver), A9 the first row of a flow series the store has ever had
  (including a new host's first row, which the rollup releases late),
  A10 a connected socket silent for 60 s. A4 needs the OUI table (M4).
- **Episodes** build, open, close after two quiet evaluated minutes, and
  are kept 24 h; a recurrence starts a new one. The table holds 512 and
  never pushes out an open or building episode. A new episode takes a
  free slot, else its own rule's oldest closed one, else (while its rule
  holds under a ninth of the table) the oldest closed one of a rule over
  that share: one rule's flood cannot erase another's history.
- **Persistence.** Schema v3 adds `baseline`, `baseline_cell`,
  `episode`, `fanout` and `reported`, migrated from v2 in one additive
  `BEGIN IMMEDIATE` step. A memory-only build keeps all of it in memory
  and says so. Evicted baselines' rows are deleted before the hour's
  writes, the delete queue grows rather than forget an id, a new entry
  whose pair still has a row takes it over, and a refused batch is
  written the hour after. A restore into a smaller table deletes the
  rest in small transactions. The analysis state counts towards
  `--web-max-mb` but the ceiling can only drop time-series rows, so it
  keeps a history allowance beside the analysis state: a week of hour
  rows for every series the baselines can hold (64 bytes a row,
  measured; about 51 MB at the default 512 keys). The real bound is
  `used <= max(ceiling, analysis + allowance)`: when the analysis
  state's pages (SQLite's `dbstat`; the baseline tables re-measured
  after each baseline write, the small tables on every pass) leave less
  than the allowance, the time series is trimmed to the allowance
  (`store_ceiling_raised`) rather than erased or left to grow. Without
  `dbstat` the ceiling drops until under or out of rows. slothweb
  refuses to start (exit 2) with a `--web-max-mb` below the estimate
  plus the allowance and names the minimum: 96 MB at 512 keys, 1,437 MB
  at 8,192.
- **Page.** The Anomalies view (cards with a kind glyph, score bar in
  the heat ramp, evidence, the metric's last hour, first and last seen,
  chips by kind), and on the Overview a throughput tile and "now vs
  normal" over the baseline band, the hour-of-week heatmap, the top five
  open episodes, and a view-only sensitivity slider.

## M4: devices and lookup

The full account is in
[`web/README.md`](../../web/README.md#devices-and-lookup-m4). In short:

- **sloth.db, read-only.** Every request (and A2's minute pass) opens
  its own connection with `SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW`
  and closes it after, so no snapshot outlives a request. A WAL file
  with no `-wal`, or a `-wal` and no `-shm`, is opened as an immutable
  URI, since a plain read-only open would make both side files; with
  both present it is a WAL reader with `readonly_shm=1`, which never
  initialises sloth's `-shm`: a crashed sloth's WAL is read into a
  private index rather than recovered on the shared one, so a sloth
  restarting beside slothweb never meets `SQLITE_BUSY_RECOVERY`. A
  VFS that never creates a named file covers a sloth closing between
  the choice and the read. `query_only`, `DEFENSIVE`, a 100 ms busy
  timeout and a progress budget (250 ms a request, 1500 ms for the
  History strip, which counts every row in its range) mean a slow read is
  slothweb's `503`, never sloth's stall; sloth's own `db_open()` waits
  out another reader's lock for 1 s (`DB_BUSY_MS`). A hot rollback
  journal is an error that sloth clears, not "not a sloth.db". Schema
  v1 to v7 is read (older ones by probing columns), the bound held to
  sloth's `DB_SCHEMA_VERSION` by a test; a newer one is refused with a
  message.
- **The allow-list.** An authorizer denies any column not on
  `web_sdb_allow[]` (devices' §8.6 columns, PNL SSIDs, associations,
  ARP, DHCP, mDNS and NBNS names, alerts without `detail`), any
  pragma but `table_info`, and anything but a `SELECT`; the test reads
  `tests/test_db.c`'s guardrail words and fails on a listed column
  named for a secret or a credential. `alerts.key`, which names a
  cleartext credential's username, is predicate-only: readable by the
  device query and the drawer's alerts read alone, never served.
- **Query language** (§9.1): every prefix of the spec, AND, `-`,
  quotes; bounded (256 bytes, 12 terms, 64 bytes a term) and checked per
  prefix; one statement from constant fragments, values bound, LIKE
  escaped; fuzzed by `fuzz_web_query`.
- **Vendor table** (§9.2): MA-L, MA-M, MA-S and IAB from
  `web/data/*.csv`, generated into `build/web/`; most specific block
  first; local and group bits always reported. Since the 2026-10-26
  owner ruling (reversing 2026-10-21's) the four CSVs are committed:
  Debian's `ieee-data` 20260625, 39,627 MA-L, 6,451 MA-M and 11,639
  MA-S/IAB assignments, their origin and SHA-256 in
  `web/data/SOURCE.md`, refreshed by hand with `make update-oui`
  (`/usr/share/ieee-data`, else the IEEE; never a build or CI step). So
  the default build has the full table and A4 is on; the binary grows
  from 0.5 MB to 3.3 MB, the build time barely moves (7 to 8 s clean).
  A `WEB_OUI_DIR` without CSVs: sloth's 117 entries, said so on
  `/api/health` and the Lookup card; CI builds and tests that fallback.
  The same day fixed a hang in the generator: each CSV had its own
  4,096-slot name index that rehashed every earlier name, so after
  `oui.csv` the second file never finished; one index for the build,
  sized for its names, now. The demo's MACs are all locally
  administered, so on the demo no device gets an IEEE vendor and A4
  never fires; the table shows through Lookup on a globally
  administered MAC, or on real traffic.
- **Passive names** (§9.3 minus the active half): sloth.db's and the
  stream's DHCP, mDNS and NBNS names, sloth's hostname, and a passive
  PTR cache (`slothweb.db` v4, `passive_ptr`, 4,096 addresses). The
  cache stays empty today: sloth's `dns` record carries no PTR target
  (`src/dns_log.c` reads A and AAAA only), a sloth change outside
  `web/`.
- **Rules.** A4: a present, globally administered, unicast MAC in no
  IEEE block, only with the full table (off with a reason otherwise), a
  burst of more than eight folded into one episode. A2 asks sloth.db's
  `MIN(first_seen)` first and also takes sloth.db's new MACs (a wired
  device among them); without sloth.db, M3's stream path.
- **Page.** Devices (search box, a virtualised table of up to 512 rows
  with the §8.6 columns, swatch, `~` for random, severity border, 144-
  cell strip), the drawer (everything `/api/device/{mac}` gives, the
  strip, the week heatmap, the episodes) opened from a row or an
  anomaly card, and Lookup. `textContent` only; no request off the
  page's own server.
- **Vendor research (2026-10-27).** Under the OUI card, in the drawer
  and on the Lookup card: what `web/data/vendors/` documents about the
  block's holder (kind, country, parent, founded, device classes,
  products found carrying it, radios, documented silicon, FCC grantee
  codes, randomisation, security notes, summary, numbered sources),
  each field with a confidence word and every claim with a `[n]`,
  compiled in by `web/tools/vendorkb.c`; `"vendor_research"` on both
  routes, `{found:false}` and "no research yet for <name>" for a
  vendor without a file. Sources as plain text lines, never links.
  <!-- count:vendors -->276<!-- /count --> entries today, covering most
  of the reference host's vendor names; the rest are pending because
  nothing public ties them to a company (`web/data/vendors/COVERAGE.md`
  lists both and carries the totals, held to the lists by the test). A
  registrant that is a separate company in an entry's group (an
  affiliate) finds the entry marked as another company's, its country,
  parent and founded left unknown. [[vendor-research]] has the format,
  the coverage and the rules the build enforces.

## M5: WiFi, History and the SQL box

The full account is in
[`web/README.md`](../../web/README.md#wifi-history-and-the-sql-box-m5).
In short:

- **WiFi** (§8.8). `/api/wifi/channels`: a channel x time grid of
  `wifi.ap_count` (mean per cell) or `wifi.ctrl_total` (sum), rows
  2.4, 5 and 6 GHz by channel, then channels sloth could not place
  (`?`), with a rule between bands, the finest
  tier that covers the range, keys from the rollup and the store.
  `/api/wifi/aps`: `beacon_aps` through the M4 allow-list, AKM bits
  decoded to suite names (`src/rsn_ie.c`'s), downgrade flags by name
  (`WPA_DG_*`), MFP, SSID history and count, KARMA score; an SSID count
  above 1 in `--sev-warn`. Since v5 of slothweb.db each cell of the
  grid is also a stacked bar of the five busiest transmitters on the
  channel in it (`/api/wifi/channels?mix=1`, from the frame counts of
  `beacon` and `probe_client`, a station's on the channel of its latest
  probe; `assoc` counts both ends' frames and is left out; APs in their
  SSID's colour, clients in their MAC's), with a heat strip per row for
  its busyness and the five listed on hover, tap or the arrow keys.
  Every SSID, and every alert title and detail (sloth writes the SSID
  into them as it came), is sent in a display form (`\xNN` for any
  octet that is not printable UTF-8, Default_Ignorable code points and
  blank lookalikes included, flagged "non-printable"), coloured over its
  octets as the TUI colours it. Every table on the page sorts by a
  column (in place, by the column's type; server-paged ones through the
  route's checked `sort` word and `dir=asc|desc`, addresses by number on
  the server too) and resizes by its header's edge
  (drag, arrows, double-click to fit), widths and sort kept per table
  in the browser with a `reset columns` control ([Kept
  settings](#kept-settings-2026-10-27)).
  `/api/wifi/deauth`: frames per bssid with
  DEAUTH_FLOOD episodes matched on the predicate-only alert key. Probe
  clients from `/api/series` over the M3 band.
- **History** (§8.10). `/api/history/overview` (the 30 d strip: devices
  first seen and alerts begun per cell, sessions as markers; counted per
  cell over sloth's `idx_<t>_first_seen`, or without it bucketed from
  the rows in range, found by `last_seen` when most of the table is
  older; cached 60 s per sloth.db state, the `-wal`'s included; a
  timeout names the read, the rows it had counted and how it was
  reading them (`plan`); 1500 ms is 6–12 times the snapshot's idle
  desktop scan, 1.3–5 times a loaded one — see [[sqlite-schema]] and
  `web/README.md`),
  `/api/history/devices` (who was here: `[first_seen, last_seen]`
  overlapping the range, presence over the range and nothing past it,
  from the hour tier as well for a range older than
  `--web-retain-days`), `/api/history/alerts` (an alert row is a
  finding since sloth's schema v8, #170: it matches a range from its
  latest incident's start, `incident_first_seen`, not from the
  finding's `first_seen`, so a range inside the quiet gap between two
  incidents does not list it; since v11, #175, a key with rows in
  `alert_incidents` is read from those, so its `sev`, `count`,
  `first_seen` and `incidents` are the incidents' in the range — a key
  CRIT once and LOW since reads LOW in a range holding only the LOW
  one — and an earlier incident in the range lists it at all)
  and `/api/history/flows` (no key, detail, cookie or username;
  `mqtt_flows` not read), `/api/sessions` and `/api/sessions/new`:
  `--report`'s new APs, devices and probe clients since the previous
  session's `COALESCE(ended, started)`, the window closed at that
  visit's end for an older session.
- **The SQL box.** `--web-allow-sql` (default off; `--strict` refuses
  it; announced with `--web-allow-remote`). GET only; the text checked
  (one `sql=`, UTF-8, `SELECT` or `WITH` first) before anything is
  queued; M4's opener; one statement (the tail must be blank); an
  authorizer allowing `SELECT`, `READ` and a short function list and
  denying everything else, and denying `READ` of the withheld columns,
  `sqlite_dbpage`, `sqlite_stat3/4`, `dbstat`, `pragma_*` and anything
  outside `main`; `sqlite3_stmt_readonly()`; limits; 5 s by a progress
  handler, 10,000 rows, 4 MB; no temporary file (a sort past the 2 MB
  cache is a `400` `temp_space`); one query at a time on its own thread,
  a second a `503` `busy`, and after each statement a rest as long as
  it ran, so sloth can restart its WAL while a client loops the box. The withheld columns (`web_secret.h`) are one list for
  both readers: `tests/test_db.c`'s guardrail words and the credential
  words on any TEXT/BLOB column, plus `alerts.key`, `alerts.detail`,
  `cleartext_creds.username`, `mqtt_flows.last_username`,
  `rogue_radius.last_identity`, `rdp_flows.last_cookie`; deliberately
  withheld in the box too. The recipes are extracted from
  [[sqlite-schema]] by `web/tools/recipes.c` at build time; the
  "Findings by severity" and "Cleartext credential exposures" recipes
  read a withheld column, and "What is actually taking the space?"
  reads `dbstat`, and the three are refused naming it.

## M6: Flows, polish, the README

The full account is in
[`web/README.md`](../../web/README.md#flows-m6). In short:

- **Flows** (§8.9). `/api/flows?proto=` reads one of `ssh_flows`,
  `rdp_flows`, `smb_sessions`, `snmp_flows`, `ldap_events`,
  `kerb_events`, `bgp_sessions` through the M4 allow-list, paged
  (`limit` 1..200, `offset`), sorted, filtered by an address, each
  parameter validated whole. `mqtt_flows` is never read
  (`proto_withheld`): it holds MQTT usernames. The columns a tab leaves
  out are named in the answer: the SSH banner, the RDP cookie, the SNMP
  community count, and Kerberos' two preauth counts, which are integers
  but named for a credential word, and the allow-list's name guard
  (held to `tests/test_db.c`'s guardrail) is not made type-aware to
  admit them. An SMB1 session (`smb_sessions.dialect`, sticky to
  `SMB1` in sloth) is `smb1: true` and drawn in `--sev-crit`.
- **The chord diagram.** `/api/flows/graph`: the largest pairs of the
  pair tables (at most 200 read), their busiest endpoints (at most 64
  drawn), and a `fold` that says how many pairs, counted flows and
  addresses were left out of how many; drawn on Canvas 2D by protocol
  hue with a text legend and the fold line. A label too long for its
  width is cut from the left only after a `.` or `:`, behind `…`
  (`….51.100.1`), so a cut address never reads as a different whole
  one.
- **Polish.** Found by driving the page in headless Chromium against
  the demo in four states (full, no `--sloth-db`, no stream,
  `WITH_SQLITE=0`) at 1280 and 360 px: the view list as buttons in tab
  order, rows and cards focusable with `Enter`, the drawer taking and
  returning focus, wide tables scrolling inside their own box, header
  columns aligned with their rows, pointer events on the History strip,
  `color-scheme: dark`, the view in the address (`#flows`, through
  `window.history`: a local `history()` once hid the global and the
  call failed silently), and a memory-only build's pages saying it
  cannot read sloth.db.
- **The README** (`web/README.md`): prerequisites, build (the committed
  IEEE CSVs and `make update-oui`), the demo, running beside sloth (the socket
  and its permissions, `--sloth-db`, `--store`), opening the page; a
  troubleshooting table of every start-up message, scraped from the
  source by `test_readme.c` so an undocumented one fails the suite; and
  the security section.
- **Demo and check.** `make web-demo` builds `build/web/slothweb-demo`:
  `db PATH` writes a sloth.db from sloth's own DDL, `feed unix:PATH`
  serves a generated stream in sloth's record shapes and order, both
  with documentation addresses, locally administered MACs and example
  names only. `make web-quickstart-check` follows the README's quick
  start literally in a temporary copy of the tree and curls
  `/api/health` and `/`. The screenshots in `docs/assets/slothweb/` are
  of that demo.

## The restyle: Spacetrucker chrome, TUI data (2026-10-23)

The page took the owner's own design system, Spacetrucker
(www.river.io/jeff), for its chrome, and sloth's TUI colours for its
data (owner ruling 2026-10-23: "color code all data the same as the
sloth cli"). The full account, with the token mapping, the data table
and the contrast table, is `web/README.md`'s Design section.

- **Chrome.** `web/ui/theme.css` holds the site's tokens (void, panel,
  ink, dim, the phosphor family, brass, amber, ice, violet, the glows)
  under slothweb's semantic names (`--bg`, `--panel`, `--ink`,
  `--muted`, ...). The components are the site's: a brass-edged sticky
  top bar (title, views, theme toggle), the pill status strip, eyebrow
  panel titles, brass-bordered rounded cards, the site's buttons and
  chips, dotted row rules, HUD brackets and a dot grid on the KPI
  tiles. The side panel is gone: its sock/db/store lines are a footer.
  Fira Code is named first and used only if installed; still no font
  file and no request. No motion layer (a page updating every second
  would retrigger it); the title's cursor blinks, off under reduced
  motion; the CRT scanlines and vignette are a quarter of the site's
  strength, under every panel, off in light and under reduced motion.
- **Data.** Every address, SSID, host name, info string, severity, heat
  level and sparkline is coloured as the TUI colours it, the dark theme
  byte for byte: the hash palette (`tui_ip_fg` by `ip_color_index()`),
  bold for an address seen in two or more sources, SSIDs by their own
  hash, host names through the brand table (Google's letters in the
  logo's sequence), info strings in the earth tones, the phosphor
  pairs, `tui_heat()`'s thresholds, the sparkline's level grading,
  every record sloth emits from the monitor radio (beacons to EAPOL) on
  the monitor rows' xterm 236, and the alert-hot override: for an hour
  after an alert names an address as its `match_ip`, that address is in
  `CP_ALERT_HOT_*` by the alert's severity, bold from WARN, over the
  hash colour. `web/tools/palette.c`
  generates the colours at build time from `src/tui_palette.c`'s pair
  table and `src/tui.c`'s brand table (never copied by hand), and
  `test_tui_colors.c` runs the TUI's own renderer against the page's
  functions on fixed addresses (alert-hot ones too), SSIDs (non-ASCII
  ones through the page's own UTF-8 encoder) and host names (upper-case
  ones through its lower-casing) and requires the same colour for every
  byte.
- **Light theme.** The site's cream, behind the toggle; dark is the
  default whatever the browser prefers, the choice kept in
  `localStorage` (the page works without it) and applied by the head
  script before first paint, inside the same CSP hash. The data keep
  their hues: each TUI colour's HSL lightness is lowered in 0.005 steps
  until it reads at 4.5:1 on both the light `--bg` and `--panel`.
  Canvases read their colours from the custom properties and are
  redrawn on a toggle.

## Deployment and freshness (#153, #168)

- **The unit.** `packaging/systemd/slothweb.service` runs slothweb as
  `sloth`, the sensor's own account (its state dir is `0700 sloth`,
  its socket `0600 sloth`), with both capability sets empty,
  `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=yes`,
  `/var/lib/sloth` in `ReadOnlyPaths=` (with `-`, so a host whose sensor
  never started still runs it), `RestrictAddressFamilies=AF_UNIX
  AF_INET AF_INET6`, the signal syscalls denied (the shared uid could
  otherwise stop or kill the sensor; [[deployment]] §6 states the
  tradeoff) and its own `StateDirectory=slothweb`. `ExecStart`
  fixes `--socket unix:/run/sloth/sloth.sock`, `--sloth-db
  /var/lib/sloth/sloth.db` and `--store /var/lib/slothweb/slothweb.db`;
  `/etc/default/slothweb` adds the bind (loopback when empty; the
  Tailscale recipe with `--web-allow-remote` and a single `/32` is in
  the file, commented, with placeholder addresses). `make install`
  places the binary, `make install-service` the unit and, no-clobber,
  the defaults. `sloth-migrate-sensor --with-slothweb` installs, starts
  and verifies it after the sensor ([[deployment]] §4.3, §6).
- **The live file, read in place.** As `sloth`, beside a running
  sensor, slothweb opens `sloth.db` as a WAL reader (`readonly_shm=1`)
  and makes no file beside it; `test_same_uid_reader_beside_a_writing_sloth`
  holds that with the directory made `0500` and `sloth.db`, its `-wal`
  and `-shm` `0400` for the reads (the read-only mount, by mode) and a
  writer of the same uid committing between them. It does not pin
  `readonly_shm` itself: with the `-shm` unwritable SQLite reads it
  read-only either way, as under the real mount;
  `test_crashed_sloth_restarts_beside_a_reader` does.
- **How old the database is.** `/api/health` carries `sloth_db_mtime`
  (the file's, or for a WAL reader the newer of the file's and its
  `-wal`'s) and `sloth_db_age_s`, and `sloth_db_stale` (older than
  `sloth_db_stale_after_s`, 600 s, while the stream is current). The
  Devices, WiFi access-point, Flows, History and Lookup views each say
  `database as of HH:MM` (the date in front when it is not today's),
  in the warning colour with the age when
  stale. A `--sloth-db` copy replaced by `rename(2)` is read from the
  next request; `web/README.md` gives the checkpoint-safe refresh
  (`sqlite3 ... ".backup"`, then a rename).

## The Alerts page and an alert's page (2026-10-26)

Owner requests 2026-10-23..26: the `6 Alerts` tab was a placeholder.
It is now the Alerts page: the stream's open incidents first (the
open-alerts tile counts exactly these), then the recently resolved ones
and sloth.db's rows, one row per alert key from both sources (sloth.db's
rows of a key grouped, about 114 a key on the owner's pre-v8 host,
#170; the stream's incidents of a key shown as its open one, else its
newest closed one), each with the key's incidents and count, the same
two the alert's page shows, filtered by state, severity, type and a
search word.
`/api/alerts` and `/api/alert` are GET only and validated whole.

Any alert, wherever it is listed (the Alerts page, the Overview's
latest alerts, History's alerts in the range, the device drawer), opens
its own page: what it is (the rule table's trigger in one sentence,
the whole entry folded under "details", severity, ATT&CK),
why it matters (every research corpus document that cites the type),
how to investigate and fix it ([[alert-remediation]], written for all
90 types), the evidence (severity history, counts, first and last seen,
whether sloth saved a pcap, the detail text), every incident of its key
as runs, and the device it names. On a sloth.db v11 file (#175) the runs
are built from `alert_incidents`, each run its incidents' own peak and
count (`"history":{"source":"incidents"}`; `"rows"` for a key with no
incident rows, whose single v8 row makes one run of the finding's peak
and sum), and `/api/alert` adds `db_incident`: one incident's own
`first_seen`, `last_seen`, `sev`, `peak_sev`, `count`, `observations`,
`closed_at` and `reason` — the stream incident the page opened on,
matched by sloth's id as a predicate (`"which":"opened"`), else the
key's newest (`"latest"`); `null` without such rows. The page's `sev`
and `count` stay the finding's. The figures are data for the page's
header, whose layout is #179's. The first three are extracted at
build time by `web/tools/alertkb.c` from the files themselves, never
copied, and `web/tests/test_alertkb.c` holds every type to having them.

**What the alert did leads, count trails (#179, 2026-11-03).** For a
per-tick rule `count` is how long the condition stood, about four a
second: three EVIL_TWIN bundles copied on the reference host read
44.8M, 44.9M and 39M against `observations` of 1, 1839 and 1839, and
the operator read them as attack intensity. The page's header now reads,
under the type, severity and technique: the detail changes
(`observations`), the times opened (`incidents`), first and last seen
and the span, the rule's `confidence` and its verdict phrase
(`rule_reason`), and `count` last, labelled evaluations, with a tooltip.
`/api/alert` writes its members in that order, so the copy-JSON
bundle's `alert.page` does too; nothing is renamed, since the names are
contract. `rule_reason` is EVIL_TWIN's or KARMA_AP's own phrase ("vendor
OUI differs", "candidate, uncorroborated", "attack-in-progress", ...),
matched at ingest against a table of the rule's literals in the text
after the detail's last quote (every remote string those rules write is
a quoted SSID), so the word served is the table's, never the detail's
bytes, and it is shown where the detail is withheld; a test holds every
word to a literal in `src/alerts/rules_twin.c`. Both fields are the
stream's: sloth.db keeps neither. The Alerts page sorts its open rows
by severity, then observations, then the newest change, never by count,
shows a changes column ahead of incidents and the evals column, and
draws a row at or under 20% confidence muted (owner ruling
2026-11-03: `<= 20`, so the 20% "vendor OUI differs"-only EVIL_TWIN
rows are muted) (display only), never a CRIT
one: EVIL_TWIN keeps CRIT on a hard signal however far context lowers
the percent (an uninventoried BSSID with a copied OUI and a forged
802.11k claim reads 5%), and muting it would make that claim the
lever the rule refuses it.

M4's rules hold. `alerts.key` stays predicate-only: the reads
group by it and match on it, a list row is named by an opaque
`d<rowid>` or `s<handle>`, and a stream incident's key is kept in
memory as a bound predicate, never rendered. sloth's `incident_id` is
not served either: FNV-1a64 over the key, the creation time and a small
counter, it inverts to the key's unsalted hash, and from there a
dictionary recovers a `CLEARTEXT_CRED` username. slothweb names an
incident by its own handle (a startup nonce and a counter), in the
list, the alert's page, its links and `/api/live`'s `alert_id`. And credential material
stays off the page: an alert's detail is shown only for the 50 types
whose every detail format `web/tests/test_alertfmt.c` audits from
`src/alerts/` on every run to carry numbers, addresses, ports,
channels and network names only; the stream's detail of any other type
is not kept, and sloth.db's is read through `web_detail_ok(type)` inside
SQLite.

The lists are bounded: each reads at most 20,000 rows that its filters
match, newest first through `idx_alerts_last_seen`, the filters inside
the bounded read so an old row of a rare type or address is reached by
asking for it, and says when it stopped there and how far back it got.
A filter that matches little walks the window under the 250 ms budget;
on the owner's uncompacted 868k-row file a rare type over the full
400-day window is past it (a 503 that says so), the default views are
inside it, and `--db-compact-alerts` (#170) makes every one a few
milliseconds. History's alerts in the range collapse by key the same
way, each listed key counted over all of its rows in the range through
the primary key, with the scan's bound reported; the drawer's alerts
naming a device walk the table newest first a slice at a time, the
device test inside the read, until the budget, and say how far back
they got when it stopped them.

Every Overview tile is a link (keyboard and focus included) to the view
of what it counts: throughput to Activity's per-interface rx and tx and
top hosts, devices to the Devices view under `pass:latest` (the latest
pass's MACs, a new query term), open alerts to the Alerts page's open
rows, open anomalies to every open episode, records/s to the records by
type, sensor health to a health view (capture, monitor, the stream,
sloth.db and its freshness), each with its filter named and a way back.
A test asserts each count on the demo's own data.

## Copy JSON: the analysis bundle (2026-10-27)

Owner request 2026-10-27: a **copy JSON** button (and **download
.json**) on every detail view (the device drawer, an alert's page, the
Lookup card, the BLE drawer, a TACDB platform) that captures the view's
data as one JSON document to paste into Claude for analysis.
`/api/bundle?kind=device|alert|lookup|ble|platform&id=` answers it. The
bundle splices the detail routes' own answers in verbatim rather than
re-rendering them, so it carries exactly what the page shows and
nothing it withholds (alert key, `incident_id`, unaudited detail,
credential columns); around them an envelope (schema, time, server and
time zone, sensor health, sloth.db, the capture scope in effect and
what it excludes, a `withheld` list), optional sections, a glossary, a
suggested prompt and the limits applied. The sections are routes'
bytes as well: `frrs` is the FRRS record as `/api/frrs/report` (a
device, a BLE address) or `/api/frrs/report/alert` answers it, an
alert's `triage` is `/api/frrs/history`, and `vendor_research`,
`assessment` and `evidence` (the capture files listed with their
hashes, never a pcap's bytes) are lifted whole out of the drawer's and
the alert page's own answers; `location` is a device's
`/api/positions?mac=` answer (where the sensor was when it heard it,
and its track) and an alert's page `loc` stamp. What no build has yet
(a COMINT report, signal history) reads `{"available": false, "reason": ...}`,
as does a section whose route did not answer (`no_store` without
slothweb.db; under Local a BLE address's record is `withheld` with its
drawer). `server.slothweb.build_version` is the sloth source
tree slothweb was built from; slothweb has no version of its own. The
ticker records a bundle lists are matched on their address members
(`mac`, `ip`, `src`, `dst`, ...), never on the 80-byte line, which a
long name can cut so that `192.0.2.123` reads `192.0.2.12`.
512 KB hard cap, optional sections dropped first. The
copy works on plain http (a hidden textarea and `execCommand`) where
`navigator.clipboard` does not exist. Detail in
[`web/README.md`](../../web/README.md#copy-json-the-analysis-bundle).

## Sensor location (2026-10-27)

sloth's `--location` / `--gps` stamp ([[location]]) reaches the page in
two places. An alert's page gains a "where the sensor was" section
(`#loc-alert`): the coordinates, the accuracy estimate, the altitude,
the source and the time sloth received the fix, and a copy button. The device drawer
gains a scatter (`#loc-drawer`) of where the **sensor** was each time
it heard the device, coloured by RSSI, with the sensor's track, drawn
on a local projection with no map tiles, and GeoJSON / GPX exports.
Both come from `web/ui/location.js` (`window.SlothLocation`), one hook
per view, so the rest of the page is unchanged. Server side:
`web/src/web_loc.c` (the stamp, range-checked, from the stream's `loc`
object or sloth.db v9's alerts columns) and `web/src/web_positions.c`
(`/api/positions`, at most 200 samples an answer so the widest
rendering fits the 64 KiB response; a cut answer says so in every
format — JSON and GeoJSON `"more":true`, GPX `truncated` in its
metadata). slothweb reads schema v1..v9;
`device_positions`, `sensor_positions` and the six stamp columns are on
the allow-list. Details: `web/README.md` *Sensor location*.

## Capture scope (2026-10-26)

Owner request: a Monitor | Hybrid | Local switch in the top bar that
filters every view by where and how the data was captured. Hybrid is
everything, as before; Monitor is the passive monitor radio (and the
BLE receivers, passive radio too) with nothing from the connected Wi-Fi
or Ethernet; Local is the host's own interfaces, the managed card's own
scans included, never the passive radio. sloth's records carry no
capture path, so `web/src/web_scope.c` places each by what it is, in
one table the tests hold to the files it classifies; every `/api` route
takes `scope=`, the server counts, pages and filters, and the page
keeps the scope's records on its ticker. A device seen both ways is in
both scopes with each scope's own fields; under Local the WiFi view is
the managed card's own scan and link (`/api/wifi/local`, sloth.db's
`wifi_aps` and `wifi_stas`) with the radio's panels not drawn, the Flows
are empty under Monitor saying why; the SQL box is unscoped. sloth's
`sensor_health` gained `capture_linktype`, so the stream's IP-capture
records can count as Monitor's while the IP capture is itself a radio
(the host's own ARP table, leases, scan entries and socket table, with
the top hosts, THREAT_IP and BEACONING read from it, never do), and
`monitor_only`, reported but not used to tag (an `any` handle's
allow-list can hold wired interfaces too). An `/api` answer without
`scope=` is as before; `/events` records gained `sc` (and a device
row's Monitor line, `text_m`). The whole of it, view by view:
[[capture-scope]]. `web/tests/test_scope.c` asks every route under
each scope against one fixture with a MAC seen both ways, each absence
seen red under a named mutation.

## Kept settings (2026-10-27)

Owner request: "the web interfaces columns should remember sorting and
sizeing the whole UI should keep settings between launches where it is
changeable". Every control a viewer can change is kept per browser in
`localStorage`, one JSON value per setting under one versioned
namespace, `slothweb.v1.<name>`; no server state and no endpoint. The
view (a tab's), theme, scope, sensitivity, each table's column widths
and sort (by the table's id, through the one `DataTable()`), the
ticker's pause, the collapsed chrome, the Anomalies chip and mode, the
Activity metric and each metric's key, and every view's filters,
windows, sorts and search boxes, the SQL box's draft included. An
address that names a view, a filter or a scope wins, and a filter it
or scope it sets is not kept, so a link reproduces what it names: an
Alerts address naming any filter sets the others, the search and the
window included, to their defaults; a kept filter never raises a
drill-down bar, and the bar's `show all` clears the kept filters; the
Anomalies kind chip narrows its own list, never the Overview's top
five or the tile's drill-down. The kept values are what the bare
address and a tab click open on. A kept width for a
column a table no longer has is ignored, one under the column's floor
is drawn at it; a kept sort on a column that is gone or no longer sorts
is left off. Blocked or cleared storage is the defaults, never an
error. The keys of the build before (`slothweb.theme`,
`slothweb.scope`, `slothweb.sensitivity`, `slothweb.cols.<table>`) are
moved into `v1` on the first load, and no other key is touched (a
later build's `slothweb.v2.*` survives this one, and its reset). Each table keeps its `reset
columns`; `reset settings` in the footer forgets everything and loads
the bare address again. What is deliberately not kept (the History
range, the Records type pick, the drawer, the recipe picker) and why,
setting by setting: [`web/README.md`](../../web/README.md#kept-settings).
`web/tests/test_prefs.c` holds it by the page's text, and fails on a new
form control (any attribute order) or ARIA toggle that is neither kept
nor listed as not kept; the behaviour
(sort and resize, relaunch, still there; reset; storage that throws)
was driven in headless Chromium.

## The glyph layer (2026-10-27)

[`docs/web-visual-spec.md`](../web-visual-spec.md) specifies the
glyph set for the page's data graphics, and the rules every glyph and
panel follows; its rulings table of 2026-10-26 overrides its body.
Slice V0 builds the first three of them — **G1** the band sparkline, **G5** the binary presence
strip, **G6** the bullet and count bar — and writes the rules down in
[`web/README.md`](../../web/README.md#the-glyph-layer): R1 to R12, the
caption grammar (R9: source, window, tier, scale, n), the three empty
states (R5: `no data`, `warming`, a gap, which never look alike) and
the honest-window rule (R4: data covering less than a tenth of the
window shrinks the window to the data and says `6 min of 24 h`). It
adds no data: no new series, no changed route payload.

Each glyph is a pure function from data and a size to a list of marks
(`[kind, x, y, w, h, token]`, CSS pixels and a colour *token*, never a
colour) plus a painter that draws the list. That split is what makes
the page's canvas code testable: `web/tests/test_glyph.c` ports the
geometry into C line for line and pins the JS verbatim out of the
served page, so a change on either side fails `make web-test` — the
mechanism `test_tui_colors.c` already uses for the TUI's colours, and
the one the owner chose (ruling 2 of 2026-10-26) so the suite stays
free of node. `web/tools/palette.c`'s generator is the other shape in
this tree and does not fit: a palette is static data a tool can emit,
a glyph's geometry is a function of data the page only has at run time.

Two rulings of 2026-10-26 shape G1. Ruling 1 keeps **TUI parity for
the sparkline's ink**: R1's "one ink" holds for every glyph except
G1's line, which grades by level exactly as
`src/views/dashboard_primitives.c :: draw_sparkline_at()` does, with
out of band still said by the band and by the last-value dot. Ruling 3
keeps G2's −67 dBm reference line, captioned as a field rule of thumb
(G2 is slice V2). R12 is why each of the three names its character-cell
form in the README: a glyph with no TUI form is not added.

Finding F5 lands with it: the status strip holds the network's facts
(`devs alerts anomalies rec/s`, with the scope control and the page's
own live dot) and the footer holds every fact about slothweb
(`sock db store tick up clients`), one row each and never mixed. The
strip's `sensor` pill is gone — it was the footer's `sock` under
another name. `web/tests/test_routes.c ::
test_the_strip_and_the_footer_are_split` holds the two rows apart by
element id.

### Slice V1 (#171, 2026-11-03)

The MVP's second half: after it every number on the Overview has its
comparison. The series landed first (379ac49: `live.devices`,
`live.alerts_open`, `live.anomalies_open`, `records.rate`,
`sensor.drops`); this slice adds `records.total`, the same records
unkeyed, so the records/s tile is one read rather than one per type,
and draws them.

- **Tiles (F1, ruling 5).** Urgency first: open alerts, open
  anomalies, sensor health, throughput, devices, records/s, then BLE
  advertisers. Each has the 24 h G1 of its series over the band for
  each bucket's hour, and under it G1's words: `band lo to hi` (or
  `warming`) and `↑ ↓ →` since the previous bucket. The number is still
  `/api/live`'s. `web/ui/facts.js` owns the six series and paints the
  tiles, the strip's 40 px G1s after `devs ble alerts anomalies rec/s`,
  and the footer's `drops` (§6.9) with its last bucket's count beside
  it, its words naming the bucket (`drops per 10 s`); the throughput
  tile stays app.js's.
  The V1 series are Hybrid's, so under Monitor or Local their glyphs
  are the `no data` dash and the words name the scope that holds them.
- **Anomaly cards (F13).** G1 of the metric that fired over its band,
  the episode's window shaded in `--signal` at 12 percent, a caption;
  `series unavailable` in the glyph's place when the read fails. A
  window over an hour reads the minute tier when there is a store, and
  a card keeps its y-range across the Overview's minute (R11).
- **Hour of week (F3).** The grid is G4 in `glyph.js` now: a warming
  cell plain `--rule` with no hatch (R8), an all-warming grid only its
  now outline, the caption `warming: n of 168 cells` with the ramp's
  top and n. The warming meaning is that word count (R10). G4 has no
  TUI form yet; the grid predates the glyph layer, so R12 is owed, not
  met.
- **Small multiples (F6).** One shared y-scale by default, its top in
  the caption, a `scale: own` toggle kept in the browser (each cell then
  prints its top), sorted by |z| when a key has a baseline and by value
  otherwise, the caption naming which.

Not in V1: one-ink sparklines (F7, overruled by ruling 1), F4's hover
notes, the Records panel's per-type G1 (§6.1), G4's TUI form.

### Slice V2 (#171, 2026-11-03)

The RF half: how near an emitter is, and whether it is coming closer,
as a glyph beside every signal number.

- **The series (§7).** `ap.rssi` and `sta.rssi` are the `rf.rssi.bssid`
  and `rf.rssi.sta` gauges that already fed the FRRS Report: the same
  quantity, so no new metric and no slothweb.db step. The spec's assoc
  and `wifi_sta` sources for `sta.rssi` are the AP's signal, so they
  are not in it. Each `/api/devices` and `/api/wifi/aps` row, the
  drawer's `/api/device/{mac}` and the Lookup card's `/api/lookup`
  carry an `"rf"` member (`web/src/web_rf.h`): 60 minute means of the
  fine buckets in memory, the whisker at the last value (the beacon's
  own 60 s range when that beacon is in the last value's minute, else
  that minute's samples), and sloth's band and
  trend. Under Local it is null.
- **Agreeing with the distance estimate.** G2 fits no slope and draws
  no distance of its own. Its number is bold when sloth's
  `est_dist_trend` says `approaching`, and after it come sloth's band
  and trend glyph as the TUI's distance cell prints them (`room ↘`),
  read from the latest beacon or probe_client record in the FRRS
  ledger and passed on only as one of sloth's words. Each table's
  caption counts `n approaching (sloth's estimate)`.
- **G2 (F9, F20).** In the Devices and AP tables' `dBm` column at 72 by
  14 px, on the fixed −95 to −20 dBm scale, with the −67 dBm rule
  (ruling 3: a field rule of thumb, not a standard); every row draws
  the same hour so the rows compare. At full width in the drawer and at
  the end of the Lookup card, with three time labels and R9's caption;
  there R4's shrink applies, and an empty trail is its caption.
- **New (F15).** A `--signal` dot before the swatch of a row first seen
  in the last 24 h, counted in the caption; G5's first-seen mark on the
  strip.
- **G6 (F17).** Bullets on risk (sloth's levels, tick at HIGH), karma
  (`karma_candidates.score`, the TUI's 1 to 7 `[y]` score, tick at 3,
  the least a PNL- or deauth-corroborated candidate scores) and
  the anomaly score (tick at 60 for A1, cards and table); bars on the
  Devices anom and Flows total columns, each on its column's largest
  value. The card's rounded score bar is gone (R8).

Not in V2: G2's TUI half (the Devices Enter signal trail on the fixed
scale), the Flows counts column, G4's small form on the Lookup card, G2
on the managed card's tables (another receiver, no series) and on the
WiFi Clients panel (V3, below).

### Slice V3 (#171, 2026-11-03)

The air picture: the WiFi view is four panels, top to bottom, as
`docs/web-visual-spec.md` §6.3 lays it out, and History's strip says
how many.

- **Channels: G3 (F8).** One horizon strip per channel seen in the
  last 30 days, two bands laid over one another. The scale is the
  server's, never the busiest cell in view: `/api/wifi/channels` rows
  carry `"scale"` — `absolute` with the channel's own largest over 30
  days (the fine ring's day without a store), or `z`, with a `"z"` per
  cell, for `ctrl_total` against its hour-of-week baseline, scored as
  A1 scores a minute. On a z strip the second band begins at the
  slider's k and is the panel's only colour (`--heat-2`), so the strip
  is flat while the channel is normal. Nothing observed, observed and
  quiet, and warming are three different marks (R5). The `channels`
  control keeps the stacked grid of 2026-10-26 one choice away.
- **The drill-in (ruling: both).** A picked column is drawn beside the
  strips as each channel's five busiest transmitters, stacked in their
  TUI colours, and the list under the panel names the picked cell's.
- **Emitters.** The AP table nearest first by default, the SSID count
  a row of `▪`.
- **Chains.** The deauth frames as a G7 rug (since V4, of the bssids
  with one stage; G8 draws the rest), one lane per bssid with a frame
  or a flood in the window, on one scale, flood
  episodes underlined in `--sev-crit`; no deauth collapses the panel
  to `0 deauth in the window` (F16).
- **Clients.** The probe-client chart over its band (hidden when it has
  no points, F16), and the probing clients last seen in the window,
  nearest first, each with G2 and G5.

`web/ui/air.js` draws the strips, the drill-in and the deauth rug. Each
strip prints its own top beside its key (R3), and when the channels
were observed for less than a tenth of the window every strip draws
only those columns and the caption says `6 min of 1 h` (R4).
- **History (F12).** The 30 d strip is G7: a lane for devices first
  seen and one for alerts begun, each tick its cell's count on one
  scale for both, the tallest in the caption; survey sessions full
  height.

Not in V3: the probe-flood rug (the page has no alert type table to key
`alerts.fired` by), per-severity ticks on History's alert lane, and
G3's and G7's TUI forms (R12).

### Slice V4 (#171, 2026-11-03)

The projection layer's last two pieces: where in an attack chain a
BSSID is (F14), and who talks to whom in one scan (F11).

- **G8, the chain timeline.** Four 18 px lanes on one time axis in the
  order the chain runs, `deauth`, `twin`, `assoc`, `karma`, each lane's
  axis drawn whether or not it has anything, so the stage not yet seen
  is an empty lane. Deauth frames and associations are ticks on one
  scale; each DEAUTH_FLOOD, EVIL_TWIN and KARMA_AP incident a bar from
  its first to its last observation in the severity it reached, its
  word in the lane's label (`twin CRIT 70%`); under the lanes the links
  sloth made, in words: `tainted ↑ 5 s` (a deauth flood on the other
  half within 5 s, sloth's `attack_in_progress`) and `attributed ↑`.
- **`/api/wifi/chain`.** The deauth rows, or one `bssid=`, each with
  the EVIL_TWIN and KARMA_AP rows sloth.db holds whose key names the
  BSSID (a predicate, never read out), the associations to it per cell
  (the station never read), and the links. A key is matched at its
  BSSID fields, never as a substring; an association is a stage only
  on a BSSID with a twin or karma row. sloth.db keeps no link G8 can
  draw (`twin_episodes` latches the taint with no time, and has no
  attribution or confidence; the attack-chain alert's key names the
  SSID and its detail is withheld), so the links are the stream's
  `twin_episode`, kept in memory by
  `web/src/web_chain.c` (64 pairs, evicted and counted), and the
  answer says since when. No new series and no slothweb.db step.
- **Where.** The WiFi chains panel draws one G8 per bssid with more
  than one stage and leaves the rest to the G7 rug, collapsing to its
  caption with none; the alert page, in an `attack chain` section
  above the device, draws the chain of the BSSID its key names
  (`/api/alert`'s `device.bssid`, a `beacon_aps` BSSID matched as a
  predicate), around the alert's span; the drawer draws it for a BSSID
  with more than one stage in the last 24 h.
- **The Flows matrix (ruling 4: matrix first).** `/api/flows/graph?
  form=matrix`: every endpoint of the pairs read, sources and
  destinations each in address order with their /24 or /64 group, the
  cells merged by pair. The page draws a row per source and a column
  per destination, a rule where the subnet changes, each cell G6's
  count bar on one scale behind its count, its protocols as letters
  (`S` `R` `M` `N` `B`), SMB1 in the critical colour; the chord is the
  `draw` control's second choice (kept). `web/ui/flowmx.js`.

Not in V4: G8's TUI form (R12), the matrix's TUI layout, a BSSID with
no deauth key as a candidate on the WiFi panel (its alert page and
drawer still draw it), the probe-flood rug.

**Sources**: `docs/web-visual-spec.md` (§2 F1-F20, §5, §8, §10),
`web/ui/glyph.js`, `web/ui/facts.js`, `web/ui/rf.js`, `web/ui/air.js`,
`web/ui/chain.js`, `web/ui/flowmx.js`,
`web/src/web_rf.c`, `web/src/web_wifi.c`, `web/src/web_chain.c`,
`web/src/web_flows.c`, `web/tests/test_glyph.c`, `web/tests/test_rf.c`,
`web/tests/test_chain.c`, `web/tests/test_flows.c`, `web/README.md` (Design),
`src/rf_distance.h` (the band and trend G2 agrees with),
`src/views/dashboard_primitives.c` (`draw_sparkline_at()`),
`web/tests/test_tui_colors.c` (the pinning mechanism),
`web/tools/palette.c` (the generator shape, for contrast).

## Triage and the FRRS record (2026-11-01)

The owner asked (2026-10-27) for triage buttons on every alert record
(*false*, *noise*, *incident*, *follow recommended*) and for the
information gathered in the shape of COMINT's Frequency Resource Record:
BEI, SCS, EC/S and TACDB, with the seven COMINT disclosures folded in as
a Report. The specification, the field-by-field mapping onto what sloth
records and the owner's open questions (Q1-Q16, each with the default
this build took) are [`docs/web-frrs-spec.md`](../web-frrs-spec.md);
the routes with their request and response shapes are
[`web/README.md`](../../web/README.md#triage-and-the-frrs-record).

- **Triage** is operator state in slothweb.db (schema v6, an additive
  step with its migration test on a v5 file and the failure that leaves
  it unchanged): one row per decision, appended, the state of an
  alert its newest row; a click that changes nothing adds no row. No
  bound refuses an operator's change: past 64 rows an alert's history
  folds (its first row and its newest kept, the folded counted and
  shown), imported rows hold at most 8 of it, and at 20,000 rows the
  oldest superseded rows fold, imported ones first; a clear is always
  taken, and the tile warns near the cap. Every alert row on every view carries the chip
  and the buttons; triaged-out rows (`false`, `noise`, `known`) are dimmed, never
  hidden, and the open-alerts tile keeps its count and says how many of
  it are triaged out. `/api/alerts?triage=` filters and counts; without
  it the answer is as before. Triage never reaches sloth.
- **A note over its bound is refused where the operator sees it (#181,
  2026-11-03).** The bound is 240 bytes of UTF-8; the field's
  `maxlength` is 240 too, but a browser counts UTF-16 units, so 121
  accented letters fit the field and not the server, and on 1.8.5 seven
  triages with notes of roughly 230 and 330 characters were refused while
  the page looked done. (That accounts for the 230s, not the 330: no
  note over 240 characters can be typed into the field, so that one was
  set by script, which `maxlength` does not bind, or posted directly.
  The page now measures what it is about to send, whatever set it.)
  The refusal now carries the bytes sent and the bound
  (`"length":242,"limit":240`, never the text), the page says
  "note too long: N of M bytes" beside the buttons, counts the note in
  bytes as it is typed, sends no note over the bound, marks a change
  pending until the server answers, reads the panel again after a
  refusal, and draws the history from the server's rows only.
- **Known** (owner request 2026-11-03: "a Green tag for known or a
  sigint term for known good traffic"): a fourth verdict, the button
  `known`, drawn green. Known good — expected traffic from a friendly
  or neutral emitter (the FRRS/EW affiliation sense: friend, or neutral
  per MIL-STD-2525's green); triaged out like false/noise, never an
  incident. Stored as state 4 after `incident`, so 0-3 keep their
  values; no schema step, because nothing in slothweb.db rejects 4 (no
  `CHECK` on the column, the word validated against the state table,
  anything outside it read as untriaged; an older build shows a known
  alert untriaged). No assessment recommends it.
- **Follow recommended** reads the research assessment's front matter
  (`--web-assessments DIR`, `<TYPE>.md`, until it closes;
  `slothweb.service` passes the copy `make install` puts in
  `share/sloth/alert-assessments`): *noise* only where
  `false_positive_risk` is `high` **and** `noise_verdict` `noisy` or
  `very noisy` (eight types), because `noise_verdict` says how the rule
  counts, not whether an alert is real (FRAG_PLAINTEXT is "very noisy"
  at a `low` false-positive risk); below that bar the button says "no
  automatic triage" and does nothing. The assessments judge a rule,
  not an alert: `false_positive_risk: high` (ARP_SPOOF carries it) never
  marks an alert *false*, and `severity_assessment` never makes one an
  *incident*; both are shown beside the buttons as advice (Q3). The
  compiled table the assessments' own generator will write replaces the
  reader.
- **The record** (BEI, SCS, EC/S, TACDB, Report) is built only from what
  sloth already records: sloth.db through the column allow-list (now
  holding the parametric columns too), the stream's latest records per
  emitter in a bounded in-memory ledger, and slothweb's own baselines
  and episodes. Every field names its source; absent is *not observed*.
  It says, every time, that a single passive sensor has no location
  axis and that sloth decrypts nothing. The Report's signal item plots
  RSSI against time (Q7, owner ruling 2026-11-02 "Keep, bounded"): three
  gauges, `rf.rssi.sta` (probe requests), `rf.rssi.bssid` (beacons and
  the AP's association frames) and `rf.rssi.ble` (advertisements), each
  the signal sloth last heard as a record reports it, sampled only while
  the record's `last_seen` is fresh. They sit in the existing tiers (the
  minute tier's 30 days, `--web-retain-days`), the Wi-Fi pair in the
  device class's keys and `rf.rssi.ble` in the BLE class's (#177), each
  under `--web-max-keys` with its eviction, Monitor's scope, and
  are not scored for anomalies. The record carries the last 24 h in 48
  half-hour cells with min and max, drawn on the alert page and in the
  drawer as the TUI's sparkline glyphs in its heat ramp; "no samples"
  when there are none. A receiver's own figure, not a calibrated
  measurement, and the record says so.
- **The TACDB tab**: units with subordinate units, platforms by
  nomenclature, each with its emitters (each opening its EC/S and
  Report), suggestions from sloth's own correlations (sequence-counter
  trails, Multi-Link affiliation, adjacent BSSIDs on one channel, a
  station both the host's card and the air heard) confirmed or
  dismissed by the operator, export and import as JSON Lines. A
  delete is reversible and keeps its row, so deleted rows count toward
  a bound twice each cap. The export carries live rows, parents first;
  the import refuses a file without its header first and its `end`
  line last (a file cut short merges nothing), merges whole or not at
  all in one prepared transaction (1,000 triage lines at most, `413`
  beyond), never merges two platforms on a name alone, never puts an
  older decision over a later one, and records the file's `by` and
  `peer` as claims beside the importer. Its check runs the merge and
  rolls it back, so it reports what the merge would. Operator data:
  a platform spans every capture scope, and each emitter row says which
  scopes heard it.

**The write surface.** slothweb was GET and HEAD only by the
2026-10-21 ruling; the owner's request reverses that for its own state
and nothing else. Six paths take POST: JSON with a checked
`Content-Type`, `Content-Length` bounded (4 KiB, the import 8 MiB) and
refused before the body is read, an `Origin` that must equal the
`Host` (slothweb sets no cookie, so Origin is the whole cross-site
defence), a token bucket per peer, every member validated whole and an
over-long value refused rather than cut. The allow list stays the trust
boundary: there is no login, and a row's "by" is the peer's address
and a typed name. `--web-read-only` removes the six routes and restores
the surface byte for byte. The UI is its own module
(`web/ui/frrs.js`, `window.SlothFrrs`) reached from `app.js` through
seven one-line guarded hook points, so the parallel slices changing
`app.js` merge around it.

**Sources**: `docs/web-frrs-spec.md`, `web/src/web_frrs.c`,
`web/src/web_frrs_report.c`, `web/src/web_frrs_tacdb.c`,
`web/ui/frrs.js`, `web/tests/test_frrs.c`, the owner's request of
2026-10-27.
**Last updated**: 2026-11-03 (#181: a note over its bound refused with the bytes sent and the bound, said beside the buttons, counted as typed, no row before the server confirms); 2026-11-02 (the Report's RSSI against time: `rf.rssi.*`, Q7 answered); 2026-11-02 (second review: history and the table's
cap fold instead of refusing, no row for an unchanged write, noise
recommended only for a high false-positive risk and a noisy count, the
import prepared once and bounded at 1,000 triage lines, imported `by`
and `peer` as claims, the check running the merge, bidirectional
controls refused, the body deadline scaled to its length, the installed
assessments passed by the unit); 2026-11-02 (review fixes: the
recommendation read against the assessments' real vocabulary, the
import's header and end checks and its transaction, the bounds on
deleted rows and imported triage, the suggestion rules as §7 states
them); 2026-11-01.
## An alert's proof: its capture, assessment and bibliography (2026-10-27)

Owner requests of 2026-10-27: "show the full packet capture in alerts
at the bottom as well", and the device drawer's alert rows tapped for
"full verbose details of the alert, include bibliography, when possible
prove the alert with evidence". The alert's page gains a last section,
drawn by its own module (`web/ui/evidence.js`, one hook in
`alertPage()` and one in `openDrawer()`, so the slices editing
`app.js` in parallel merge beside it):

- **Observed against threshold**: the incident's count, observations
  and span (labelled for what they are: `count` is evaluations, one per
  poll while the condition stands, and `observations` follows it once
  the detail moves, so neither counts frames or requests), the `name=value` numerals of an audited detail, beside the
  thresholds the type's assessment states; with no capture, why not,
  in sloth's own terms (no `--pcap-dir`; an L2-only rule, which the
  `--pcap-dir` export can never hold; under `pcap.min_severity`, CRIT
  by default; inside `pcap.key_cooldown_secs`; swept by
  `pcap.retain_days`). So "none saved" does not read as "nothing
  happened".
- **The assessment and its bibliography**: each
  `docs/wiki/alert-assessments/<TYPE>.md`, built in at compile time by
  `web/tools/alertasm.c` (lookup `web/src/web_alertasm.h`), front
  matter (its `count_semantics` and `noise_verdict` as written),
  sections and Bibliography entries as text. 72 of the 90 types have
  one; for the others the page says "no assessment yet". The build
  stops on a stem that is not an alert type or a `[n]` with no
  Bibliography entry.
- **The packet capture**, last: with `slothweb --pcap-dir DIR` (the
  sensor's own, read in place), every file the alert has, found through
  sloth's manifests ([[pcap-export]] §5, §6) by `incident_id`, the
  record's `pcap_path`, or, labelled, rule and time; its SHA-256
  recomputed over the bytes read (`hash verified`, `HASH MISMATCH`,
  `no manifest entry`); every frame decoded with its fields and hex
  dump, 24 a page, a filter, and the file downloadable. 802.11 frames
  are read with sloth's own parsers linked from `src/`
  (`radiotap.c`, `dot11_frame.c`, `dot11_ie.c`, `wifi_freq.c`,
  `dns_wire.c`, `netstr.c`; the first `src/` code in the slothweb
  binary, leaf files that include no `sloth.h`), with the IEEE Std
  802.11-2020 subtype, reason (Table 9-49) and status (Table 9-50)
  names; Ethernet, SLL and SLL2 by slothweb's bounded summary decoder.
  The sensor keeps 64 bytes of a packet, so a decode stops where the
  bytes do and every such frame says `truncated at snaplen 64`; a
  record cut short of its file's snaplen says `N of M bytes captured`
  instead, since the snaplen did not cut it. When more than one
  manifest line names a file, any line whose hash and size match
  verifies it (a later-stamped line cannot outvote it), and lines that
  disagree are said as `conflicting manifest lines (N)`. A name whose
  file is a symlink, a FIFO or anything not regular is listed as
  `unreadable: not a regular file` and cannot be opened.
- **The drawer's alert rows** carry a `›`, are 44 px tall on a touch
  screen, and a tap opens the alert's page and closes the drawer, which
  at phone width covers it. Checked at 360 px under touch emulation by
  `web/tools/tap_check.py` (by hand: it needs Chromium).

Never served: a handshake pcap or `eapol.22000`, which can share an
`--eapol-dir` and are crackable material: their names pass neither
alert-pcap grammar, their manifest sinks are not indexed, and a request
never names a file (the routes take an index into the alert's own
list).

Withheld unless asked for: an **evidence pcap**
(`<incident_id>-<event>-<RULE>[-N].pcap` in the `--eapol-dir`) is raw
802.11 frames from sloth's evidence ring, which notes every monitor
frame, so an EAPOL-relay or A-MSDU-EAPOL incident's file can hold
EAPOL/PMKID handshake material, the reason sloth writes it only under
`--collect-handshakes` ([[pcap-export]] §4). slothweb lists it with
`withheld: may hold EAPOL/PMKID handshake material` and neither decodes
nor serves it (`403 withheld_evidence_pcap`) unless started with
`--web-serve-evidence-pcap`, announced on stderr. With
`--web-allow-remote` the bare flag is refused (exit 2);
`--web-serve-evidence-pcap=remote` serves the files to remote peers
too, announced as such. The demo writes a made-up `--pcap-dir` for its SMB1 and deauth
incidents (`slothweb-demo pcaps DIR`, in the quick start).

**Sources**: owner requests 2026-10-27; `web/src/web_evidence.h`,
`web_pcap.h`, `web_pcapdir.h`, `web_alertasm.h`, `web_dot11_names.h`,
`web/ui/evidence.js`, `web/tests/test_evidence.c`,
`tests/fuzz/fuzz_web_pcap.c`; `src/alert_pcap.c`,
`src/evidence_export.c`, `src/evidence_manifest.c`; IETF
draft-ietf-opsawg-pcap; tcpdump.org link-layer types; radiotap.org;
IEEE Std 802.11-2020 Tables 9-1, 9-26, 9-49, 9-50.
**Last updated**: 2026-10-27.

## The BLE view (2026-11-02)

Owner request: "add bluetooth to the web ui". The reference host's
sensor runs with `--bt-monitor` and `sloth-ble-scan` holding a passive
scan, so the stream carries `ble_device` and `ble_alert` records and
`sensor_health` the `btmon_*` / `ble_*` / `btcap_*` members; sloth's
TUI has the `[*]` view ([[ble]]). sloth.db has no BLE table, so
slothweb keeps BLE itself: `web/src/web_ble.h` holds 1024 advertisers
(one row per advertiser **as one sensor heard it**, keyed address,
address type and sensor, as sloth keys them: the host controller and an
Ubertooth hearing the same address are two rows whose counts are never
summed), 128 findings (standing until the `alert.resolve` of the same
key, or quiet for two heartbeats), the latest `sensor_health`'s
Bluetooth block, and per row the last sixteen `(ts, adv_count)` points
for an advertising rate and a 96-bit strip of the quarter hours of the
last day it was heard in; and persists the rows in slothweb.db **v7**
(`ble_device`, `ble_alert`, their indexes, an additive migration from
the triage slice's v6 with its two tests on a v6 file holding triage
rows) so a restart keeps the history. The rate
is kept in the module rather than as a per-address series in the
rollup: that class is 512 keys shared with the Wi-Fi tables, and a
resident random-address device is a new key every fifteen minutes.
Two global series do enter the rollup, `ble.devices` and
`ble.adv_rate`, from `sensor_health`, both Monitor's. Since the owner's
Q7 ruling (2026-11-02) one per-address series does too, `rf.rssi.ble`,
for the FRRS Report's signal against time. It sat in the shared device
class first, as the ruling asked ("capped by its existing key limits"),
where a stream of rotating addresses pushed out the quiet keys first,
BLE and Wi-Fi alike; since #177 (2026-11-03) it has a class of its own,
`ble`, at the same `--web-max-keys` N, so an advertiser evicts only
the least recently seen advertiser and a quiet Wi-Fi key's signal
history is never the one that goes; each eviction is counted on
`/api/health` (`key_evictions.ble`). The advertising rate stays in
the module.

The tab (key `0`) is the TUI view at parity: the same columns with the
TUI's own cell strings (`type_ch`, `count_cell`, `age_cell`, the HWS
flags, `summary_cell`, `rf_dist_cell`'s full form), every column
sortable and resizable through the one `DataTable()`, a row one colour
(`--tui-bright` for a HID or watchlisted advertiser, `--tui-normal`
otherwise: no swatch, no hash hue, no RSSI heat, no monitor ground),
the header line, the rotation-hints block (verbatim; the estimate is
not on the stream, only the hint count as a decade band, and the block
says so), the empty state and the legend, all dim as the TUI draws
them; plus the columns the TUI lacks: the address in words (`random
static`, `random RPA`, `random NRPA`, ...), the Bluetooth SIG's names
from its assigned numbers, the best RSSI, the rate, first heard, the
PDUs heard and the watch category, each with a server sort word. A click opens a drawer in the TUI detail's order and
wording, then the PDUs heard, the PHYs and SID, the stamps, a 24 h
presence strip (G5, quarter hours, stored with the row), the rate (a
G1), and the `hid_oui` findings naming the address. The findings
table lists `ble_alert` standing first; the same incidents are on the
Alerts page as `alert.*` records, typed and Monitor's. The Health view
gains a `bluetooth` block, the sensor tile's sub-line the `btmon`
stream, the Overview a `ble advertisers` tile (count, HID / watchlisted
/ standing, a G1 of `ble.devices`), the strip a `ble` pill. Under Local the view is empty and says
why; `/api/ble`, `/api/ble/alerts` and `/api/ble/{addr}` answer
`out_of_scope` there ([[capture-scope]]) and `/api/live`'s `ble` member
is `null`.

**BLE Devices** (owner request 2026-11-02: "show a waterfall similar to
wifi for bluetooth devices"; "visualize in the best way to convey ble in
a similar style"). The tab reads `BLE Devices` and the GNSS tab `GPS
Sat`, ids, views and keys unchanged. Above the table: a header strip
(advertisers in the last 60 s, trackers among them, the nearest, reports
per second) and two panels in the WiFi view's idiom (`web/ui/bledev.js`,
`web/src/web_bledev.c`). Channels would say nothing: an HCI advertising
report carries none, so every host-controller row is channel -1. **Who
is around** (`/api/ble/classes`) is a device class x time grid, each
cell the class's five busiest advertisers by advertising reports as
stacked bands (a named device in its name's hash colour, else its
address's) and grey for the rest, the WiFi channel mix's engine on a
second instance keyed by class slug, its rows in slothweb.db's `chmix`
as kind 3 under `b:` keys (no schema step: v7 still; each view reads its
own namespace), with `ble.class.advertisers` and `ble.class.adv` as the
heat fallback. Seven classes, first match wins: Trackers (a watch
category, Appearance Tag or Keyring, a Tile or CHIPOLO UUID by the SIG
registry), Input (sloth's HID bits), Beacons (Eddystone), Wearables &
audio (Apple Proximity Pairing and Magic Switch, Fast Pair service data,
Samsung's buds and watch packets, worn, audio and health Appearances),
Phones & computers (Apple AirDrop, Handoff, Instant Hotspot, Nearby
Action and Info, MS-CDP, Phone and Computer Appearances), Vehicles &
IoT (HomeKit, fixed, home, vehicle and industrial Appearances), Unknown;
sources in `research/bluetooth/ble-device-classes.md`, iBeacon,
AltBeacon, Find My and SmartTag left out there with the reason, and
Trackers always a row because an empty one is information. **How
close** (`/api/ble/proximity`) is one row per advertiser heard in the
window (12, 24 or 48; trackers first, then signal less
announced power), each
cell its mean `rf.rssi.ble` graded hot-is-near by sloth's own distance
bands for an advertiser announcing no power (-39.75, -53.11, -67.75 and
-81.11 dBm at 1, 3, 10 and 30 m), with what the grade is not and that
rotating addresses are not linked said under it. The drawer gains the
address's signal over the window in the grade's colours, its class and,
for an Ubertooth row, the LL channels it was heard on. Review fixes
(2026-11-02): the BLE `adv_count` high-water marks are a table of their
own, so a flood of random addresses cannot evict the Wi-Fi and flow
counters' marks; every tracker in the window is read before the newest
of the rest; each row is graded at its own announced power (the new
`ble_device` `ext_tx_power`, else TX Power Level, else 0 dBm) and
nearest ranks by signal less it; with no BLE sensor the strip says so
and the panels are hidden, and an Ubertooth alone is said to be
uncredited; the drawer's BLE lines are cleared on each open and redrawn
on a theme change; a name opens the drawer on a click only; phone-width
class labels fall back to glyphs. sloth's side:
`ble_device` is re-sent once a 10 s slot while the advertiser is heard
([[jsonl-schema]]), so both panels have a point a fine bucket rather
than one per 300 s heartbeat. Tests: `web/tests/test_bledev.c` (each
rule, the order, the slugs, the page's copies, the grade against
`src/rf_distance.*`, the class mix fed from records, the gauge, both
routes from memory and the store, the namespaces sharing `chmix`, a v7
file reopening as one; each absence seen red under a named mutation),
`tests/test_ble_rules.c` (the slot over sixty passes).

**Anonymous advertising** (2026-11-03). An LE Extended Advertising
Report with Address_Type 0xFF carries no AdvA; sloth zeroes the address,
so one row per sensor holds every anonymous advertiser that sensor hears
([[ble]]). Until now those rows were in `ble.class.advertisers` and in
neither `ble.class.adv` nor the class mix, so a class row's advertiser
count and its drawn bands disagreed. Now anonymous advertising is
Unknown's, whatever its row's fields would read as, and its three
numbers sit in that one row: its reports are one entry
(`{id: "anonymous", kind: "anon", class: "b:unk"}`; in the mix and
`chmix` kind 4 with the zero address, which no advertiser's entry can
carry, since an address reaches the mix only through `web_key_mac()`,
which refuses all zeros, and the kind is in every key besides), and it
counts as one advertiser there. Not per record, because the row's
fields are no one advertiser's: sloth keeps the first manufacturer pair
the row heard for good, ORs in HID bits and only ever sets a watch
category ([[ble]]: "an anonymous row's AD fields are the least
trustworthy on the table"), so the first anonymous advertiser a sensor
hears would fix the class of every anonymous report after it, and one
keyboard Appearance would move all later ones to Input for good.
`web_ble_class_of_rec()` and `web_ble_dev_class()` both answer Unknown
for `addr_type` 255, so the gauge, the reports and the band cannot
part when the fields change. That includes an anonymous row sloth's watchlist marked
(`watch_category` set): it stays in Unknown, not Trackers, because the
mark may belong to any one of the advertisers sharing the row; the
table and the drawer show the row's watch category as before. The
anonymous advertiser is counted by its own flag, not by its zeroed
address, so a real row whose AdvA is literally all zeros (an Ubertooth
copies AdvA as heard) is a second advertiser, not merged with it. Under
a read cut (256 rows read) the header's `advertisers` is the rows read
plus anonymous advertising, so it can read 257 with `advertisers_more`
set. A named advertiser whose fields change
class still can: its earlier bands stay in the row it left, so in the
bucket where it moves it can be drawn in both rows while the gauge, a
snapshot, counts it in one. The band is `--muted`, the cell's list says
"anonymous" and it opens no drawer. **Where it is not**: the proximity panel. With no address
there is no `rf.rssi.ble` series to key, and the one row per sensor
carries whichever anonymous advertiser was heard last, so a line of it
would be several devices' signals drawn as one. It has no row there and
is never the strip's nearest, and it is skipped before the 256-address
read cap, so a cut still reads 256 advertisers and the note's "of the
256 read" is true; the answer's `anonymous_heard` and the panel's note
say when some was left out, and the class panel counts it.
A b801ab7 slothweb reading a newer slothweb.db skips kind 4 (its reader
keeps kind 3), so on a downgrade those reports are missing from the
minute and hour cells rather than drawn as an address; no schema step.
Tests: `test_anonymous_counts_agree` (built from the one anonymous row
sloth can send: the host stream's, its mfr pair kept, the class change
from an OR-ed HID bit), `test_anonymous_routes` (the page's `isAnon()`
word held to the one the answer serves), the anonymous row under a cut
in `test_proximity_keeps_old_trackers`, and the kind-4 rows in
`test_chmix_ble_kind` and `test_store_shares_chmix`
(`web/tests/test_bledev.c`), each seen red under a named mutation.

**A1 and the 10 s slot: measured, no code change** (2026-11-03). The
slot made `ble_device` about 30 times as frequent, and
`records.rate{ble_device}` (a counter keyed by record type) is A1-scored.
It does not fire on that step on the reference host, and the arithmetic
is in the baseline code itself (`web/src/web_baseline.c`
`feed_cell()`, `web_baseline_score()`, `web_bl_cell_sd()`):

- `records.rate` first shipped in 379ac49 (authored 2026-11-02 14:10
  UTC, 08:10 CST); the host's first slothweb start after that was 08:15
  CST, and the sensor with the slot started at 22:52 CST the same day
  (the journal's unit starts). Under 15 hours of a 168-hour week: no
  hour-of-week cell of the series holds more than one pre-step sample.
- A cell is an EWMA with alpha = 1 - 2^(-1/4) = 0.1591; its first
  sample sets the mean with var 0; it scores z = 0 while n < 3
  (`WEB_BL_WARM_N`); a minute is scored before its hour is fed.
- One pre-step sample m0, then the new rate r m0 each week, d = (r - 1)
  m0: week 1 is scored at n = 1 and week 2 at n = 2, both warming. After
  week 2's feed the cell's residual is (1 - alpha)^2 d and its variance
  alpha (1 - alpha)^2 (2 - alpha) d^2, so week 3's first scored minute
  has z <= (1 - alpha) / sqrt(alpha (2 - alpha)) = 0.841 / 0.541 = 1.55,
  for any r; the within-hour term only adds to the spread, and each
  later week is lower. `WEB_ANOM_Z_THRESHOLD` is 3, for three minutes
  running: a steady minute cannot reach it, and a noisy one would need
  1.66 times the new mean three minutes in a row.
- Measured through `web_baseline.c` itself (a scratch driver, not
  committed) at r = 30: z peaks at 1.48, 1.54, 1.55 and 1.55 for m0 of
  0.5, 4, 40 and 400 records a minute.

What would fire: two pre-step samples cap z at sqrt((1 - alpha) /
alpha) = 2.30, still quiet, but three or more fire A1 on the first
post-step week (measured z 14.5 to 290 over the same m0). So an install
that had learned `records.rate{ble_device}` for three weeks before
taking b801ab7's sensor would see one A1 episode on `ble_device`; none
can exist, because the metric and the slot shipped 14 hours apart. A
later change of a record's feed shape on an install with a learned
series is not handled by any rule today: that is a follow-up (a feed
generation slothweb can read from `sensor_health`, or a rebaseline on a
release boundary), not a gap this step opened.

The SIG's company identifiers, 16-bit service UUIDs and appearance
values are committed as CSVs under `web/data/btsig/` with a
`SOURCE.md` (URLs, the date and SHA-256 of the YAML fetched once during
development, the licence note) and compiled in by
`web/tools/btsig_gen.c`, as the IEEE registry is; `make update-btsig
SRC=DIR` converts the YAML found in a given directory and never
fetches (the ab5fcb2 ruling). Every string off the stream is hostile
and treated as the Wi-Fi tables treat theirs: the local name in its
display form (`web_ssid.h`) with the non-printable marker, the sensor
and PDU words, kinds, families and distance words only from sloth's
closed vocabularies (else `other`, counted), the watch category only
as sloth's slug, the finding's key kept for the resolve join and never
rendered. Full description, the parity table and the v7 schema:
[`web/README.md`](../../web/README.md#ble). Tests:
`web/tests/test_ble.c` (hand-built records, every route under each
scope, the metrics, the store round trip and seed, each absence seen
red under a named mutation), `web/tests/test_btsig.c` (the committed
CSVs to `SOURCE.md`'s hashes, the lookups), the v5 migration pair in
`test_store.c`, the vocabularies held to `src/` as text in
`test_parity.c`.

Where the stream does not carry the TUI's number, the web says what it
shows. The header's `BLE advertisers: N` is sloth's own table
(`sensor_health` `ble_devices`, the TUI's `s->ble_device_count`), with
the rows slothweb keeps beside it (they outlive sloth's evictions and
restarts); the rotation block counts the same live figure. The TUI's
`flood keys` is the flood detector's tracked windows, which no record
carries, so the web shows `standing floods: N`, the `adv_flood`
findings standing, under that name. `ble.devices` is sampled while
either source is configured (an Ubertooth alone counts in sloth's
table), `ble.adv_rate` only with the host stream, whose reports it
counts. A finding seeded after a restart carries every field the live
one rendered (`ble_alert` keeps eight integer columns and a flood's
citation line in `detail`, inside v7, which had not shipped), and a
resolve on its live key resolves the stored row in place. The BLE
tables are inside `--web-max-mb`: the ceiling drops the advertisers no
flag marks right after the channel mix and before any keyed history,
the HID and watchlisted ones and the findings after the keyed history,
so an address flood trims its own rows and not the Wi-Fi and host
series; the row cap is 8,192 (eight times the in-memory table), the
flagged rows last. A failed write leaves its batch dirty for the next
flush. Tests on the store side: `test_ble.c`'s failed-write and
row-cap cases, `test_store.c`'s
`test_ceiling_takes_ble_rows_before_history`.

**Sources**: `src/views/ble.c`, `src/jsonl.c` (the three emitters),
`src/rf_distance.c`, `src/ble_detect.c`, `web/src/web_ble.h`,
`web/src/web_store.c` (v7), `web/data/btsig/SOURCE.md`,
`research/papers/rssi-distance-estimation.md`.
**Last updated**: 2026-11-02.

## Tests

`make web-test` is self-contained: no host file, loopback ephemeral
ports only, no network beyond `127.0.0.1` and `::1`. The acceptance list
of #157 maps to it as follows.

| Acceptance item | Test |
|---|---|
| loopback-default bind | `test_default_bind_is_loopback_8770`, `test_open_binds_loopback_by_default` |
| refused non-listed peer, v4 and v6 | `test_refused_peer_v4`, `test_refused_peer_v6`, plus non-loopback addresses in `test_default_is_loopback_only` |
| refused non-loopback bind without the flag | `test_remote_bind_refused_without_flag`, `test_open_refuses_remote_bind` |
| 405 for POST/PUT/DELETE/PATCH | `test_write_methods_405_over_socket`, `test_every_other_method_is_405` |
| 8 KB header cap answered 431 | `test_header_cap_is_431`, `test_oversize_header_431_over_socket` |
| refused remote bind under `--strict` | `test_strict_refuses_remote_even_with_flag` |
| slow or idle clients time out | `test_idle_client_times_out`, `test_slow_client_times_out` |

#158 (M0) maps as follows.

| Acceptance item | Test |
|---|---|
| served page has no `http(s)://` URL and no external font or script reference | `test_page_makes_no_external_reference`, `test_page_over_socket`, `test_font_is_the_system_monospace_stack`, `test_csp_hashes_match_the_page` |
| embedded page with ETag and `304` | `test_page_is_200_with_etag_and_csp`, `test_page_304_on_matching_validator`, `test_page_over_socket` |
| `/api/health` | `test_health_json`, `test_health_over_socket` |
| SSE tick counter and ping | `test_event_formats`, `test_events_stream_ticks_and_pings` |
| slow-client drop | `test_slow_events_client_dropped` |
| the Spacetrucker chrome tokens (§8.1, amended) | `test_design_tokens_are_spacetrucker` |
| `405` unchanged for writing methods | `test_routes_are_still_405_for_writes`, `test_routes_405_for_writes_over_socket` |
| first tick at once; stream socket options (`TCP_NODELAY`, `SO_SNDBUF`) | `test_events_first_tick_at_once` |
| stream client leaving noticed on the read path | `test_events_client_eof_noticed_on_read` |
| drop at the 64 KB threshold, not past it | `test_slow_events_client_dropped` (`sse_drop_backlog`) |
| foreign `Host` refused (DNS rebinding) | `test_foreign_host_is_421`, `test_foreign_host_refused_over_socket`, `test_host_ok`, `test_host_count_must_be_one` |

#159 (M1) maps as follows. The fake sloth is the test itself, writing
hand-written lines in `src/jsonl.c`'s order and field layout into a
unix socket in a fresh temporary directory, or a loopback TCP port.

| Acceptance item | Test |
|---|---|
| Overview device count matches the TUI within 5 s | `test_device_count_matches_what_sloth_sent` (3, 12, 300, 0 and 7 devices per pass, each read back from `/api/live` over HTTP within 5 s), `test_device_count_is_the_latest_pass` |
| reconnect, with capped back-off | `test_reconnect_after_peer_closes`, `test_backoff_without_a_peer`, `test_backoff_bound`, `test_instant_close_is_backed_off` |
| truncated, overlong, invalid UTF-8 and hostile lines | `test_hostile_stream`, `test_truncated_lines`, `test_invalid_utf8_refused`, `test_duplicate_member_refused`, `test_framer_drops_overlong_lines`, `test_caps` |
| markup in an SSID or hostname renders as text | `test_markup_is_escaped`, `test_hostile_strings_are_escaped`, `test_events_carry_escaped_records`, `test_page_renders_stream_values_as_text` |
| socket state on `/api/health` | `test_reconnect_after_peer_closes`, `test_backoff_without_a_peer`, `test_device_count_matches_what_sloth_sent` |
| a count that may be short is not shown as current | `test_cut_pass_is_not_published`, `test_empty_table_publishes_zero`, `test_reconnect_is_a_new_stream` |
| read-only towards sloth | `test_client_never_writes` |
| `/api/live` fits its buffer at every cap | `test_worst_case_live_fits` |

#160 (M2) maps as follows.

| Acceptance item | Test |
|---|---|
| after 1 h, the 24 h chart shows the last hour at 10 s and the store is under 5 MB | `test_acceptance_one_hour` (an hour of records through the framer on a pinned clock: 42,120 fine rows, 360 points 10 s apart from the 24 h request, from memory, from the store and after a restart; 1.8 MB on disk after the hour's compaction and at most 3.4 MB during the hour, WAL included, checked after every step) |
| metric derivation, deltas floored at zero | `test_gauges`, `test_event_counters`, `test_highwater_deltas`, `test_flow_counters`, `test_channels`, `test_presence`, `test_pass_gauges` |
| three tiers with sum/count/min/max | `test_bucket_boundaries_and_aggregates` |
| keyed metrics bounded, LRU, evictions counted | `test_key_classes_are_bounded_lru`, `test_eviction_churn_on_whole_life`, `test_unestablished_key_held_not_lost`, `test_churn_two_samples_not_in_long_tiers`, `test_churn_three_samples_not_in_long_tiers`, `test_highwater_table_bounded`, `test_highwater_evicted_row_not_recounted`, `test_highwater_gone_filter_rotates`, `test_queue_full_drops_fine_first_and_counts`, `test_recurring_host_under_lru_keeps_long_tiers`, `test_label_keys_established_and_separate`, `test_queue_holds_max_keys_hour_and_shutdown` |
| own file, secure open, migration chain, newer refused | `test_fresh_store`, `test_v0_file_is_migrated`, `test_v0_failed_step_leaves_file_unchanged`, `test_v1_file_is_migrated`, `test_v1_failed_step_leaves_file_unchanged`, `test_newer_file_refused`, `test_foreign_files_refused`, `test_foreign_wal_left_as_it_is`, `test_clean_wal_refused_leaves_dir_unchanged`, `test_file_rules`, `test_defensive_read_back` and `test_file_swapped_between_opens` (through test seams; not the owner rule, which needs privilege to exercise) |
| secret-column guardrail | `test_schema_text_guardrail`, `test_no_column_can_hold_secret_material`, `test_secrets_never_reach_disk` |
| compaction and the ceiling | `test_compaction_retention`, `test_ceiling_drops_oldest_fine_first`, `test_long_stop_expiry_keeps_wal_small`, `test_ceiling_spares_global_series`, `test_ceiling_holds_under_key_churn` |
| strict parameters, bounded answers, behind the W0/M0 checks | `test_parameters_validated`, `test_series_json_and_paging`, `test_routes`, `test_worst_case_fits`, `test_merged_answer_capped` |
| writes off the HTTP thread | `test_store_thread` |

#161 (M3) maps as follows.

| Acceptance item | Test |
|---|---|
| a generated 7 d stream: nothing fires on the quiet one, A3 for a device that appears only at night, A1 for a burst | `test_six_weeks_quiet_then_burst_and_night` (`test_replay.c`: six generated weeks through the framer, decoder, rollup, store thread and engine on pinned clocks; four weeks warm the cells, which a 7 d stream alone cannot, since a cell sees one sample a week; the routine has noisy gauges, Poisson counts and an input for every rule, and slothweb and sloth restart mid-week), `test_a9_fires_for_a_new_host_at_real_cadence`, `test_half_hour_zone_routine_is_quiet` |
| the closed hour fed whatever the flush phase | `test_hour_feed_any_flush_phase` |
| a seeded-state test per rule | `test_anomaly.c`: `test_a1_*`, `test_a2_*`, `test_a3_*`, `test_a5_*`, `test_a6_*`, `test_a7_*`, `test_a8_*`, `test_a9_*`, `test_a10_*`, `test_mad_*` |
| episodes, the listing, the event | `test_episode_closes_after_two_quiet_minutes`, `test_closed_episode_listed_for_its_window`, `test_reopen_needs_a_fresh_streak`, `test_full_table_keeps_open_episodes`, `test_worst_case_listing_fits`, `test_anomalies_route`, `test_anomalies_route_worst_case`, `test_baseline_route`, `test_anomaly_event_and_tick` |
| v3 migration, its failure, persistence | `test_v2_file_is_migrated`, `test_v2_failed_step_leaves_file_unchanged`, `test_analysis_state_round_trip`, `test_state_survives_restart`, `test_baseline_evicted_and_back_in_one_hour`, `test_baseline_refused_batch_is_written_later`, `test_baseline_insert_takes_over_a_stale_row`, `test_baseline_shrinking_restore_keeps_wal_small`, `test_restored_episode_values_are_checked`, `test_a7_history_survives_restart` |
| the page's M3 elements and fetches, and the push | `test_page_carries_the_m3_view`, `test_events_carry_anomalies` |
| bounded identity tables | `test_ident.c` |

#162 (M4) maps as follows.

| Acceptance item | Test |
|---|---|
| `vendor:apple random:yes seen:<24h` returns the right rows against a test-generated database | `test_acceptance_query` (`test_slothdb.c`: exactly D1 and D6 of a sloth.db built from `src/db_schema.c`, each term shown to matter), `test_devices_acceptance` (the same over HTTP) |
| a MAC from a small vendor resolves that sloth's table misses | `test_lookup` (an MA-S MAC through `/api/lookup`, against the test's IEEE-format table and against sloth's own), `test_sloth_fallback`, `test_lookup_by_block` |
| sloth.db opened read-only, the test asserting it | `test_open_flags`, `test_reading_changes_nothing`, `test_live_wal_reader`, `test_wal_without_shm`, `test_refusals`, `test_older_schema` |
| no credential or secret column servable | `test_allow_list_against_the_guardrail`, `test_authorizer_denies`, `test_device_drawer` (no user name in the answer) |
| the query language, bounded, one bound statement, fuzzed | `test_query.c`, `test_query_terms`, `tests/fuzz/fuzz_web_query.c` |
| OUI table generated, never committed, build without it | `test_oui.c`, `test_builtin_table` (the default build `ieee`, an empty `WEB_OUI_DIR` `sloth`); `/build/` keeps the generated table out of git |
| the committed registry (2026-10-26) | `test_committed_registry_matches_source`, `test_committed_registry_builds_in_time`, `test_second_file_after_many_names`, `test_update_oui_is_never_automatic` |
| vendor research under the OUI card (2026-10-27) | `test_vendorkb.c`: every entry complete, cited and named for an exact registry `Organization Name`, its affiliates too; the lookup folding spelling and flagging an affiliate; `"vendor_research"` on the drawer and Lookup, without the entry's country, parent and founded for an affiliate, `{found:false}` without a file; the page drawing it as text; the generator refusing each defect (`test_generator_refuses_each_defect`); `COVERAGE.md`'s Have and Pending lists together the reference host's list, every Have name finding its entry and the count line equal to the lists (`test_coverage_matches_reference_and_entries`) |
| passive names, PTR cache, v4 migration | `test_ptr.c`, `test_v3_file_is_migrated`, `test_v3_failed_step_leaves_file_unchanged`, `test_passive_ptr_rows`, `test_newer_file_refused` |
| A4 and the durable A2 | `test_a4_unknown_vendor`, `test_a4_off_without_the_ieee_table`, `test_a4_burst_is_one_episode`, `test_a2_durable_first_seen`, `test_device_z_now` |
| routes, strict validation, presence, drawer, Lookup, page | `test_devices.c` |

#163 (M5) maps as follows.

| Acceptance item | Test |
|---|---|
| the `sqlite-schema.md` recipes run from the SQL box and match the `sqlite3` output | `test_acceptance` (`test_sqlbox.c`: a sloth.db generated from `src/db_schema.c`, seeded so every recipe has rows; each recipe through `/api/query` over a loopback socket and through the sqlite3 C API on the same file, identical, and through the `sqlite3` shell when on `PATH`; the three recipes reading a withheld column or `dbstat` refused naming it), `test_recipes_are_the_pages` |
| a write statement is refused | `test_writes_refused` (`INSERT`, `UPDATE`, `DELETE`, `DROP`, `ATTACH`, `PRAGMA writable_schema`, a temp table, DML-tail CTEs, two statements; the file byte for byte and its directory unchanged), `test_precheck`, `tests/fuzz/fuzz_web_sqlbox.c` |
| no credential column servable, even in the box | `test_withheld_columns`, `test_writes_refused`'s recipe-shaped queries |
| behind `--web-allow-sql`, default off; `--strict`; the remote warning | `test_off_by_default`, `test_web_allow_sql_flag` |
| 5 s, 10,000 rows, bounded output, one at a time | `test_limits`, `test_one_at_a_time` |
| WiFi: waterfall, AP table, deauth timeline | `test_wifi.c`, `test_parity.c` |
| History: strip, who was here, sessions, new since | `test_history.c` |

#164 (M6) maps as follows.

| Acceptance item | Test |
|---|---|
| a stranger with the README can run it in five minutes | `make web-quickstart-check` (`web/tools/quickstart_check.sh`: the README's quick start, read out of the README and run in a temporary copy of the tree; `/api/health` connected with sloth.db open, `/` the page) |
| every start-up message documented | `test_every_start_message_is_documented` (`test_readme.c`) |
| the security section's points; the screenshots present and small | `test_security_section`, `test_screenshots` |
| Flows: tabs, SMB1, withheld columns, validation, paging, the chord's fold, the matrix form (#171 V4) | `test_flows.c` |
| An alert's proof: pcap reader and decoders on hand-built frames, the name gate, the manifest index, hash verified and mismatched, the routes, the download, the assessment generator's build stops | `test_evidence.c`; `tests/fuzz/fuzz_web_pcap.c` |

The restyle maps as follows.

| Item | Test |
|---|---|
| data coloured as the TUI colours it, byte for byte | `test_tui_colors.c` (`src/tui.c` linked and its output captured) |
| Fira Code named, never fetched; the chrome tokens | `test_font_is_the_system_monospace_stack`, `test_design_tokens_are_spacetrucker` |

A test cannot connect from a non-loopback address, so the socket-level
refusals narrow the list and connect from loopback; the list function
itself is tested on non-loopback sockaddrs. Each absence assertion was
run against a mutant of its guard and seen to fail before it was kept,
except the store's owner rule, held by code reading only.

The suite runs clean under ASan/UBSan and TSan, and `make cppcheck`
covers `web/`.

## Related pages

- [[data-socket-exposure]] — the remote-bind guard this copies.
- [[jsonl-schema]] — the stream M1 consumes.
- [[sqlite-schema]] — sloth's database, which M4 reads read-only and
  M2's store never touches; its migration rule is the one
  `slothweb.db` follows; its query recipes are the SQL box's (M5).
- [[alert-remediation]] — the investigate-and-fix steps an alert's page shows.
- [[alerts]] — the engine and the rules the Alerts page lists.
- [[capture-scope]] — the Monitor / Hybrid / Local switch and how each datum is placed.
- [[ble]] — the Bluetooth host source whose `ble_device` / `ble_alert`
  records and `sensor_health` members the BLE view shows.
- [[cli-reference]] — sloth's own flags; slothweb's are in
  [`web/README.md`](../../web/README.md), the triage slice's
  `--web-read-only` and `--web-assessments` among them
  (`tests/test_docs_consistency.c` holds that page to sloth's own
  `src/main.c`, so slothweb's flags cannot be tabled there).
