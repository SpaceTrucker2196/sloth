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
full IEEE vendor table at build time from CSVs the developer fetches
(never committed; without them, sloth's own table and A4 off), shows
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
`src/probe_pnl.c` (what `mac_random` is), issues #102, #157, #158,
#159, #160, #161, #162, #163 and #164.

**Last updated**: 2026-10-26 (#170: `/api/history/alerts` and the deauth episodes overlap a range from the latest incident's start; the restyle's review: the alert-hot override, every monitor-radio record on the monitor rows, closed anomaly cards at full contrast, the spec's §8.1 amended; 2026-10-23 the Spacetrucker restyle: the owner's design system for the chrome, the TUI's colours for the data, a light theme behind a toggle; before it the same day M6, #164: the Flows view, the polish pass, the README's five minutes, troubleshooting and security, the demo data and screenshots).

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
naming the SHA-256 of the page's one `<script>` and one `<style>`, and
`connect-src 'self'` for the health read and the stream. A browser
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
`--web-max-keys` device MACs (512) and half that many host IPs, least
recently seen out first, evictions counted on `/api/health`;
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
  timeout and a progress budget (250 ms a request) mean a slow read is
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
  first; local and group bits always reported. No CSV: sloth's 117
  entries, said so on `/api/health` and the Lookup card.
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
  above 1 in `--sev-warn`. `/api/wifi/deauth`: frames per bssid with
  DEAUTH_FLOOD episodes matched on the predicate-only alert key. Probe
  clients from `/api/series` over the M3 band.
- **History** (§8.10). `/api/history/overview` (the 30 d strip: devices
  first seen and alerts begun per cell, sessions as markers),
  `/api/history/devices` (who was here: `[first_seen, last_seen]`
  overlapping the range, presence over the range and nothing past it,
  from the hour tier as well for a range older than
  `--web-retain-days`), `/api/history/alerts` (an alert row is a
  finding since sloth's schema v8, #170: it matches a range from its
  latest incident's start, `incident_first_seen`, not from the
  finding's `first_seen`, so a range inside the quiet gap between two
  incidents does not list it)
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
- **The README** (`web/README.md`): prerequisites, build (with the
  optional IEEE CSV fetch), the demo, running beside sloth (the socket
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
| OUI table generated, never committed, build without it | `test_oui.c`, `test_builtin_table`; the `web/data/` and CSV ignore rules |
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
| Flows: tabs, SMB1, withheld columns, validation, paging, the chord's fold | `test_flows.c` |

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
- [[cli-reference]] — sloth's own flags; slothweb's are in
  [`web/README.md`](../../web/README.md).
