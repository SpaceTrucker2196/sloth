# slothweb

The browser dashboard for sloth data, built in milestones. The spec is
[`docs/web-ui-spec.md`](../docs/web-ui-spec.md); the rulings table at its
top overrides the body. Tracker: #102.

**This is the backend half of M3 (#161), on top of M2 (#160), M1
(#159), M0 (#158) and W0 (#157).** W0 is the listener, the
allowed-peer list and its refusals. M0 added the embedded page,
`/api/health` and an `/events` stream. M1 added the data-socket
client: slothweb reads sloth's JSONL stream, keeps a small live state,
serves it as `/api/live`, and the page's Overview shows the device
count, open alerts by severity, records per second, sensor health and
a record ticker. M2 adds the time series: metrics derived from the
same records, rolled into 10 s, 1 min and 1 h buckets, kept in
slothweb's own `slothweb.db`, served as `/api/series`, and drawn by
the Activity view. Run it beside sloth and open `http://127.0.0.1:8770`.

**M3 adds baselines and anomaly rules** (`web_baseline.h`,
`web_anomaly.h`), served as `/api/anomalies`: 168 hour-of-week cells
per (metric, key) with a four-week EWMA half-life (§5.3), and five of
§6's ten rules — A1 (any keyed metric's minute value out of band for
three consecutive minutes, which also covers §6's A7 since
`host.conns` is one of the metrics A1 scans), A3 (a device present in
an hour of the week it is normally absent), A8 (a host's NXDOMAIN
share over its last ten minutes), A9 (a host's first-ever use of
flow.ssh/rdp/smb/snmp/mqtt) and A10 (the data socket connected but
silent). **A2, A4, A5 and A6 are not implemented**: each is a lookup
against `sloth.db` or the vendor/name lookup module, neither of which
exists yet — that is M4 (#162). The Anomalies view and the Overview
heatmaps §6/§8.4 call for are also not built yet; today the rules are
only reachable at `/api/anomalies`. Without SQLite, A10 still runs (it
only needs the live state); A1, A3, A8 and A9 need the minute or hour
tier and do not.

## Build and run

```sh
make web            # builds ./slothweb (with SQLite, as sloth's default)
make web-test       # builds ./slothweb_test and runs it
make web WITH_SQLITE=0       # a slothweb with no store (10 s tier in memory)
make web-test WITH_SQLITE=0  # and its tests
./slothweb          # listens on 127.0.0.1:8770, reads unix:/run/sloth/sloth.sock,
                    # keeps its time series in ./slothweb.db
```

sloth creates its unix socket `0600`, so slothweb runs as the same user
as sloth (or one sloth's socket directory admits); the kernel's
permission check is the only authentication the stream has.

`slothweb` is C99 and links libc and pthreads, and `libsqlite3` when
built with `WITH_SQLITE=1` (the default, the same switch and library
sloth uses); nothing else. It is not part of `make`, `make embedded` or
`sloth`, no `src/` file is compiled into it, and nothing in `src/`
references `web/`.

The page is built, not checked in as one file. `web/tools/embed.c` (C99,
built with the same compiler) reads `web/ui/index.html`, replaces each
`@include NAME` line with `web/ui/NAME`, and writes the result as a byte
array to `build/web/web_assets.c`, together with its ETag and a
Content-Security-Policy holding the SHA-256 of its one `<style>` and one
`<script>` block. That file is generated on every build that needs it
and is never committed; neither is any font. No Python, no Node.

## Command line

| Flag | Effect |
|---|---|
| `--socket SPEC` | sloth's data socket to read. `unix:PATH`, or `tcp:A.B.C.D:PORT` / `tcp:[V6]:PORT` with a literal address; default `unix:/run/sloth/sloth.sock`, sloth's own default since #136. Names are never resolved (`tcp:localhost:8765` is an error). A non-loopback `tcp:` address is announced on stderr; `--strict` refuses it. |
| `--web-bind ADDR:PORT` | Listen address. A literal `A.B.C.D:PORT` or `[V6]:PORT`; default `127.0.0.1:8770`. Names are never resolved, so `localhost:8770` is an error. A non-loopback address is refused unless `--web-allow-remote` is given. `[::]` is IPv6 only (`IPV6_V6ONLY`). |
| `--web-allow CIDR` | Admit peers in `CIDR` as well as loopback. Repeatable, up to 30 entries. Host bits past the prefix must be zero (`10.0.0.1/8` is refused, write `10.0.0.0/8`). A non-loopback entry needs `--web-allow-remote`. |
| `--web-allow-remote` | Authorise a non-loopback bind and non-loopback `--web-allow` entries. Each one is announced on stderr at startup. It authorises the bind, not the peers: with no `--web-allow`, a remote bind still admits loopback only. |
| `--strict` | Refuse any non-loopback bind or allow entry, even with `--web-allow-remote`, and a non-loopback `--socket tcp:` address. Same shape as sloth's `--strict` refusing a routable `--data-socket`. |
| `--store PATH` | slothweb's own SQLite file for the time series (M2); default `./slothweb.db`. Never `sloth.db`: a file that is not a slothweb store is refused untouched (below). Needs a `WITH_SQLITE` build; in one without, the flag is a usage error. |
| `--web-max-keys N` | Device keys tracked by keyed metrics, 16..8192, default 512; host keys get N/2 (256). Least recently seen out first. |
| `--web-max-mb N` | Ceiling on the store's used size, in MB, default 256. Checked after every 10 s write and at each compaction; over it, the oldest 10 s rows go first, then the 1 min and 1 h rows of keyed series, and the global series' rows last. |
| `--web-retain-days N` | Days of 1 min buckets kept, 1..400, default 30. |
| `--help` | Usage. |

Exit status: `0` after `SIGINT`/`SIGTERM`, `1` when the bind fails or
the store is refused, `2` on a usage error or a policy refusal.

## What a peer gets

1. **At accept().** The peer address is checked against the allowed-peer
   list before anything else. The default list is `127.0.0.0/8` and
   `::1`; a v4-mapped peer (`::ffff:a.b.c.d`) is matched as IPv4. A peer
   outside the list is closed without a byte read or written, and
   counted. Loopback is always on the list; `--web-allow` extends it and
   never replaces it.
2. **The header block** must arrive complete, request line through the
   empty line, within 8 KB, or the answer is `431`. A body is never read.
3. **One answer**, then the connection closes (no keep-alive), except
   for an event stream:

   | Request | Answer |
   |---|---|
   | `GET`/`HEAD` with no `Host`, or two | `400` |
   | `GET`/`HEAD` whose `Host` is not `localhost` or an IP literal | `421`, before any route (below) |
   | `GET /` | the page, `200`, `ETag`, `Cache-Control: no-cache` |
   | `GET /` with a matching `If-None-Match` | `304`, no body |
   | `GET /api/health` | `200` JSON, `Cache-Control: no-store` |
   | `GET /api/live` | `200` JSON, `Cache-Control: no-store` |
   | `GET /api/series?...`, `/api/keys?...`, `/api/metrics` | `200` JSON, `Cache-Control: no-store`; `400` with `{"error":"reason"}` for a parameter that does not pass (below); `503` with no time series attached |
   | `GET /api/anomalies` | `200` JSON, `Cache-Control: no-store`, open and recently-closed episodes; no query parameters yet, any query is `400` |
   | `GET /events` | `200` `text/event-stream`, held open (below) |
   | `GET /events` with 24 streams already open | `503` |
   | `GET` any other path | `404` |
   | `HEAD` of any of these | the same status and headers, no body |
   | any other method (`POST`, `PUT`, `DELETE`, `PATCH`, ...), any path | `405`, `Allow: GET, HEAD` |
   | header block over 8 KB | `431` |
   | malformed request line or header | `400` |
   | HTTP major version other than 1 | `505` |
   | no complete header block within 10 s of accept() | `408`, best effort |

   Methods are case-sensitive (RFC 9110 §9.1): `get` is `405`.

   **Host.** The allow list judges the TCP peer, and the operator's
   browser is a loopback peer whatever page it shows. A site that
   points its own name at `127.0.0.1` (DNS rebinding) is same-origin
   with slothweb in that browser, so its script could read
   `/api/health` and `/events`; sending no CORS headers does not stop
   that. Its requests carry its name in `Host`, so a routed request is
   answered only when `Host` (or an absolute-form target's authority)
   is `localhost`, a literal IPv4 address or a bracketed IPv6 literal,
   each with an optional `:port`. An IP literal cannot be rebound, so
   any literal is accepted, which keeps `ssh -L` forwards and a
   `0.0.0.0` bind reached by the host's address working; no name is
   resolved to decide. A remote bind reached by DNS name is refused:
   use the address. Writing methods are `405` before this check.
4. **Timeouts are absolute from accept()**, not reset per byte: a client
   trickling one byte at a time is cut off on the same schedule as one
   that sends nothing. The response has its own 10 s budget. After it, a
   client may keep sending (a body nobody reads) for 1 s before the
   socket closes. The half-close and drain make those unread bytes end the
   connection with a FIN instead of a reset; this is defensive (some
   stacks discard an unread response on reset) and the loopback tests
   check the FIN, not a rescued response, because Linux delivers the
   queued response either way.
5. At most 32 connections are held. A 33rd admitted peer is closed and
   counted as busy. If `accept()` runs out of descriptors or memory, the
   listener is left unpolled for 100 ms rather than spinning.

On shutdown slothweb prints the counters to stderr: admitted, refused at
accept, busy, served, timed out, accept back-offs.

## Routes

Paths match exactly, and an absolute-form target (`GET
http://127.0.0.1:8770/ HTTP/1.1`) routes by its path. The query string
is ignored except by the three M2 routes, which validate it whole.

**`/`** is the one page: `web/ui/index.html` with `theme.css`,
`page.css` and `app.js` inline. The `ETag` is the first 128 bits of the
page's SHA-256, so it changes exactly when the page does; the browser
revalidates on every load and gets `304` until a rebuild. The page's
policy is

```
default-src 'none'; script-src 'sha256-…'; style-src 'sha256-…';
connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
```

so the browser itself refuses any request the page did not hash, other
than same-origin `fetch` and `EventSource`. The fonts are the system
monospace stack (`ui-monospace, "SF Mono", Menlo, Consolas, "DejaVu Sans
Mono", "Liberation Mono", monospace`); no font file exists. Colours are
the `docs/web-ui-spec.md` §8.1 tokens in `web/ui/theme.css`.

**`/api/health`** answers

```json
{"service":"slothweb","milestone":"M2","uptime_s":12,
 "socket":"connected","socket_spec":"unix:/run/sloth/sloth.sock",
 "last_record_age_s":0,"socket_attempts":1,"socket_connects":1,
 "socket_reconnects":0,"socket_failures":0,"socket_closes":0,
 "socket_retry_ms":0,"socket_last_error":null,"socket_last_error_age_s":null,
 "socket_bytes":48113,"socket_lines":92,"socket_records":92,
 "socket_decode_errors":0,
 "socket_decode_by":{"syntax":0,"utf8":0,"depth":0,"fields":0,
   "not_object":0,"duplicate_key":0,"no_type":0,"overlong":0,"truncated":0},
 "socket_gaps":0,"socket_gap_dropped":0,
 "db":"none","db_schema":null,"db_rows":null,
 "store":"open","store_path":"./slothweb.db","store_schema":2,
 "store_rows":{"fine":42120,"minute":7020,"hour":117},
 "store_bytes":1765376,"store_max_bytes":268435456,"store_batches":360,
 "store_write_errors":0,"store_last_error":null,"store_compactions":2,
 "store_dropped_expired":0,"store_dropped_ceiling":0,"store_ceiling_runs":0,
 "retain_days":30,
 "series_keys":{"global":1,"device":30,"host":20,"iface":2,"channel":3,"alert":0},
 "series_key_caps":{"global":1,"device":512,"host":256,"iface":32,"channel":64,"alert":128},
 "key_evictions":{"global":0,"device":0,"host":0,"iface":0,"channel":0,"alert":0},
 "key_returns":{"global":0,"device":0,"host":0,"iface":0,"channel":0,"alert":0},
 "series":117,"samples":221385,"ring_rows":42120,"queue_rows":0,
 "queue_cap":32768,"queue_dropped":0,"churn_dropped":0,"highwater_evictions":0,
 "values_clamped":0,
 "sse_clients":1,"tick_seq":12}
```

`socket` is `connecting`, `connected` or `retrying` (waiting out a
back-off of `socket_retry_ms`). `socket_last_error` is slothweb's own
text (`connect: No such file or directory`, `peer closed the stream`),
never anything the peer sent. `socket_gaps` counts sloth's `socket_gap`
markers and `socket_gap_dropped` the records they say were dropped
(jsonl-schema, #93). The `db` fields are `sloth.db`'s and stay
`"none"`/`null` until M4. The `store` fields are M2's (below): `store` is
`open`, or `memory` in a build without SQLite (`store_path`,
`store_schema` and `store_rows` are then `null`); `store_rows` is the
rows stored, kept by the writer (a bucket merged into one already on
disk is not counted again) and recounted at each compaction;
`key_evictions` counts keys pushed out of each class by its cap,
`key_returns` evicted device and host keys that came back and were given
their earlier life (below), `queue_cap` the store queue's size and
`queue_dropped` the closed buckets it had no room for, and
`highwater_evictions` rows pushed out of the running-total table.

**`/api/live`** is the live state:

```json
{"socket":"connected","devices":42,"devices_stale":false,"devices_ts":1792629211,
 "device_passes":118,"device_passes_unpublished":0,
 "alerts_open":{"low":0,"warn":1,"crit":0,"overflow":false},
 "records":9120,"records_s":61.4,"last_record_age_s":0,
 "types":{"iface":236,"device":4956,"dns":310,"...":0},
 "types_other":0,"types_invalid":0,
 "sensor":{"state":"ok","age_s":40,"ts":1792629171,"capture_iface":"any",
   "capture_open":1,"capture_running":1,"capture_exit":"none",
   "monitor_iface":"","monitor_open":0,"monitor_running":0,"monitor_exit":"",
   "scope":"none","scope_not_enforced":0},
 "alerts":[{"ts":1792629100,"type":"alert.create","sev":1,"title":"…",
   "detail":"…","incident_id":"9f2c41ab77e30d58"}],
 "recent":[{"seq":9071,"type":"dns","ts":1792629210,"text":"example.com  10.0.0.5"}]}
```

| Member | Meaning |
|---|---|
| `devices` | the number of `device` records in sloth's latest snapshot pass: the TUI's device count (below). `null` until a pass has been seen. `devices_stale` is `true` while the socket is down and until the current connection delivers a pass |
| `alerts_open` | incidents open now, by severity (0 LOW, 1 WARN, 2 CRIT), from the `alert.create` / `.update` / `.escalate` / `.resolve` records. Starts empty on each connection (below). `overflow` once more than 256 are open |
| `records`, `records_s` | records decoded since start, and the mean over the five whole seconds before now |
| `types` | records by `type`, for up to 48 names; the rest are `types_other`. A `type` that is not 1..32 bytes of `[a-z0-9_.]` is `types_invalid` and is not shown |
| `sensor` | the latest `sensor_health` record and `state`: `unknown` (none yet), `ok`, `degraded` (a capture or monitor handle open with its thread not running, or the launch scope not enforced), `not_observing` (neither handle open), or `stale` (none for 330 s; it is change-only with a 300 s heartbeat) |
| `alerts` | the last 8 alert lifecycle records, newest first |
| `recent` | the last 50 records of any type, oldest first, each as its `type`, `ts` and a short `text` built from the members a reader looks for first (`qname`, `host`, `ssid`, `mac`, `ip`, `src`, ...), at most 80 bytes |

**`/events`** is a Server-Sent Events stream. It starts with
`retry: 3000` and the current tick, then:

| Event | Cadence | Payload |
|---|---|---|
| `tick` (with `id:`) | 1 s | `{"seq":N,"ts":UNIX,"uptime_s":U,"sse_clients":K,"socket":"connected","devices":42,"devices_stale":false,"alerts_open":[low,warn,crit],"records_s":61.4,"records":9120,"sensor":"ok"}` |
| `record` | with each tick | `{"seq":N,"type":"dns","ts":UNIX,"text":"..."}`, the records added since the previous tick, the newest 20 at most (spec §7.1: coalesced to 20 a second); a gap in `seq` says some were skipped |
| `: ping` comment | 15 s | none; keeps proxies and idle timers from closing it |

`seq` counts up by one per second from start-up; a late wake-up sends
one tick, not a burst. Anything the client sends on the stream is read
and discarded, which is also how its departure is noticed. A client
that stops reading is dropped once 64 KB is waiting for it (its socket
send buffer is capped at 16 KB as well), and its browser reconnects on
its own after the `retry` delay. Every accepted socket has
`TCP_NODELAY` (spec §10.2): events are small and should not wait for
the previous one's ACK. At most 24 streams are held, so 8 of
the 32 connection slots stay free for the page and the API.

## The data socket (M1)

One thread (`web/src/web_ingest.c`) connects to `--socket`, reads, and
hands each line to the decoder. It never writes a byte to the socket
(the stream is one-way; sloth never reads from a client) and never
resolves a name. When the connection fails or the peer closes it, the
thread waits and tries again: 250 ms, doubling, capped at 4 s, so a
restarted sloth is back on the page within the spec's 5 s. A
connection that delivered at least one whole line resets the wait; one
that is accepted and closed at once (sloth refusing a client over its
per-peer cap does that) does not, so it is never redialled in a tight
loop. A TCP connect gives up after 3 s.

**Every byte from the socket is untrusted.** Lines are framed on `\n`
and capped at 16 KB (sloth's own line buffer is 8 KB); a longer line is
discarded through its newline and counted once, however the reads split
it. Each line is decoded by a strict reader written for this
(`web/src/web_jsonl.c`), not by `research/mcp/json.c`, which decodes
`\u` only to Latin-1 and does not check raw UTF-8. A line is refused
whole, and counted by reason, unless it is one JSON object (RFC 8259)
with nothing after it, at most 384 top-level members and 8 levels deep,
every string well-formed UTF-8 (RFC 3629) both raw and after `\u`
decoding (no lone surrogate, no overlong form, no raw control byte, no
`\u0000`), no member name twice (which `type` would win is what a
hostile line would like to choose), and a string `type`. A line the
connection ended in the middle of is counted as `truncated`.

Strings are kept cut to a fixed size on a code-point boundary and leave
slothweb only through one JSON writer (`web/src/web_json.c`), which
escapes per RFC 8259 and also writes `<`, `>`, `&`, `'`, DEL, C1 and
U+2028/U+2029 as `\uXXXX`. So a hostname or SSID holding markup is never
markup in any byte slothweb sends, and the page shows every stream value
with `textContent` only: the script contains no `innerHTML` or other
HTML or code sink, and a record type picks its colour from a fixed
table rather than becoming a class name.

**The device count.** sloth's poll thread rebuilds `s->devices` every
poll and writes one `device` record per row (`jsonl_emit_devices()`),
so the number of `device` records in one pass is exactly the TUI's
`device_count`. slothweb counts rows, not distinct MACs, for the same
reason. The pass is not one unbroken run on the wire: the capture
thread writes `dns`, `tls`, `quic`, `http`, `ntp`, `icmp` and
`cleartext_cred` records through the same writer at the same time, and
no lock spans the pass, so a DNS answer can land between two device
rows. Only the poll thread's own record types (`POLL_TYPES` in
`web/src/web_live.c`) steer the count; every other type, alerts and
types sloth adds later included, is passed over. A pass ends at the
first poll-thread record of another type and is then published. A pass that a `socket_gap`, an undecodable line or an
implausible `type` may have cut short is not published, and the
previous count stands (`device_passes_unpublished`). sloth's snapshot
batch starts with the `iface` records, so a batch that reaches the next
batch's start with no `device` record at all publishes `0`, unless
something was lost in it. A new connection is a new stream: a pass begun
on the old one is never finished by the new one.

**Open alerts** are counted from the lifecycle records since this
connection. sloth replays nothing on connect, so an incident opened
earlier is counted once it is updated or escalated, and a resolve missed
while disconnected cannot leave one open forever: the set starts empty
on every connection. An under-count heals itself; an over-count would
not.

## The time series (M2)

### Metrics

The ingest thread hands each decoded record to `web/src/web_metrics.c`
after the live state, which turns it into samples. The set is
docs/web-ui-spec.md §5.1, and every one of its metrics has a source
`src/jsonl.c` writes today, so none is left out:

| Metric | Kind | Key | From |
|---|---|---|---|
| `iface.rx_rate`, `iface.tx_rate` | gauge | interface | `iface` `rx_rate`, `tx_rate` |
| `host.rx_rate`, `host.tx_rate`, `host.conns` | gauge | IP | `top_host` `rx_rate`, `tx_rate`, `conn_count` |
| `dev.frames` | counter | MAC | `frame_count` deltas of `probe_client` (`mac`) and `assoc` (`sta_mac`). Not `seqnum_client`: sloth counts the same probe requests in both tables (`src/capture/probe.c` feeds each to `seqnum_track_observe()` and then `record_probe()`), so the two summed would count every probe twice. The probes it leaves out are those whose body was cut short of its information elements |
| `dev.present` | presence | MAC | any record with `mac` or `sta_mac` whose `last_seen`, if it has one, is within 10 s of its `ts` |
| `dns.queries` | counter | IP | `dns` with `is_resp` 0, by `src` |
| `dns.nxdomain` | counter | IP | `dns` with `answer` `NXDOMAIN`, by `src`, which on a response is the resolver: sloth's record names no client for an answer |
| `tls.handshakes` | counter | IP | `tls`, by `src` |
| `http.requests` | counter | IP | `http` without `status` (a response has one), by `src` |
| `alerts.fired` | counter | alert type | `alert` (one per new alert key), by `ty`; the lifecycle records are not counted again |
| `wifi.ap_count` | gauge | channel | `channel_summary` `ap_count` |
| `wifi.ctrl_total` | counter | channel | `channel_summary` `ctrl_total` deltas: sloth's figure is a running total, so this is a counter, not the spec's gauge |
| `wifi.deauth` | counter | MAC (BSSID) | `deauth` `count` deltas per (src, dst, bssid, subtype), by `bssid` |
| `wifi.probe_clients` | gauge | none | `probe_client` rows per snapshot pass |
| `conns.total` | gauge | none | `connections` rows per snapshot pass |
| `flow.ssh`, `flow.rdp`, `flow.smb`, `flow.snmp`, `flow.mqtt` | counter | IP | deltas of `ssh_flow` `banner_count`, `rdp_flow` `connect_req_count`, `smb_session` `count` (by `client_ip`), `snmp_flow` get+getnext+getbulk+set+response+trap, `mqtt_flow` connect+subscribe+publish, per flow, by source |

A key is a canonical form checked by type: a MAC is lower-case
`xx:xx:xx:xx:xx:xx` (all zeros, sloth's "no MAC", is not one), an IP is
what `inet_ntop()` writes back for what `inet_pton()` accepted, an
interface name is 1..15 bytes of `[A-Za-z0-9_.:@-]`, a channel is
1..233 with `6g` in front on 6 GHz (5 and 6 GHz share numbers), an alert
type is `ty` 0..9999. A record whose key does not pass is not counted,
so no string a peer wrote is ever a key as it was sent. Gauges take
sloth's `%.2f` reals.

**Running totals.** `frame_count`, `count` and the flow counts are
high-water marks. Each is turned into a delta against the last value
seen for the same row, floored at zero, so a row sloth evicted and made
again does not read as a negative burst. On a new connection sloth
re-sends every row at its full total, so the first sight of a row is a
baseline (no delta) unless the row's own `first_seen` is no earlier than
the connection's first record, i.e. it was born while slothweb was
listening; rows with no `first_seen` (`channel_summary`) are always a
baseline on first sight. Every connection starts a new
table. The table holds 4,096 rows, least recently used out first,
counted as `highwater_evictions`. An evicted row's id goes into a small
two-hash filter, so a row born while listening, evicted and then seen
again on the same connection is a baseline the second time rather than
counting its whole total twice; a filter collision can only turn a born
row into a baseline. The filter is two generations of 4,096 ids, 8 KB
each, cleared with the table: when the newer fills, the older is
cleared and takes the next ids, so a long connection never saturates
it. That bounds both sides. A lookup is wrongly positive at most about
2.7% of the time (a born row's first total taken as a baseline), and an
evicted id is remembered across at least 4,096 later evictions and
fewer than 8,192; a row evicted and seen again only after more than that
counts its total a second time.

**Rows per pass** (`conns.total`, `wifi.probe_clients`) use the same
batch start as the device count: the first `iface` record after another
poll-thread record. `connections` is written just before its tick's
`iface` records, so the window that closes at a batch start holds that
tick's connections and the previous tick's probe clients. The partial
window a connection opens in is not sampled, nor is one that a
`socket_gap` or an undecodable line may have cut.

Bucketing uses slothweb's clock, never a record's `ts`: a hostile `ts`
could otherwise write anywhere in history.

### Tiers

| Tier | Bucket | Kept | `tier=` |
|---|---|---|---|
| fine | 10 s | 24 h | `fine` |
| minute | 1 min | `--web-retain-days` (30 d) | `minute` |
| hour | 1 h | 400 d | `hour` |

Every series keeps one open bucket per tier with sum, count, min and
max. A bucket closes when a sample lands in a later one, or when the
store thread finds its interval over, whichever is first. A gauge's
value is sum/count, a counter's sum, presence's max. Keys are bounded
per class: device MACs (`--web-max-keys`, 512), host IPs (half, 256),
interfaces (32, sloth's `MAX_IFACES`), channels (64, sloth's
`MAX_CHAN_ENTRIES`) and alert types (128: sloth has 90 kinds); a new key
in a full class evicts the one seen least recently, after writing out
its open buckets, and is counted in `key_evictions`. The one global key
is never evicted.

Interfaces, channels and alert types come from catalogues sloth itself
bounds, which no peer can churn, so their keys are *established*, as
the global key is, from their first sample: an alert type that fires
twice in a few seconds gets its minute row when the minute ends and its
hour row when the hour does, and an evicted channel's rows are written,
not dropped. Each has its own class, so a busy channel list cannot
evict a quiet alert type.

Device and host keys are whatever a frame or a packet claims, and what
an eviction writes for them is decided on the key's whole life, not on
how many samples it took. One is established once its samples span a
minute (the last 60 s or more after the first). Until then its 10 s
buckets are written as usual, but its 1 min and 1 h buckets are held in
memory (at most two per tier, since samples within a minute cross at
most one boundary of each). When it becomes established they are
written. When it is evicted first they are dropped, counted as
`churn_dropped`, whether it took one sample or a hundred. A key neither
established nor evicted has them written at shutdown, so until then its
minute and hour rows are not in the store. The life outlasts a stay in
the class: an evicted key's first sighting, and whether it was
established, are kept in a small table (four entries per key slot) and
given back when it returns (`key_returns`). So a real host that recurs
under LRU pressure, evicted between each two of its samples, is
established a minute after it was first seen and from then on writes
its minute and hour buckets, partial at each eviction and merged by the
store; it loses only its first minute's. The table prefers established
keys: an unestablished one never displaces an established one, so a
scan can only push out the entries of keys still in their first minute.
What holds, then: a scan or a spoofed-source flood whose keys are each
seen for under a minute writes 10 s rows only, which the ceiling drops
first and which expire in 24 h; at shutdown at most the keys then
resident (one class cap) write what they held. Keys seen across a
minute or more do reach the 30-day and 400-day tiers, one row per
metric per bucket each, under churn too: that is bounded by the
ceiling, not by this rule. A key evicted and seen
again is a new series in memory: `/api/series` finds its earlier rows in
the store, and without one they are gone from the answer.

Closed buckets wait for the store thread in a queue sized from the
class caps: six rows for every series the classes can hold, and at
least 32,768 (about 3 MB at the default `--web-max-keys`, 41 MB at
8,192; allocated zeroed, so only what is used is resident). Six covers
what one series can close between two writes: two 10 s rows, a minute
and an hour row, and the two held rows of a key becoming established.
So the hour boundary, which closes a 10 s, a minute and an hour bucket
of every series in one pass, and the shutdown, which writes what is
queued and then closes everything still open, fit at 8,192 keys. The
store thread also writes early once 16,384 rows are queued. Only
eviction churn can outrun the queue; then a 10 s row is dropped before
a minute or hour row (one arriving at a full queue takes the newest
queued 10 s row's place), and every drop is `queue_dropped`.

Closed 10 s buckets also go to a ring of 131,072 rows in memory (about
5 MB); `/api/series` reads it for what the store has not written yet,
and in a build without SQLite it is all there is.

### slothweb.db

`--store` (default `./slothweb.db`) is slothweb's file and holds nothing
but closed buckets: `series(id, metric, key)` and one table per tier,
`(series, t, sum, n, min, max)`. It is never `sloth.db`.

- **Opening** follows sloth's rules for its own database (`src/db.c`,
  `src/secure_file.c`, re-implemented because no `src/` file is linked):
  the path is opened by descriptor with `O_NOFOLLOW` and created `0600`;
  an existing file must be a regular file owned by the effective uid
  with no group or other bits and one link, and the `-wal`, `-shm` and
  `-journal` files, when present, the same; anything else is refused,
  never repaired. SQLite then opens it with `SQLITE_OPEN_NOFOLLOW` and
  `SQLITE_DBCONFIG_DEFENSIVE`, and needs 3.31.0 or later.
- **Identification** happens before anything is written, on a
  read-only connection: the last read-write connection to close on a
  WAL database checkpoints the WAL into it and deletes the WAL, so
  identifying a WAL-mode sloth.db on one would rewrite the file it
  refused. A read-only connection does make an absent `-wal` (empty)
  and `-shm` (32 KB), so a WAL-mode file with no `-wal` (cleanly
  closed: all it holds is in the main file) is read as an immutable
  URI instead, which opens no side file; a refused, cleanly closed
  sloth.db leaves its directory exactly as it was. They are not made
  and deleted, because deleting would race sloth opening its own file.
  A `-wal` with no `-shm` beside it still gets one made. Only once the
  file is ours or empty is it opened read-write (and identified again
  there, so a file swapped between the two opens is refused). An empty
  file is new: no schema object, and `application_id` and
  `user_version` both 0, so a file another program has set up but given
  no table yet is not taken for one. A new store is stamped with
  slothweb's own `application_id` (`0x534c5745`, "SLWE"), and a file
  carrying any other non-zero one is refused. A file whose `meta` table
  says `store = slothweb` is ours, at its `schema_version`. Anything
  else (sloth.db, whose `meta` is differently shaped, any other
  database, a file that is not SQLite) is refused and left byte for
  byte as it was. So is a store whose version is newer than this
  build's.
- **Migration** follows the 2026-10-21 owner rule: a chain of steps from
  v0, each additive, each in one `BEGIN IMMEDIATE` transaction with its
  own version stamp, so a failed step leaves the file at the version it
  last reached, with the step's own changes rolled back. A new file is
  stamped v0 first and takes the same chain, so the chain runs on every
  first start. Today the chain is two steps: v0 to v1 creates the four
  tables, v1 to v2 indexes each tier on `t` (plain `CREATE TABLE` and
  `CREATE INDEX`: a name already taken fails the step rather than being
  adopted).
- **No column can hold a credential**: `web/tests/test_store.c` keeps
  sloth's `test_db.c` guardrail (no column named for a password, a
  community, a nonce, a key or a token may be TEXT or BLOB), and scans
  the file for an SNMP community, an MQTT user name and a cleartext
  credential fed through the stream. Keys are canonical addresses and
  names only.
- **Writes** come only from the store thread (`web/src/web_tsdb.c`),
  never the HTTP thread: once a second it closes due buckets, every
  10 s (or as soon as 16,384 are queued) it writes the closed ones, up
  to 4,096 to a transaction. A bucket already on
  disk (one an eviction or a restart closed early) is merged: sums and
  counts added, min and max widened, and not counted again in
  `store_rows`. On shutdown what is queued is written, then every open
  bucket is closed and written, so a restart picks up where it stopped. One
  bucket is briefly short after a restart: the one the restart split.
  Until this run's part of it is written (within two flush intervals),
  `/api/series` has the last run's part in the store and this run's in
  memory, and shows the fuller of the two rather than their sum.
- **The ceiling** (`--web-max-mb`) is checked after every 10 s write,
  not only at compaction, so it bounds the file within one flush
  interval: key churn can otherwise write millions of rows in an hour.
  The check is three PRAGMAs (4 µs). Over it, slices go until it is
  under, each its own transaction: the oldest 2,048 fine rows (any
  series) until none is left, then the oldest 2,048 keyed minute rows,
  then keyed hour rows, and only then the same for the global series,
  which are one per metric whatever the traffic; series rows left with
  no bucket are swept once after the slices, and free pages are
  returned, 256 at a time. Passes that dropped rows are
  `store_ceiling_runs`, rows `store_dropped_ceiling`. Every slice reads
  the head of the v2 index on `t`; without it each was a full scan of
  the tier. Measured on a store filled to the ceiling (2,048 host keys,
  then flushes of 2,000 new fine rows each followed by the ceiling, as
  the store thread does): at 256 MB a trim took 4,767 ms before the
  index, 215 ms with it and 5-minute slices, and a median 74 ms with
  2,048-row slices; at 64 MB a median 209 ms with 5-minute slices and
  59 ms with 2,048-row ones. The index costs space: the ceiling holds
  about 36% fewer fine rows (6.1 M rather than 9.6 M at 256 MB).
- **Compaction** runs at start and then once an hour, after the write:
  rows past each tier's retention go, a tile at a time (256 series of
  consecutive id by 256 buckets of `t`, one transaction each); then the
  ceiling as above; then free pages are returned
  (`auto_vacuum=INCREMENTAL`, 256 pages to a transaction) and the WAL is
  truncated. A tier is keyed `(series, t)` and indexed on `t`, so a
  delete in `t` order scatters over the key's pages and one in series
  order over the index's; a tile is a run of both, about 2,000 pages
  whatever the size of the store.
- **The WAL** is not counted in `--web-max-mb`, which bounds the main
  file; what bounds the WAL is that no transaction is large. It is
  checkpointed once it passes 1 MB (`wal_autocheckpoint`) and cut back
  to 1 MB at the next write after a checkpoint (`journal_size_limit`),
  so between transactions it holds at most about 1 MB, and during one
  it grows by the pages that transaction changes: at most a leaf of the
  key and one of the index per row. The largest transactions are a write
  of 4,096 queued rows and a ceiling slice of 2,048, so at 4 KB pages
  the worst case is about 32 MB above the file, whatever the ceiling;
  an expiry tile changes about 8 MB at most. Before, the start-up
  compaction deleted everything expired in one transaction, and after a
  long stop the WAL grew to the size of the file. Measured on a store
  of 1.5 M fine rows (44 to 49 MB) expired at once, for 100, 1,000,
  5,000 and 20,000 series: the WAL peaked at 45 to 49 MB in one
  transaction and at 2.0 to 7.1 MB by tiles, and the compaction took 1.7
  to 4.8 s before and 1.7 to 2.4 s after. On the ceiling measurement
  above (256 MB) the WAL's largest was 11.0 MB, from the 2,000-row
  writes, not the trims.
- **Reads** come from the HTTP thread over a second, read-only
  connection (WAL lets it read beside the writer), with every value
  bound as a parameter; a table name is chosen from three constant
  statements, never from the request.

An hour of a small home network's records (2 interfaces, 20 hosts, 30
devices, 10 probe clients, 3 channels, 15 connections, a DNS query
every 2 s; 117 series) is 42,120 fine rows: 1.8 MB on disk, the file
and its truncated WAL, after the hour's compaction (1.1 MB before the
v2 index), and at most 3.4 MB during the hour, the WAL between
checkpoints included.

**Without SQLite** (`make web WITH_SQLITE=0`), there is no store:
`--store` is a usage error, the minute and hour tiers are not kept, and
`/api/series` serves the fine tier from the in-memory ring only, which
covers about 131,072 / (number of series) buckets of 10 s: about 3 h at
117 series, about 7 minutes at 3,000. The ring is shared: the closed
rows of keys since evicted stay in it until they are written over, so
under key churn the live series get less than that. `/api/metrics` says `"store":false`
and marks the two tiers unavailable; asking for one is a `400`
`tier_unavailable`. `/api/health` says `"store":"memory"`.

### /api/series, /api/keys, /api/metrics

```
GET /api/series?metric=iface.rx_rate&key=eth0&tier=fine&from=1792540800&to=1792627200
{"metric":"iface.rx_rate","key":"eth0","tier":"fine","step":10,"kind":"gauge",
 "unit":"B/s","from":1792540800,"to":1792627200,"source":"store+memory",
 "more":false,"next_to":null,
 "points":[[1792623600,1002.5,1000.5,1004.5,5],...]}
```

`points` are `[t, value, min, max, n]`, oldest first, for buckets with
`from <= t < to`; `value` is the mean for a gauge, the sum for a
counter, the max for presence. Buckets with no sample are absent. At
most 900 come back, the newest; `"more":true` and `next_to` say to ask
again with `to=next_to` for the older ones (the page does, up to twelve
times). The bucket still filling is included. `source` is
`store+memory`, `store` (minute and hour) or `memory`.

The parameters are validated before anything reads a series, and every
refusal is a `400` with a reason word of slothweb's own, never the
value back:

| Rule | Reason |
|---|---|
| the query is `name=value` pairs joined by `&`, nothing else | `bad_query` |
| a name is one of `metric`, `key`, `tier`, `from`, `to` (`/api/keys`: `metric`; `/api/metrics`: none) | `unknown_parameter` |
| each at most once | `repeated_parameter` |
| a value is percent-decoded (RFC 3986 §2.1), then 1..63 bytes of printable ASCII | `bad_escape`, `bad_value`, `empty_value`, `value_too_long` |
| the whole query is under 512 bytes | `query_too_long` |
| `metric` is one of the table above | `missing_metric`, `unknown_metric` |
| `key` passes the metric's canonicaliser; a global metric takes none | `bad_key` |
| `tier` is `fine` (default), `minute` or `hour`, the last two only with a store | `unknown_tier`, `tier_unavailable` |
| `from` and `to` are 1..11 decimal digits; `to` defaults to the end of the current bucket, `from` to 1 h, 1 d or 30 d before it | `bad_from`, `bad_to` |
| `from < to`, `to` at most a day ahead, the span no longer than the tier keeps plus one bucket | `empty_range`, `to_in_future`, `range_too_long` |

A point is at most 69 bytes, so 900 fit the 64 KB answer buffer with its
header; `test_series.c` builds that worst case. `/api/keys?metric=M`
lists the keys holding a series of `M`, most recently seen first (256 at
most, with `total`). `/api/metrics` lists the metric table, each with
its key count, and the tiers with their steps, retention and whether
this build serves them.

### The Activity view

`2` (or the sidebar) opens it; `1` goes back to the Overview. It picks a
metric (from `/api/metrics`), a key (from `/api/keys`) and a window
(1 h, 6 h and 24 h from the 10 s tier; 7 d and 30 d from 1 min; 400 d
from 1 h), and draws the series on Canvas 2D: the bucket value as a
line over its min..max band. That band is the spread inside each bucket;
the spec's baseline band (`mean ± 2 sd`), the z-score in the hover, the
`abs(z)` ordering and the ratio-to-baseline toggle need M3's baselines
and are not here. Below it, a small multiple per key (the 24 most
recently seen), each the last hour at 10 s, sorted by current value so
the loudest is top left, with the key in the TUI's colour for it: the
eight hues of `src/tui_palette.c` picked by `src/ip_color.c`'s hash
(djb2; the spec says FNV-1a, but the TUI's own hash is the one that
keeps the colours equal). Colours come from `theme.css` tokens read back
at run time. Keys are shown with `textContent` and `fillText` only and
leave the page only as an `encodeURIComponent()`'d parameter of a
same-origin `fetch`.

## What it never does

- No method that writes, ever (`405` is permanent, not a W0 placeholder).
- No name resolution of any kind, including its own bind address.
- No write to `sloth.db`, and no open of it: `--store` pointed at it is
  refused untouched.
- No write to the data socket, ever: slothweb only reads it.
- No request off the host from the page: no URL, no font, no script
  from anywhere but the page itself, enforced by the CSP above and
  checked by `test_routes.c`.
- No TLS and no authentication. For access from another host, forward
  the loopback port (`ssh -L 8770:127.0.0.1:8770 user@sensor`) rather
  than binding a routable address.

## Tests

`make web-test` builds `slothweb_test` from `web/tests/*.c` and the
`web/src/` modules (not `main.c`). It needs no host file and no running
sloth, opens only loopback ephemeral ports (`127.0.0.1` and `::1`, port
0), and unix sockets and SQLite files in fresh `mkdtemp()` directories
under `/tmp`, and never leaves the host. Every M2 test runs on a pinned
clock. `make web-test WITH_SQLITE=0` builds and runs the same suite
against the memory-only build. It is clean under
`EXTRA_CFLAGS="-Werror -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"`
and under `EXTRA_CFLAGS="-Werror -fsanitize=thread"` with
`TSAN_OPTIONS=halt_on_error=1`.

| File | Covers |
|---|---|
| `test_acl.c` | the list on hand-built sockaddrs: loopback default, non-loopback v4/v6 refused, prefix boundaries, v4-mapped folding, CIDR parse errors |
| `test_config.c` | default bind, remote bind refused without the flag and announced with it, remote `--web-allow` needs the flag, `--strict`; `--socket` default, parsing, the announcement of a non-loopback `tcp:` and its `--strict` refusal |
| `test_http.c` | hand-written request bytes: GET/HEAD routed, 405 for every other method, split reads, 400/505, the 8 KB boundary, path and query, `If-None-Match` collection and weak comparison, `Host` collection and which values are accepted |
| `test_routes.c` | the route table without a socket: page `200`/`304`/`HEAD`, no external reference in the served page, no HTML or code sink in its script (stream values are `textContent` only), the system font stack, the §8.1 tokens, the CSP hashes recomputed (SHA-256 checked against FIPS 180-4 vectors), health JSON, stream headers, `503`, event formats, `404`, `405` on every route, `421` for a foreign `Host` on every route and `400` for none or two |
| `test_json.c` | the writer's escaping byte for byte: markup, quotes, controls, C1, U+2028/9, invalid UTF-8 as U+FFFD, the code-point-boundary cut |
| `test_jsonl.c` | hand-written lines: sloth's shapes, escapes and surrogate pairs, member text inside a string, every truncation of a record, syntax errors, invalid UTF-8 raw and escaped, duplicate members, the depth, member and integer limits |
| `test_live.c` | the live state and the framer without a socket: the device count per pass, passes cut by a gap, a bad line or a bad type not published, an empty table publishing 0, a reconnect as a new stream, the alert lifecycle counts, type names, records per second, sensor-health states, the recent ring, hostile strings escaped in `/api/live` and in `record` events, the worst-case `/api/live` fitting its buffer, split reads, truncated and overlong lines |
| `test_ingest.c` | the client over a real unix socket and loopback TCP, the test playing sloth: `--socket` parsing and its refusals, the back-off bound, **the device count `/api/live` reports matching what the fake sent within 5 s** for 3, 12, 300, 0 and 7 devices (spec §12, M1), markup escaped over HTTP and over `/events`, reconnect after the peer closes, retrying with no peer at the capped interval, no tight loop on a peer that closes at once, a mixed stream of truncated, overlong, invalid-UTF-8 and hostile lines, and that the client never writes to the socket |
| `test_rollup.c` | bucket boundaries in all three tiers, sum/count/min/max, value by kind, non-finite and huge values, the per-class key caps and LRU eviction with its flush and counters, churn decided on a key's whole life (keys of two and three samples crossing minute and hour boundaries keep only their 10 s rows, a key spanning a minute keeps all), held rows released when a key is established and at shutdown, a host recurring under LRU pressure keeping its minute and hour rows, interface, channel and alert keys established from their first sample and in classes of their own, the ring query's merge and bounds, the full store queue dropping 10 s rows before minute and hour rows and counting them, and every class full at `--web-max-keys` 8192 across an hour boundary and a shutdown with nothing dropped |
| `test_metrics.c` | hand-written lines through the decoder on a pinned clock: the key canonicalisers, gauges from `%.2f` reals, hostile keys refused, event counters, running totals as deltas floored at zero and first-sight baselines, flows, channels, presence, a probe request counted once though both `probe_client` and `seqnum_client` carry it, rows per pass with gaps and bad lines, the bounded high-water table, an evicted row seen again not counted twice, the evicted-id filter's two generations remembering an id across 8,191 evictions and forgetting it at the next rotation |
| `test_store.c` | the DDL guardrail in every build; with SQLite: a fresh store, `test_db.c`'s secret-column sweep, secrets fed through the stream absent from the file, a v0 and a v1 file migrated, a v0 and a v1 file whose step fails left where they were, a newer file and foreign files (a sloth.db shape, other databases, a file with another program's `application_id` and `user_version` but no table yet, our own `meta` under a foreign `application_id`, not SQLite) refused byte for byte, a WAL-mode sloth.db with an unflushed WAL refused with the file and its WAL byte for byte, a cleanly closed WAL-mode sloth.db refused with its directory listing unchanged, the file rules (symlink, mode, links, side files, a directory; the owner rule is not tested, see below), `DEFENSIVE` refusing a `sqlite_master` write on the store's handle and a library that leaves it off failing the open, a file swapped between the identifying and the writing open refused byte for byte, merged writes counted once in `store_rows` and bound queries, retention, the WAL left empty by the compaction, a start after a long stop expiring everything with the WAL never past one slice, the ceiling dropping the oldest fine rows first and sparing global series, and holding under 200 new keys a second within one flush interval; churn of two and three samples per key writing no minute or hour row while slothweb runs |
| `test_series.c` | every parameter rule and its reason, the answer's shape and paging, the routes (`HEAD`, `400` without echo, `query_too_long`, `421` and `405` on all three, `503` without a time series, the health members), the 900-point worst case fitting, the 900-point cap on a store+memory answer of 1,800 buckets and its next page, the store thread running beside reads and writes, and spec §12's M2 acceptance: an hour of records through the framer on a pinned clock, the 24 h request answered with 360 points 10 s apart (from memory, from the store's fine tier, and through `/api/series` again after a restart over the same store), the store under 5 MB on disk with its WAL after every step of the hour |
| `test_server.c` | real loopback sockets: default bind address, a refused peer over v4 and v6, 405 for POST/PUT/DELETE/PATCH, 431, idle and slow clients timed out, slot exhaustion; the page byte for byte and its `304`, health, a stream's ticks and pings and the client leaving, the first tick at once, a departing client noticed on the read path with no event due, the stream socket's `TCP_NODELAY` and `SO_SNDBUF`, a non-reading stream client dropped at the 64 KB backlog and not past it, the stream cap, `421` for `Host: attacker.example` |
| `test_baseline.c` | the hour-of-week index wrapping weekly, a never-fed (metric, key) scoring absent, fewer than `WEB_BL_WARM_N` feeds forcing z to 0 even against a wildly different probe, an established cell scoring a near-zero z at its own mean and a large one far from it, two hour-of-week cells of the same (metric, key) warming independently, a full table evicting the least-recently-fed entry and never one still in use, re-feeding the same pair not growing the table, `web_baseline_cap_for()` at the default and the extremes, and a NaN/infinite feed ignored |
| `test_anomaly.c` | end to end against a real `slothweb.db` and rollup, weeks of baseline history established through `web_baseline_feed()` directly and "now" written through `web_store_write()` and read back by the rule through `web_store_query()` — the same call production makes: the hourly pass itself wiring a closed hour bucket into the baseline, A1 opening on three consecutive minutes of a sustained burst and staying silent on a quiet stream or two burst minutes broken by a quiet one, A3 firing for a device present in an hour of the week it is normally absent and staying silent in its normal hours, A8 firing on a high NXDOMAIN share and not on a normal one, A9 firing once on a host's first-ever use of a protocol and not touching that episode again once the baseline has an entry, A10 firing past `WEB_ANOM_A10_SILENCE_S` of socket silence and not before it, every rule but A10 a no-op without a store, and an open episode closing after `WEB_ANOM_CLEAR_TICKS` quiet minutes |

A test cannot originate from a non-loopback address, so the refused-peer
socket tests narrow the list instead (only `127.0.0.2`, or only IPv4)
and connect from `127.0.0.1` and `::1`; `test_acl.c` covers the
non-loopback addresses against the same function the accept path calls.
Every absence assertion was seen to fail under a mutant of the guard it
covers before it was trusted. One rule has none: the store's owner rule
(a file owned by another uid is refused) cannot be exercised without
privilege a test must not ask for, and removing it leaves the suite
green; it is held by code reading. Two guards are reached only through
test seams in `web_store.c` (`web_store_test_no_defensive`,
`web_store_test_between_opens`, NULL and 0 outside the tests): the
`DEFENSIVE` read-back, by a seam that reads it back as off, and the
writer's second identify, by a seam that swaps the file between the two
opens.

`make cppcheck` analyses `web/` with the rest of the tree.

## Layout

```
web/
  README.md        this file
  src/
    main.c         argv, signals, the run
    web_config.c   command line, the remote-exposure policy, announcements
    web_acl.c      the allowed-peer list
    web_http.c     request parsing and the fixed error responses
    web_routes.c   the route table, health and live JSON, event formats
    web_server.c   listener, poll loop, timeouts, event streams, counters
    web_ingest.c   --socket, the data-socket thread, back-off, line framing
    web_jsonl.c    the strict JSONL record decoder
    web_live.c     the live state: counts, devices, alerts, sensor, ring
    web_metrics.c  records to samples: keys, deltas, rows per pass (M2)
    web_rollup.c   the metric table, the three tiers, key bounds, the ring
    web_store.c    slothweb.db: open rules, identification, migration, I/O
    web_tsdb.c     the store thread: close, write, compact
    web_series.c   /api/series, /api/keys, /api/metrics
    web_baseline.c 168 hour-of-week cells per (metric, key), z-scoring (M3)
    web_anomaly.c  A1, A3, A8, A9, A10; /api/anomalies (M3)
    web_json.c     the JSON writer every outgoing string goes through
    web_assets.h   the generated page's symbols
  ui/              the page sources (index.html, theme.css, page.css, app.js)
  tools/
    embed.c        ui/ -> build/web/web_assets.c (build time only)
    sha256.c       SHA-256 and base64 for embed.c and the tests
  tests/           slothweb_test (make web-test)
```

Wiki page: [`docs/wiki/slothweb.md`](../docs/wiki/slothweb.md).
