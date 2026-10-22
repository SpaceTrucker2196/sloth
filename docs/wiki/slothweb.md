# slothweb

The browser dashboard's server, a separate binary under `web/`. This
page tracks what has shipped; the design is
[`docs/web-ui-spec.md`](../../docs/web-ui-spec.md), whose rulings table
overrides its body.

**Summary**: slothweb is at M2 (#160) on top of M1 (#159), M0 (#158)
and W0 (#157). M2 derives the spec §5.1 metrics from the records M1
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

**Sources**: `web/README.md`, `web/src/web_metrics.c`, `web/src/web_rollup.c`,
`web/src/web_store.c`, `web/src/web_tsdb.c`, `web/src/web_series.c`,
`web/src/web_ingest.c`, `web/src/web_jsonl.c`,
`web/src/web_live.c`, `web/src/web_json.c`, `web/src/web_acl.c`, `web/src/web_config.c`,
`web/src/web_http.c`, `web/src/web_routes.c`, `web/src/web_server.c`,
`web/src/main.c`, `web/ui/*`, `web/tools/embed.c`, `web/tests/*.c`,
`Makefile` (`web`, `web-test`, `cppcheck`), `docs/web-ui-spec.md`,
`src/jsonl.c` (`jsonl_emit_devices()`, `jsonl_emit_state_snapshots()`),
`src/db.c` and `src/secure_file.c` (the open and migration rules M2
re-implements), issues #102, #157, #158, #159 and #160.

**Last updated**: 2026-10-21 (M2, #160).

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
| M3 to M6 (baselines, devices, Wi-Fi, flows) | children of #102 | not started |

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
recently seen out first, evictions counted on `/api/health`; labels
(interfaces, channels, alert types) are capped at 128; global metrics
are always kept. Closed fine buckets also go to a 131,072-row ring in
memory, which is all `/api/series` has without SQLite.

### The store

`slothweb.db` is opened by descriptor with `O_NOFOLLOW`, created 0600,
and refused (never repaired) if it is not a regular file of the
effective uid with no group or other bits and one link; the WAL and
shared-memory files are checked the same way, and SQLite then opens it
with `SQLITE_OPEN_NOFOLLOW` and `DEFENSIVE`: sloth's own rules for
`sloth.db`. The file is identified before anything is written: empty is
new, a `meta` table naming it a slothweb store is ours, anything else
(sloth.db included) is refused untouched, and so is a schema newer than
the build. Schema changes follow the 2026-10-21 owner rule: a chain of
additive steps from v0, each in one `BEGIN IMMEDIATE` with its own
stamp, so a failed step leaves the file at the version it reached. A
new file is stamped v0 and takes the same chain. There is only v1 today.
No column can hold a credential (sloth's `test_db.c` guardrail, copied).

The store thread, never the HTTP one, closes due buckets every second,
writes them in one transaction every 10 s, and once an hour drops rows
past retention, then, while the used size is over `--web-max-mb` (256),
the oldest fine rows, then minute, then hour; then returns free pages
and truncates the WAL. Queries use a second, read-only connection with
every parameter bound.

### `/api/series` and the Activity view

`/api/series?metric=&key=&tier=&from=&to=` answers at most 900 buckets
(`[t, value, min, max, n]`, oldest first) with `more` and `next_to` for
paging. Every parameter is validated first: known names only, each
once, percent-decoded to printable ASCII, the key through the metric's
canonicaliser, the range non-empty, at most a day ahead and no longer
than the tier keeps. `/api/keys` and `/api/metrics` feed the pickers.
The Activity view draws the selected series as a line over its
per-bucket min..max band on Canvas 2D, with a small multiple per key
(the loudest top left) coloured by the TUI's IP hash palette. Baselines,
z-scores and the ratio toggle are M3.

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
| design tokens per §8.1 | `test_design_tokens_match_spec` |
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
| after 1 h, the 24 h chart shows the last hour at 10 s and the store is under 5 MB | `test_acceptance_one_hour` (an hour of records through the framer on a pinned clock: 42,120 fine rows, 360 points 10 s apart from the 24 h request, about 1.1 MB on disk) |
| metric derivation, deltas floored at zero | `test_gauges`, `test_event_counters`, `test_highwater_deltas`, `test_flow_counters`, `test_channels`, `test_presence`, `test_pass_gauges` |
| three tiers with sum/count/min/max | `test_bucket_boundaries_and_aggregates` |
| keyed metrics bounded, LRU, evictions counted | `test_key_classes_are_bounded_lru`, `test_highwater_table_bounded` |
| own file, secure open, migration chain, newer refused | `test_fresh_store`, `test_v0_file_is_migrated`, `test_v0_failed_step_leaves_file_unchanged`, `test_newer_file_refused`, `test_foreign_files_refused`, `test_file_rules` |
| secret-column guardrail | `test_schema_text_guardrail`, `test_no_column_can_hold_secret_material`, `test_secrets_never_reach_disk` |
| compaction and the ceiling | `test_compaction_retention`, `test_ceiling_drops_oldest_fine_first` |
| strict parameters, bounded answers, behind the W0/M0 checks | `test_parameters_validated`, `test_series_json_and_paging`, `test_routes`, `test_worst_case_fits` |
| writes off the HTTP thread | `test_store_thread` |

A test cannot connect from a non-loopback address, so the socket-level
refusals narrow the list and connect from loopback; the list function
itself is tested on non-loopback sockaddrs. Each absence assertion was
run against a mutant of its guard and seen to fail before it was kept.

The suite runs clean under ASan/UBSan and TSan, and `make cppcheck`
covers `web/`.

## Related pages

- [[data-socket-exposure]] — the remote-bind guard this copies.
- [[jsonl-schema]] — the stream M1 consumes.
- [[sqlite-schema]] — sloth's database, which later milestones read
  read-only and M2's store never touches; its migration rule is the one
  `slothweb.db` follows.
- [[cli-reference]] — sloth's own flags; slothweb's are in
  [`web/README.md`](../../web/README.md).
