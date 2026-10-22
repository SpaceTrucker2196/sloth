# slothweb

The browser dashboard for sloth data, built in milestones. The spec is
[`docs/web-ui-spec.md`](../docs/web-ui-spec.md); the rulings table at its
top overrides the body. Tracker: #102.

**This is M1 (#159) on top of M0 (#158) and W0 (#157).** W0 is the
listener, the allowed-peer list and its refusals. M0 added the embedded
page, `/api/health` and an `/events` stream. M1 adds the data-socket
client: slothweb reads sloth's JSONL stream, keeps a small live state,
serves it as `/api/live`, and the page's Overview shows the device
count, open alerts by severity, records per second, sensor health and a
record ticker. Run it beside sloth and open `http://127.0.0.1:8770`.

## Build and run

```sh
make web            # builds ./slothweb
make web-test       # builds ./slothweb_test and runs it
./slothweb          # listens on 127.0.0.1:8770, reads unix:/run/sloth/sloth.sock
```

sloth creates its unix socket `0600`, so slothweb runs as the same user
as sloth (or one sloth's socket directory admits); the kernel's
permission check is the only authentication the stream has.

`slothweb` is C99 and links libc and pthreads only. It is not part of
`make`, `make embedded` or `sloth`, no `src/` file is compiled into it,
and nothing in `src/` references `web/`. Later milestones may link
`libsqlite3`, which `WITH_SQLITE` already links; nothing else.

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
| `--help` | Usage. |

Exit status: `0` after `SIGINT`/`SIGTERM`, `1` when the bind fails, `2`
on a usage error or a policy refusal.

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

Paths match exactly; the query string is ignored, and an absolute-form
target (`GET http://127.0.0.1:8770/ HTTP/1.1`) routes by its path.

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
{"service":"slothweb","milestone":"M1","uptime_s":12,
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
 "sse_clients":1,"tick_seq":12}
```

`socket` is `connecting`, `connected` or `retrying` (waiting out a
back-off of `socket_retry_ms`). `socket_last_error` is slothweb's own
text (`connect: No such file or directory`, `peer closed the stream`),
never anything the peer sent. `socket_gaps` counts sloth's `socket_gap`
markers and `socket_gap_dropped` the records they say were dropped
(jsonl-schema, #93). The database fields stay `"none"`/`null` until M4.

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

## What it never does

- No method that writes, ever (`405` is permanent, not a W0 placeholder).
- No name resolution of any kind, including its own bind address.
- No write to `sloth.db`; M1 does not open it at all.
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
0) and unix sockets in a fresh `mkdtemp()` directory under `/tmp`, and
never leaves the host. It is clean under
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
| `test_server.c` | real loopback sockets: default bind address, a refused peer over v4 and v6, 405 for POST/PUT/DELETE/PATCH, 431, idle and slow clients timed out, slot exhaustion; the page byte for byte and its `304`, health, a stream's ticks and pings and the client leaving, the first tick at once, a departing client noticed on the read path with no event due, the stream socket's `TCP_NODELAY` and `SO_SNDBUF`, a non-reading stream client dropped at the 64 KB backlog and not past it, the stream cap, `421` for `Host: attacker.example` |

A test cannot originate from a non-loopback address, so the refused-peer
socket tests narrow the list instead (only `127.0.0.2`, or only IPv4)
and connect from `127.0.0.1` and `::1`; `test_acl.c` covers the
non-loopback addresses against the same function the accept path calls.
Every absence assertion was seen to fail under a mutant of the guard it
covers before it was trusted.

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
    web_json.c     the JSON writer every outgoing string goes through
    web_assets.h   the generated page's symbols
  ui/              the page sources (index.html, theme.css, page.css, app.js)
  tools/
    embed.c        ui/ -> build/web/web_assets.c (build time only)
    sha256.c       SHA-256 and base64 for embed.c and the tests
  tests/           slothweb_test (make web-test)
```

Wiki page: [`docs/wiki/slothweb.md`](../docs/wiki/slothweb.md).
