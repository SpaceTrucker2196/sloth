# slothweb

The browser dashboard's server, a separate binary under `web/`. This
page tracks what has shipped; the design is
[`docs/web-ui-spec.md`](../../docs/web-ui-spec.md), whose rulings table
overrides its body.

**Summary**: slothweb is at M0 (#158) on top of W0 (#157). W0 is a
listener with an allowed-peer list: loopback-only bind by default
(`127.0.0.1:8770`); a non-loopback bind or allow entry needs
`--web-allow-remote` and is announced on stderr; `--strict` refuses
both. Peers outside the list are closed at accept() and counted. M0
adds three routes behind it: one embedded page with an ETag and `304`,
`/api/health`, and an `/events` Server-Sent Events stream with a 1 s
tick counter. Every method other than `GET`/`HEAD` is `405` on every
path, a header block over 8 KB `431`, and idle or slow clients time out
on an absolute budget.

**Sources**: `web/README.md`, `web/src/web_acl.c`, `web/src/web_config.c`,
`web/src/web_http.c`, `web/src/web_routes.c`, `web/src/web_server.c`,
`web/src/main.c`, `web/ui/*`, `web/tools/embed.c`, `web/tests/*.c`,
`Makefile` (`web`, `web-test`, `cppcheck`), `docs/web-ui-spec.md`,
issues #102, #157 and #158.

**Last updated**: 2026-10-21.

---

## Where it sits

slothweb is a consumer of sloth, never part of it. It is built by
`make web`, tested by `make web-test`, and is not in `make`, `make
embedded` or the `sloth` binary. No `src/` file is compiled into it and
nothing in `src/` references `web/`. W0 links libc and pthreads; the
spec allows `libsqlite3` later, which `WITH_SQLITE` already links, and
nothing beyond it.

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
| M1 to M6 (ingest, series, baselines, devices, Wi-Fi, flows) | children of #102 | not started |

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
peer also pins little kernel memory. At most 24 streams are held; the
25th `GET /events` is `503`, which keeps 8 of the 32 slots for the page
and the API.

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

A test cannot connect from a non-loopback address, so the socket-level
refusals narrow the list and connect from loopback; the list function
itself is tested on non-loopback sockaddrs. Each absence assertion was
run against a mutant of its guard and seen to fail before it was kept.

The suite runs clean under ASan/UBSan and TSan, and `make cppcheck`
covers `web/`.

## Related pages

- [[data-socket-exposure]] — the remote-bind guard this copies.
- [[jsonl-schema]] — the stream later milestones consume.
- [[sqlite-schema]] — the database later milestones read, read-only.
- [[cli-reference]] — sloth's own flags; slothweb's are in
  [`web/README.md`](../../web/README.md).
