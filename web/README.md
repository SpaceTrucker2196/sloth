# slothweb

The browser dashboard for sloth data, built in milestones. The spec is
[`docs/web-ui-spec.md`](../docs/web-ui-spec.md); the rulings table at its
top overrides the body. Tracker: #102.

**This is W0 (#157): the listener, the allowed-peer list and its
refusals, before any route exists.** It serves nothing. Every `GET` and
`HEAD` gets a fixed `404`, every other method gets `405`. M0 adds the
first routes.

## Build and run

```sh
make web            # builds ./slothweb
make web-test       # builds ./slothweb_test and runs it
./slothweb          # listens on 127.0.0.1:8770
```

`slothweb` is C99 and links libc and pthreads only. It is not part of
`make`, `make embedded` or `sloth`, no `src/` file is compiled into it,
and nothing in `src/` references `web/`. Later milestones may link
`libsqlite3`, which `WITH_SQLITE` already links; nothing else.

## Command line

| Flag | Effect |
|---|---|
| `--web-bind ADDR:PORT` | Listen address. A literal `A.B.C.D:PORT` or `[V6]:PORT`; default `127.0.0.1:8770`. Names are never resolved, so `localhost:8770` is an error. A non-loopback address is refused unless `--web-allow-remote` is given. `[::]` is IPv6 only (`IPV6_V6ONLY`). |
| `--web-allow CIDR` | Admit peers in `CIDR` as well as loopback. Repeatable, up to 30 entries. Host bits past the prefix must be zero (`10.0.0.1/8` is refused, write `10.0.0.0/8`). A non-loopback entry needs `--web-allow-remote`. |
| `--web-allow-remote` | Authorise a non-loopback bind and non-loopback `--web-allow` entries. Each one is announced on stderr at startup. It authorises the bind, not the peers: with no `--web-allow`, a remote bind still admits loopback only. |
| `--strict` | Refuse any non-loopback bind or allow entry, even with `--web-allow-remote`. Same shape as sloth's `--strict` refusing a routable `--data-socket`. |
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
3. **One fixed answer**, then the connection closes (no keep-alive):

   | Request | Answer |
   |---|---|
   | `GET` or `HEAD`, any target | `404` (`HEAD`: same headers, no body) |
   | any other method (`POST`, `PUT`, `DELETE`, `PATCH`, ...) | `405`, `Allow: GET, HEAD` |
   | header block over 8 KB | `431` |
   | malformed request line or header | `400` |
   | HTTP major version other than 1 | `505` |
   | no complete header block within 10 s of accept() | `408`, best effort |

   Methods are case-sensitive (RFC 9110 §9.1): `get` is `405`.
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

## What it never does

- No method that writes, ever (`405` is permanent, not a W0 placeholder).
- No name resolution of any kind, including its own bind address.
- No write to `sloth.db`; W0 does not open it at all.
- No TLS and no authentication. For access from another host, forward
  the loopback port (`ssh -L 8770:127.0.0.1:8770 user@sensor`) rather
  than binding a routable address.

## Tests

`make web-test` builds `slothweb_test` from `web/tests/*.c` and the
`web/src/` modules (not `main.c`). It needs no host file, opens only
loopback ephemeral ports (`127.0.0.1` and `::1`, port 0) and never leaves
the host. It is clean under
`EXTRA_CFLAGS="-Werror -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"`
and under `EXTRA_CFLAGS="-Werror -fsanitize=thread"` with
`TSAN_OPTIONS=halt_on_error=1`.

| File | Covers |
|---|---|
| `test_acl.c` | the list on hand-built sockaddrs: loopback default, non-loopback v4/v6 refused, prefix boundaries, v4-mapped folding, CIDR parse errors |
| `test_config.c` | default bind, remote bind refused without the flag and announced with it, remote `--web-allow` needs the flag, `--strict` |
| `test_http.c` | hand-written request bytes: 404 for GET/HEAD, 405 for every other method, split reads, 400/505, the 8 KB boundary |
| `test_server.c` | real loopback sockets: default bind address, a refused peer over v4 and v6, 405 for POST/PUT/DELETE/PATCH, 431, idle and slow clients timed out, slot exhaustion |

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
    web_http.c     request classification and the fixed responses
    web_server.c   listener, poll loop, timeouts, counters
  tests/           slothweb_test (make web-test)
```

Wiki page: [`docs/wiki/slothweb.md`](../docs/wiki/slothweb.md).
