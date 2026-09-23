# sloth-stream — reference JSONL consumer

A small Python 3 program that connects to a running sloth's
`--data-socket SPEC` and streams the live JSONL records. Use it to:

- **Verify** a deployment — confirm sloth is emitting on the socket
  you think it is, in the format you think it is.
- **Tail** specific record types (`dns`, `tls`, `alert`, …) with
  pretty-printing.
- **Pipe** raw JSONL into other tools (`jq`, a SIEM forwarder, a
  notebook).
- **Read** as a worked example before writing your own consumer in
  another language — the connect / read / parse / filter / reconnect
  loop generalises directly.

Stdlib only. No external dependencies. Python 3.7+.

The wire-format contract this script codes against is
[`docs/wiki/jsonl-schema.md`](../../docs/wiki/jsonl-schema.md).
Sloth's side of the connection is implemented in
[`src/data_socket.c`](../../src/data_socket.c).

---

## Quick start

Start sloth with a data socket. UNIX-domain for same-host consumers,
TCP for remote (over a trusted transport — Tailscale, a private VPN,
or localhost only):

```sh
sudo ./sloth --data-socket unix:/tmp/sloth.sock
sudo ./sloth --data-socket tcp:127.0.0.1:8765
sudo ./sloth --data-socket tcp:100.64.0.5:8765       # e.g. a Tailscale IP
```

Then point this script at the same spec:

```sh
python3 examples/consumer/sloth-stream.py unix:/tmp/sloth.sock
python3 examples/consumer/sloth-stream.py tcp:127.0.0.1:8765
```

You should immediately see a colourised tail of every record sloth
emits, one line per record.

---

## Filters

```sh
# Only alerts — note this is FIRST SIGHTINGS ONLY (see below)
python3 sloth-stream.py unix:/tmp/sloth.sock --type alert

# The full alert lifecycle, including WARN -> CRIT escalations (#98)
python3 sloth-stream.py unix:/tmp/sloth.sock \
    --type alert.create,alert.update,alert.escalate,alert.resolve

# Multiple types (comma-separated)
python3 sloth-stream.py unix:/tmp/sloth.sock --type dns,tls,quic

# By `src` substring (matches any record that has a `src` field)
python3 sloth-stream.py unix:/tmp/sloth.sock --src 10.0.0.5

# Combine: TLS handshakes from one client
python3 sloth-stream.py unix:/tmp/sloth.sock --type tls --src 10.0.0.5
```

---

## Output modes

```sh
# Pretty-print (default)
python3 sloth-stream.py unix:/tmp/sloth.sock

# Raw JSON pass-through — exactly what sloth sends
python3 sloth-stream.py unix:/tmp/sloth.sock --raw | jq .

# Type counts — one summary line every 5 seconds, instead of per-event
python3 sloth-stream.py unix:/tmp/sloth.sock --count
# example output:
#   alert=3 dns=187 http=14 tls=42
```

---

## Reconnect behaviour

By default the script reconnects with a 1-second backoff on
disconnect (broken pipe, EOF, sloth restart). To exit instead — useful
for one-shot scripts or shell pipelines that want a finite stream:

```sh
python3 sloth-stream.py unix:/tmp/sloth.sock --no-reconnect
```

Be aware: **lines emitted during the disconnect window are lost**.
Sloth's data socket is non-blocking and one-way (per MISSION.md §4);
backpressure protection is on the consumer side. If you need
durability, write to `-o FILE` *and* the socket, and tail the file
alongside.

---

## Backpressure

The socket writer in sloth is non-blocking and delivers **whole
records or none** (#93). If your consumer falls behind, sloth queues up
to 512 KiB of complete lines for your connection (only — other
consumers are unaffected). Past that it drops whole incoming records
and, before the next line you do receive, sends a
`{"type":"socket_gap","seq":…,"dropped":…,"dropped_total":…}` record
so you know how many you missed. If your connection accepts no bytes
for 30 s, sloth closes it. Bytes after the last `\n` at EOF are an
unfinished record — `stream_lines()` already discards them. A few
principles to stay healthy:

1. Keep the read loop tight — don't do heavy work inline. Hand the
   parsed record to a queue and process elsewhere.
2. Filter at sloth-side where you can (`--type` is client-side; if you
   only want alerts and the stream is large, consider also writing to
   a file for archival and using the socket only for the hot path).
3. Treat reconnects as normal — every consumer will see them; design
   for at-least-once-with-gaps semantics, not exactly-once.

---

## Alerts: `--type alert` is not enough (#98)

`{"type":"alert",...}` is written **only when a dedup key is new**. An
alert created at WARN that later becomes CRIT produces no second
`alert` record, so a pipeline that pages on CRIT and filters
`--type alert` will never fire. Everything after creation rides the
lifecycle family:

| Record | Meaning |
|--------|---------|
| `alert.create` | new incident, alongside the legacy `alert` record |
| `alert.escalate` | severity went up (`prev_sev` → `sev`). **This is the paging signal.** |
| `alert.update` | severity went down, or the evidence changed (floored at one per 60 s) |
| `alert.resolve` | incident closed (`reason`: `expired` after 300 s with no rule re-asserting the key, `evicted`, or `cleared`) |

Join them with `incident_id`, which is stable from create to resolve;
`event_id` is unique per event. Counters: `count` and `evaluations` are
rule ticks (every rule re-evaluates once per poll, so a persistent
condition reaches four figures without anything new happening);
`observations` only moves when the evidence does. Full field table in
`docs/wiki/jsonl-schema.md`.

---

## Is the sensor actually collecting? `sensor_health` (#91)

Every other record answers "what did sloth see". `sensor_health` answers
"was sloth able to see", and it is **the one record type a silent sensor
still emits** — which is the point, because a well-placed sensor on a
quiet segment is *supposed* to produce nothing else.

It is the stream's only singleton: one line per tick about the
collector, not one per row of a table. Change-only with a 300 s
heartbeat, so a healthy sensor costs you a line every five minutes and a
degrading one tells you the moment it degrades.

What a real consumer should alert on:

| Condition | Meaning |
|-----------|---------|
| `capture_open`/`monitor_open` 1 with `_running` 0 | **the capture thread died behind a still-open handle.** Tables stop growing and nothing else in the stream says so |
| `capture_exit`/`monitor_exit` other than `none` or `stopped` | `iface_gone` (adapter unplugged / link down), `perm_lost` (capability revoked), `not_activated`, or `error` |
| `chan_confirmed_ok` 0 | `--hop` asked the radio for `chan_requested` and the platform refused; the radio is still on `chan_confirmed` |
| `capture_drop_delta` / `monitor_drop_delta` non-zero | libpcap's buffer is overflowing right now — the lifetime `_drop` alone can't tell you that |
| `*_ifdrop_delta` non-zero | the NIC is dropping before libpcap sees it |
| `evictions` climbing | a bounded table is full and discarding observations |

Read `*_exit_detail` beside `*_exit`: `error` is the honest bucket for
libpcap wording sloth does not recognise, and the raw string is right
there rather than being guessed into a category.

Two gotchas worth knowing before you build on it:

- `*_recv`/`*_drop`/`*_ifdrop` are **sloth's** monotonic totals, not
  libpcap's raw 32-bit counters, so differencing two samples never
  yields a negative rate even across a handle restart.
- `evictions` is loss on the *instrumented* tables (alerts, top hosts,
  PNL clients, per-client PNL SSIDs, DHCP events, EAP sessions, devices).
  The probe-client, beacon, seqnum, assoc and per-protocol flow rings are
  not counted yet. Full list and field table in
  `docs/wiki/jsonl-schema.md`.

```sh
python3 sloth-stream.py unix:/tmp/sloth.sock --type sensor_health
```

---

## Source as a template

The script is deliberately small (~440 lines, single file) and avoids
clever abstractions. The structure is the textbook one:

```
parse_spec  → connect  → stream_lines  → json.loads  → filter  → format → print
                                                                   ↑
                                                                   on disconnect:
                                                                   close, sleep(1),
                                                                   loop
```

If you're porting to another language, the same shape works directly
in Go (`bufio.Scanner` over the socket, `encoding/json` for parsing),
Node (`readline.createInterface` over a socket Readable), or any
language with a TCP/UNIX-domain client and a JSON parser. The iOS
Swift client (separate repo) uses `Network.framework` with the same
read-loop shape.

---

## Smoke-testing without a running sloth

Sloth's own tests for `data_socket.c` are hermetic (UNIX-domain
fixture); you can use the same pattern to test consumers. Write a
minimal Python producer that opens a UNIX socket, accepts a
connection, and writes hand-crafted JSONL lines — then run this
script against it. The whole loop fits in ~30 lines and runs in under
a second; useful as a CI step for downstream tooling that depends on
the schema.
