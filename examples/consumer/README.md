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
# Only alerts
python3 sloth-stream.py unix:/tmp/sloth.sock --type alert

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

The socket writer in sloth is non-blocking. If your consumer falls
behind and fills the kernel send buffer, **sloth drops the line for
your connection** (only — other consumers still receive it) and the
broken-pipe path eventually reaps your fd. A few principles to stay
healthy:

1. Keep the read loop tight — don't do heavy work inline. Hand the
   parsed record to a queue and process elsewhere.
2. Filter at sloth-side where you can (`--type` is client-side; if you
   only want alerts and the stream is large, consider also writing to
   a file for archival and using the socket only for the hot path).
3. Treat reconnects as normal — every consumer will see them; design
   for at-least-once-with-gaps semantics, not exactly-once.

---

## Source as a template

The script is deliberately small (~270 lines, single file) and avoids
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
