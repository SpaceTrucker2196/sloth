---
name: jsonl-schema
description: Wire format for the sloth forensic stream — file (`-o FILE`) and read-only socket (`--data-socket SPEC`) emit the same records
type: reference
---

# JSONL stream — wire format

**Summary**: Sloth emits one JSON object per line to a file (`-o FILE`)
and/or a read-only stream socket (`--data-socket SPEC`). Same records,
same encoding, line-delimited by `\n`. This page is the contract
downstream consumers (SIEMs, the planned iOS dashboard, ad-hoc
scripts) code against.

**Sources**: `src/jsonl.c`, `src/data_socket.c`.

**Last updated**: 2026-05-26.

---

## Transports

| Transport       | Configured by                        | Use |
|-----------------|--------------------------------------|-----|
| File (append)   | `-o /var/log/sloth.jsonl`            | log forwarder pulls / `tail -f` |
| UNIX-domain     | `--data-socket unix:/var/run/sloth.sock` | local consumer on the same host |
| TCP             | `--data-socket tcp:HOST:PORT`        | remote consumer over a trusted transport (e.g. Tailscale) |

Both `-o` and `--data-socket` can be set at the same time. Each record
is broadcast to every active sink — same line, same encoding.

**Read-only on the socket.** Sloth never reads from a connected
client. The protocol is one-way; there is no handshake, no auth, no
verbs. Access control is the caller's job (bind address, file
permissions on the UNIX socket, Tailscale ACLs).

**Backpressure.** The socket writer is non-blocking. A slow client
that fills its kernel send buffer **loses lines** for the duration of
the stall (it does not get queued). A broken pipe closes the client
fd; reconnect to resume.

**Framing.** Newline-delimited JSON (NDJSON / JSONL). Every line is
one complete JSON object terminated by exactly one `\n`. There is no
record separator beyond the newline; consumers split on `\n` and
parse each line.

## Common envelope

Every record has:

| Field | Type   | Notes |
|-------|--------|-------|
| `type` | string | record class (`dns`, `tls`, `quic`, `http`, `ntp`, `icmp`, `alert`) |
| `ts`   | int    | Unix timestamp in seconds. Per-record meaning: observation time for protocol logs, last-seen time for alerts |

String fields are JSON-escaped per RFC 8259: `"`, `\`, control bytes
under 0x20, plus the `\n` / `\r` / `\t` shorthand. Bytes ≥ 0x80 pass
through as UTF-8.

## Record types

### `dns`

```json
{"type":"dns","ts":1700000000,"src":"192.168.1.5","qname":"example.com","qtype":"A","answer":"93.184.216.34","is_resp":1}
```

| Field    | Type   | Meaning |
|----------|--------|---------|
| `src`    | string | source IP (the host that issued the query / received the response) |
| `qname`  | string | queried name |
| `qtype`  | string | `A` / `AAAA` / `PTR` / `MX` / `NS` / `CNAME` / `TXT` / `SRV` |
| `answer` | string | first A/AAAA answer, or `NXDOMAIN`, or empty if Q-only |
| `is_resp`| int    | 1 for response, 0 for query |

### `tls`

```json
{"type":"tls","ts":1700000001,"src":"10.0.0.5","dst":"93.184.216.34","host":"example.com","ver":"TLS 1.3","ja3":"deadbeefcafef00d00112233445566ff"}
```

| Field  | Type   | Meaning |
|--------|--------|---------|
| `src`  | string | client IP |
| `dst`  | string | server IP |
| `host` | string | SNI hostname (empty if not present) |
| `ver`  | string | `TLS 1.3` / `TLS 1.2` / `TLS 1.1` / `TLS 1.0` / unknown |
| `ja3`  | string | 32-char hex JA3 fingerprint (see [[ja3-fingerprinting]]) |

### `quic`

```json
{"type":"quic","ts":1700000002,"src":"10.0.0.5","dst":"1.1.1.1","host":"cloudflare.com","ver":"v1"}
```

| Field  | Type   | Meaning |
|--------|--------|---------|
| `src`  | string | client IP |
| `dst`  | string | server IP |
| `host` | string | resolved hostname (from DNS cache) |
| `ver`  | string | QUIC version string |

### `http`

```json
{"type":"http","ts":1700000003,"src":"10.0.0.5","host":"example.com","method":"GET","path":"/index.html"}
```

### `ntp`

```json
{"type":"ntp","ts":1700000004,"src":"10.0.0.1","dst":"192.168.1.5","mode":"server","version":4,"stratum":1,"ref":"GPS"}
```

`version` and `stratum` are integers.

### `icmp`

```json
{"type":"icmp","ts":1700000005,"src":"192.168.1.5","dst":"8.8.8.8","desc":"Echo Req","ty":8,"code":0,"seq":42,"v6":0}
```

`ty`, `code`, `seq`, `v6` are integers (`v6=1` for ICMPv6).

### `alert`

```json
{"type":"alert","ts":1700000006,"title":"THREAT_DOMAIN","detail":"192.168.1.5 queried malware.testing.com (IOC ...)","key":"threat-d:malware.testing.com","sev":2,"ty":3,"count":1}
```

| Field   | Type   | Meaning |
|---------|--------|---------|
| `title` | string | rule name (see [[alerts]]) |
| `detail`| string | one-line human-readable detail |
| `key`   | string | dedup key (`type:identifier`) |
| `sev`   | int    | severity: **0=LOW (yellow), 1=WARN (orange), 2=CRIT (red)**. See [[alerts]] for the tier semantics. |
| `ty`    | int    | `alert_type_t` enum value (stable per `include/sloth.h`) |
| `count` | int    | number of observations under this dedup key |

`ts` for alerts is the `last_seen` time of the dedup key, not the
first observation.

## Versioning

- **No version field.** Fields are append-only; existing names and
  semantics don't change.
- New record types may appear; consumers should ignore unknown
  `type` values gracefully.
- New optional fields may appear on existing records; consumers
  should ignore unknown keys.
- `sev` enum values are guaranteed stable (the 3-tier reclassification
  in commit `21814ec` is the last one; numeric values reused the
  `INFO=0` slot intentionally).

## Reference consumer (Python)

A complete reference consumer ships in
[`examples/consumer/sloth-stream.py`](../../examples/consumer/sloth-stream.py)
(stdlib only, ~270 lines). It exercises every record type listed
above, demonstrates the connect / read / parse / filter / reconnect
loop, and is the first thing to run when validating a deployment:

```sh
python3 examples/consumer/sloth-stream.py unix:/tmp/sloth.sock
python3 examples/consumer/sloth-stream.py tcp:127.0.0.1:8765 --type alert
python3 examples/consumer/sloth-stream.py unix:/tmp/sloth.sock --raw | jq .
```

The script is the worked example for porting a consumer to any other
language — the structure (small read loop, per-type formatter table,
disconnect → backoff → reconnect) maps directly to Go's `bufio`,
Node's `readline`, etc. See
[`examples/consumer/README.md`](../../examples/consumer/README.md)
for the full feature set.

## iOS Swift consumer sketch

The TCP transport is plain newline-delimited JSON — `Network.framework`
reads it natively:

```swift
import Network
import Foundation

let conn = NWConnection(host: "100.x.x.x", port: 8765, using: .tcp)
var buffer = Data()
conn.start(queue: .main)

func receive() {
    conn.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { data, _, _, err in
        if let data = data, !data.isEmpty {
            buffer.append(data)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer.subdata(in: 0..<nl)
                buffer.removeSubrange(0...nl)
                if let json = try? JSONSerialization.jsonObject(with: line) as? [String: Any] {
                    // dispatch by json["type"] as? String
                }
            }
        }
        if err == nil { receive() }
    }
}
receive()
```

No HTTP, no TLS framing, no length prefix — exactly what `--data-socket
tcp:...` writes.

## Related pages

- [[alerts]] — severity tiers and the `sev` mapping in detail.
- [[ja3-fingerprinting]] — origin of the `ja3` field in `tls` records.
- [[pcap-export]] — sibling forensic output (raw packets, not JSONL).
