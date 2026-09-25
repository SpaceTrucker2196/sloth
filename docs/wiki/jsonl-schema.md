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

**Last updated**: 2026-09-23.

---

## Transports

| Transport       | Configured by                        | Use |
|-----------------|--------------------------------------|-----|
| File (append)   | `-o /var/log/sloth.jsonl`            | log forwarder pulls / `tail -f` |
| UNIX-domain     | `--data-socket unix:/var/run/sloth.sock` | local consumer on the same host |
| TCP             | `--data-socket tcp:HOST:PORT`        | remote consumer over a trusted transport (e.g. Tailscale) |

Both `-o` and `--data-socket` can be set at the same time. Each record
is broadcast to every active sink — same line, same encoding.

**`-o FILE` is private (#87).** The stream carries cleartext-credential
alerts, probe lists and device MACs. The file is opened append-only and
created **0600** regardless of umask. If it already exists it must be a
regular file owned by sloth's effective uid, with no group/other
permission bits and a single link; a symlink at the path is refused.
sloth does not `chmod` it — a `0640` log from an older run is refused at
startup (`sloth: could not open jsonl output …: mode 0640 is
group/other accessible — refusing`). Make it private or pick a new
path. Devices and FIFOs (`/dev/stdout`, a named pipe) are not accepted;
use `--data-socket` for a live consumer. A record that fails to reach
the file (full disk) is counted and the first failure is printed to
stderr; writing continues.

**Read-only on the socket.** Sloth never reads from a connected
client. The protocol is one-way; there is no handshake, no auth, no
verbs. Access control is the caller's job (bind address, file
permissions on the UNIX socket, Tailscale ACLs).

**Delivery: whole records or none (#93).** The socket writer never
blocks sloth. Each client has its own queue of *complete* encoded
records (payload + `\n`, up to 512 KiB of unsent bytes on top of the
kernel send buffer), written from a saved byte offset. A record that
has started going out is always finished before the next one starts,
so a slow client receives late records, not glued or truncated ones.
When that client falls far enough behind:

| Condition | What sloth does | What the consumer sees |
|-----------|-----------------|------------------------|
| queue would exceed 512 KiB | drops the **incoming** record whole and counts it; a record already on the wire is never dropped | a `socket_gap` record before the next record it does receive (below) |
| no byte accepted for 30 s while bytes are queued | closes the connection | EOF, possibly after an unterminated fragment |
| `send()` error other than `EAGAIN`/`EINTR`, or `0` | closes the connection | EOF, possibly after an unterminated fragment |

The 30 s stall timer restarts on every byte the kernel takes, so a
client that is slow but draining stays connected (and sees gaps); only
one that has stopped reading is cut. It exists because a peer that
stops reading can hold a TCP window shut indefinitely without ever
producing `EPIPE`. Idle clients — nothing queued — are never timed out.

**Detecting loss.** A per-client sequence number counts every record
offered to that connection, delivered or dropped. It is carried by the
socket-only [`socket_gap`](#socket_gap-socket-only) record, which sloth
queues directly ahead of the first record delivered after a drop. For
every marker, *records received on this connection before it* +
*sum of `dropped` over all markers so far* = its `seq`. A connection
that never overflows never sees a marker, so the record types it
receives are unchanged by #93. The process-wide count is
`data_socket_dropped_total()`.

Reconnect to resume after a disconnect: a new connection starts on a
record boundary with `seq` 0, and gets a fresh baseline of snapshot
rows (#47). Records emitted while disconnected are gone — pair the
socket with `-o FILE` if you need them.

**Framing.** Newline-delimited JSON (NDJSON / JSONL). Every line is
one complete JSON object terminated by exactly one `\n`. There is no
record separator beyond the newline; consumers split on `\n` and
parse each line. Bytes after the last `\n` when the socket reaches EOF
are the head of a record sloth could not finish — discard them, never
parse them as a record.

## Output format

`--out-format FORMAT` selects the line encoding for both `-o` and
`--data-socket`. The internal record builder always produces JSONL;
non-JSONL formats are a transform applied at the single emit point.

| Format   | Use when |
|----------|----------|
| `jsonl`  | default. Native; consumers parse with any JSON lib |
| `cef`    | ArcSight / Micro Focus SIEMs that natively ingest CEF — single-line per record, severity mapped 0-10 |
| `syslog` | RFC 5424 syslog (forward via local syslogd / rsyslog / journald to most SIEMs). Original JSON is preserved as the MSG field for fidelity |

**`cef`** layout:

```
CEF:0|sloth-net|sloth|1|<type>|<type>|<sev>|key=val key=val …
```

- Fixed vendor/product/version cells.
- `SignatureID` and `Name` both carry the record `type` (`dns`,
  `alert`, `beacon`, …) — most ingest pipelines key on either.
- Severity 0-10 derived from the alert `sev` field for alert records
  (0=LOW→3, 1=WARN→6, 2=CRIT→9); other record types use the default
  severity 3.
- Extensions follow CEF escaping (`=` → `\=`, `\` → `\\`,
  newlines/tabs replaced with space).
- Nested arrays/objects (e.g. beacon's `neighbors`) are stringified
  as their raw JSON syntax in the extension value — preserves the
  structure for downstream parsing without inventing a CEF list
  encoding.

**`syslog`** layout (RFC 5424):

```
<134>1 <RFC3339 ts> <hostname> sloth <pid> <type> [sloth@32473 k="v" …] <original JSON line>
```

- PRI = 134 (local0.info).
- Hostname comes from `gethostname()`; spaces replaced with `-` to
  keep the header well-formed.
- MSGID = record type.
- Structured-data uses the private enterprise number `32473` (the
  IANA-allocated example PEN) under SD-ID `sloth@32473`. Replace
  with your own allocation if you need cross-organisation
  parseability.
- The MSG part is the original JSONL line so a parser that knows
  about sloth can recover full fidelity (nested arrays and all).
  SD-PARAM values intentionally exclude nested arrays/objects —
  RFC 5424 forbids them inside SD-PARAM, and the MSG preserves them.

## Common envelope

Every record has:

| Field | Type   | Notes |
|-------|--------|-------|
| `type` | string | record class (`dns`, `tls`, `quic`, `http`, `ntp`, `icmp`, `alert`, and the `alert.create` / `alert.update` / `alert.escalate` / `alert.resolve` lifecycle family added in #98) |
| `ts`   | int    | Unix timestamp in seconds. Per-record meaning: observation time for protocol logs, last-evaluated time for alerts, transition time for alert lifecycle events |

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
| `ja4`  | string | 36-char JA4 client fingerprint (FoxIO spec); survives extension reordering that breaks JA3. Omitted when not computed. |

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
{"type":"http","ts":1700000003,"src":"10.0.0.5","host":"example.com","method":"GET","path":"/index.html","ja4h":"ge11nn020000_8daaf6152771_000000000000_000000000000"}
```

| Field    | Type   | Meaning |
|----------|--------|---------|
| `src`    | string | client IP |
| `host`   | string | `Host:` header value, port stripped |
| `method` | string | `GET` / `POST` / … |
| `path`   | string | request URI |
| `ja4h`   | string | 49-char JA4H client fingerprint (FoxIO spec). Omitted when not computed. See [[../views/http]] for the section breakdown. |

**Response records (#71).** The same record type carries responses,
distinguished by the presence of `status`. `host` and `path` are the
*request's*, filled in by pairing — absent when the response could not
be confidently paired.

| Field | Type | Meaning |
|-------|------|---------|
| `status` | int | HTTP status code |
| `content_length` | int | the declared length, or `-1` when the header was absent |
| `chunked` | int | 1 = `Transfer-Encoding: chunked`, which sloth does **not** decode |
| `body_complete` | int | **key on this before comparing bytes.** 1 = the whole declared body was captured; 0 = a prefix, or none |
| `body_len` | int | bytes actually captured, bounded at 512 |

`body_complete` is the field that matters. sloth does not reassemble
TCP, so a body larger than the segment carrying its status line arrives
short. **"Different" and "incomplete" are different answers**, and a
partial body that happens to differ from an expected value is not
evidence of anything. A consumer doing a byte-exact comparison must
compare only when `body_complete` is 1 and treat 0 as "don't know".

The body itself is not emitted: it can be page content of any kind, and
the forensic value is in the status and the completeness.

### `ntp`

```json
{"type":"ntp","ts":1700000004,"src":"10.0.0.1","dst":"192.168.1.5","mode":"server","version":4,"stratum":1,"ref":"GPS"}
```

`version` and `stratum` are integers.

### `icmp`

```json
{"type":"icmp","ts":1700000005,"src":"192.168.1.5","dst":"8.8.8.8","desc":"Echo Req","ty":8,"code":0,"seq":42,"plen":56,"v6":0}
```

`ty`, `code`, `seq`, `plen`, `v6` are integers (`v6=1` for ICMPv6).
`plen` is the payload length in bytes past the 8-byte ICMP header — the
signal the `ICMP_TUNNEL` rule keys on (added #40; older records omit it).

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
| `count` | int    | **rule evaluations** under this dedup key — see the note below. Always `1` on this record, which is emitted only when the key is new |
| `technique` | string | MITRE ATT&CK technique ID (e.g. `T1110.001`). Omitted for host-posture alerts (`NO_MONITOR_MODE`). |
| `confidence` | int | additive, #89 — how likely the finding is to be **true**, in percent (5..95). A separate axis from `sev`, which is how **bad** it would be if true. **Omitted** when the rule reported none: most rules assert a condition they observed directly and have nothing to qualify, and a literal `0` would read as "certainly false". Emitted today by the `EVIL_TWIN` family |
| `inventory` | string | additive, #89 slice 2 — 16 hex chars, the content hash of the approved inventory this finding consulted (`--inventory`, see [[inventory]]). **Omitted** when the rule consulted none; stamping every record would assert the anchor backed findings it never touched. Present on the `EVIL_TWIN` family when an inventory is loaded |
| `incident_id` | string | additive, #98 — 16 hex chars identifying the incident this record opens. Join key into the `alert.*` lifecycle records below |

`ts` for alerts is the `last_seen` time of the dedup key, not the
first observation.

**`sev` and `confidence` are two axes, not one scale** (#89). Severity
is the consequence if the finding is real; confidence is the likelihood
that it is. A CRIT at 20 % and a WARN at 25 % are both meaningful and
neither dominates the other — an operator triaging needs the pair.
Collapsing them is what let an uncorroborated same-SSID RF coincidence
page at the same volume as an observed attack. Rules that infer from
circumstantial evidence report both; rules that assert what they
directly saw omit `confidence` entirely.

**`inventory` makes a finding reproducible** (#89 slice 2). The approved
inventory is the one evil-twin trust input that does not arrive over the
air, so a record that was shaped by it has to say *which* file that was.
The hash is over the file's bytes, which means a whitespace-only edit is
a different inventory — the question the field answers is "which file
did sloth read", not "were the semantics equivalent". The human-readable
`version` string inside the file cannot serve as this identity, because
nothing stops two files from both claiming `2026-09-24.1`; it is printed
at startup beside the hash and is a label only. Full semantics:
[[inventory]].

**Dedup keys for paired findings are canonical** (#89). Where a finding
is about a *pair* of BSSIDs rather than one host, the key is
`<rule_id>:<bssid_lo>:<bssid_hi>:<site>:<security_profile>` with the two
BSSIDs in byte order, so `(A,B)` and `(B,A)` are one incident. The
`EVIL_TWIN` keys `twin:` and `twin-fp:` took this shape in #89; they
previously ended in the SSID, which collapsed every BSSID pair under one
name into a single record. `site` is the operator's label for where the
sensor is; since #89 slice 2 it is populated from `--site` or the
inventory file's `site` field, and stays **empty** when neither is
given. It is never derived from an observed SSID, a BSSID or the uplink
association — a trust input taken from unauthenticated over-the-air data
is the defect #89 exists to remove, and a site that re-keyed on every
roam would split one impersonator across several incidents. A consumer
that treated the old key as opaque is unaffected; one that parsed the
SSID out of it must read `detail` or the `beacon` records instead.

**This record is emitted only when the dedup key is new.** That has
always been true and #98 did not change it: everything that happens to
an alert *after* it is created — escalation, changed evidence,
expiry — is carried by the `alert.*` lifecycle records below. A
consumer that reads only `alert` sees exactly what it saw before #98,
plus the additive `incident_id`.

**What `count` means.** It counts **rule evaluations**, not packets,
not attacks, and not independent incidents. Every rule re-derives its
condition from retained state once per poll (~1 Hz), so a single
condition that stays true for an hour reaches `count` in the
thousands. #98 named this rather than changing it, because the TUI,
the `--db` `alerts` table and existing consumers all read the field.
Use `observations` on the lifecycle records when you want "how many
times did the evidence actually move".

### `alert.create` / `alert.update` / `alert.escalate` / `alert.resolve`

Added in #98; purely additive — four new record types, no change to any
existing field. A consumer that ignores unknown `type` values keeps
working unchanged.

```json
{"type":"alert.create","ts":1700000006,"event_id":"9f2c41ab77e30d58-0001","incident_id":"9f2c41ab77e30d58","key":"mgmtfuzz:ba:ad:f0:0d:00:01","title":"MGMT_FUZZ","detail":"BSSID ba:ad:f0:0d:00:01 malformed IEs: 3 overrun / 0 oversize-SSID / 0 truncated-RSN - 802.11 mgmt fuzzing","sev":1,"ty":31,"observations":1,"evaluations":1,"count":1,"first_detected":1700000006,"last_evaluated":1700000006,"first_observed":1700000006,"last_observed":1700000006,"technique":"T1499"}
{"type":"alert.escalate","ts":1700000041,"event_id":"9f2c41ab77e30d58-0002","incident_id":"9f2c41ab77e30d58","key":"mgmtfuzz:ba:ad:f0:0d:00:01","title":"MGMT_FUZZ","detail":"...5 overrun...","sev":2,"ty":31,"prev_sev":1,"observations":2,"evaluations":36,"count":36,"first_detected":1700000006,"last_evaluated":1700000041,"first_observed":1700000006,"last_observed":1700000041,"technique":"T1499"}
{"type":"alert.resolve","ts":1700000341,"event_id":"9f2c41ab77e30d58-0003","incident_id":"9f2c41ab77e30d58","key":"mgmtfuzz:ba:ad:f0:0d:00:01","title":"MGMT_FUZZ","detail":"...","sev":2,"ty":31,"observations":2,"evaluations":36,"count":36,"first_detected":1700000006,"last_evaluated":1700000041,"first_observed":1700000006,"last_observed":1700000041,"technique":"T1499","reason":"expired"}
```

**Why they exist.** Before #98 a WARN→CRIT transition updated sloth's
engine in place and emitted nothing. A consumer paging on CRIT never
saw the escalation — the only record it ever got for that alert was
the `alert` line written when the key was first created, at WARN.

**An incident** is one continuous run of a dedup key. It opens with
exactly one `alert.create`, carries one `incident_id` through every
`alert.update` and `alert.escalate`, and closes with exactly one
`alert.resolve`. A key that fires again after its resolve opens a
**new incident with a new `incident_id`** — the engine slot is reused,
the identity is not.

| Record | Fires when |
|--------|-----------|
| `alert.create` | a dedup key not currently open fires. Once per incident. Accompanied by the legacy `alert` record |
| `alert.escalate` | severity **increased** on an open incident (e.g. WARN→CRIT). Never throttled |
| `alert.update` | severity **decreased**, or the rendered evidence (`detail`) changed. Evidence-only updates are rate-limited to **one per 60 s** per incident |
| `alert.resolve` | the incident closed. Once per incident, never repeated |

The lifecycle records carry `confidence` and `inventory` on the same
terms as the legacy `alert` record: both are additive, both are omitted
when the rule reported none, so a lifecycle-only consumer never has to
read both families to get them.

**Material change, never a poll.** An evaluation that re-renders
identical evidence emits nothing, however long the condition persists:
a retained condition re-evaluated across 100 polls produces one
`alert.create` and nothing else. When a rule's detail does carry a live
counter, the 60 s floor bounds the update rate; the event that does
fire carries the *current* detail, so suppressed intermediate
renderings are summarised rather than lost. Severity transitions are
never throttled, in either direction — severity is what consumers page
on.

**The resolve rule.** An incident resolves when **no rule re-asserted
its key for 300 s** (`ALERT_RESOLVE_AFTER_S`). The test is
`last_evaluated`, not `last_observed`: rules re-derive their conditions
from retained state every poll, so a key that stops being *evaluated*
is one whose evidence aged out of the source ring — the condition is
gone. Keying on `last_observed` instead would resolve a standing
condition that is still true (`NO_MONITOR_MODE` renders the same detail
forever) and immediately re-create it, producing a resolve/create pair
every five minutes for nothing. 300 s matches
`JSONL_HEARTBEAT_SECS`, so "is this incident still live?" has the same
horizon as every other entity in the stream. The clock is
**CLOCK_MONOTONIC** (the #88 seam in `src/flood_window.c`): an NTP step
or a manual `date` must neither resolve a live incident nor hold a dead
one open. Every *timestamp* in these records is wall clock — evidence,
not duration.

`reason` appears only on `alert.resolve`:

| `reason` | Meaning |
|----------|---------|
| `expired` | no rule re-asserted the key for 300 s |
| `evicted` | the engine hit `MAX_ALERTS` (128) and reclaimed this slot. Resolved incidents are evicted first, so a live one is dropped only when all 128 are live |
| `cleared` | the operator pressed `c` in the TUI. Every open incident closes — leaving them open would strand a consumer waiting for a resolve that can never come |

| Field | Type | Meaning |
|-------|------|---------|
| `event_id` | string | unique per event: `<incident_id>-<4-digit per-incident sequence>`, starting at `0001` and increasing in emission order |
| `incident_id` | string | 16 hex chars, stable for the whole incident. Opaque — FNV-1a over the dedup key, the detection time and a process-wide counter. Collision-resistant, not a UUID, and not stable across sloth restarts |
| `key` | string | the dedup key, same value as on the `alert` record |
| `title`, `detail`, `sev`, `ty`, `technique`, `match_ip`, `match_port` | | same meaning as on the `alert` record; `detail` and `sev` are the **current** values at the moment of the event. `match_ip`/`match_port` are omitted when the rule has no single flow |
| `prev_sev` | int | severity before the transition. Present on `alert.escalate` and on severity-decrease `alert.update` only |
| `observations` | int | evaluations whose rendered evidence differed from the previous one. A retained condition re-evaluated unchanged does **not** move this. It is the honest answer to "how many distinct observations", which `count` never was — but it is not a packet count either: sloth's rules read retained state, not frames |
| `evaluations` | int | rule ticks under this key, i.e. what `count` has always counted |
| `count` | int | identical to `evaluations`, carried so a lifecycle-only consumer never has to read both record families |
| `first_detected` | int | wall clock when the incident opened |
| `last_evaluated` | int | wall clock of the most recent rule tick. Same value as `last_seen`/`ts` on the legacy record |
| `first_observed` | int | wall clock of the first counted observation (== `first_detected`) |
| `last_observed` | int | wall clock of the most recent counted observation |
| `reason` | string | resolve cause; `alert.resolve` only |

These are ordinary records: they go to `-o FILE` and every
`--data-socket` client alike, and under `--out-format cef` or `syslog`
each type is its own CEF signature / syslog MSGID (`alert.escalate`,
…), with `sev` mapped to CEF severity exactly as on `alert`.

**Not in `--db`.** The lifecycle is a stream contract; the `alerts`
table is unchanged and `DB_SCHEMA_VERSION` is still 4. An existing
database file stays readable.

**Known gap (#89).** Two distinct evil-twin pairs advertising one SSID
still collapse into one incident, because `rule_evil_twin` keys on
`twin:<ssid>` alone. The lifecycle layer never merges across keys — it
will produce two incidents the moment the key does — but re-keying the
twin rules is F07 / issue #89 and was deliberately not done in #98.

### `cleartext_cred`

```json
{"type":"cleartext_cred","ts":1700000008,"src":"10.0.0.5","dst":"192.0.2.10","dst_port":80,"protocol":"HTTP-Basic","username":"alice","pw_observed":1}
```

| Field         | Type   | Meaning |
|---------------|--------|---------|
| `src`         | string | client IP that emitted the credential |
| `dst`         | string | server IP that received it |
| `dst_port`    | int    | server port (80 for HTTP Basic, 21 for FTP, …) |
| `protocol`    | string | `HTTP-Basic`, `FTP`, `POP3`, `IMAP`, `SMTP`, `Telnet` |
| `username`    | string | observed username, sanitized to printable ASCII |
| `pw_observed` | int    | 1 if a password token was seen on the wire, 0 otherwise |

**Guardrail — no password field, ever.** This event class records the
*fact* of a cleartext credential exposure and the username. The
password value is never stored, hashed, or truncated: `src/cleartext_creds.c`
has no code path that touches password bytes, and the JSONL schema
has no field for it. Adding one would be a scope violation on
sloth's passive-observation contract — see MISSION.md §2.

**Cadence**: event — one record per unique
`(src, dst, dst_port, protocol, username)` tuple. Repeat observations
coalesce on the ring side. Also feeds `CLEARTEXT_CRED` in the alert
stream (ATT&CK T1040).

### `connections`

```json
{"type":"connections","ts":1700000007,"src":"10.0.0.5:49152","dst":"93.184.216.34:443","proto":"tcp","state":"ESTABLISHED","rtt_ms":12.4,"retx":0,"rx_bytes":12345,"tx_bytes":6789}
```

| Field      | Type   | Meaning |
|------------|--------|---------|
| `src`      | string | local endpoint `host:port`; IPv6 is bracketed (`[fe80::1]:54321`) |
| `dst`      | string | remote endpoint `host:port`; IPv6 is bracketed |
| `proto`    | string | `tcp` or `udp` |
| `state`    | string | TCP state name (`ESTABLISHED`, `SYN_SENT`, …). **TCP only** — omitted for UDP |
| `rtt_ms`   | float  | smoothed RTT in milliseconds. **TCP only** — omitted when `rtt_us==0` (unknown) or proto is UDP |
| `retx`     | int    | total retransmissions on the flow. **TCP only** — omitted for UDP |
| `rx_bytes` | int    | cumulative bytes received since first observation (0 when pcap is off) |
| `tx_bytes` | int    | cumulative bytes transmitted since first observation (0 when pcap is off) |

**Cadence**: snapshot — one record per active flow per poll tick (≈1 Hz).
The consumer rebuilds its table from the latest snapshot keyed by
`(src, dst, proto)`. No event ring; no dedup; closed flows simply stop
appearing.

`ts` is the wall-clock time of the snapshot, not first observation. Age
of a flow is derivable client-side from the first record a consumer
sees for a given `(src, dst, proto)` tuple.

### `twin_episode`

```json
{"type":"twin_episode","ts":1700000007,"ssid":"Cafe-Net","real_bssid":"aa:bb:cc:01:02:03","twin_bssid":"11:22:33:44:55:66","enc":"WPA2","real_rssi":-70,"twin_rssi":-45,"rssi_swing_dbm":25,"attack_in_progress":1,"attacker_oui":1,"hash_mismatch":1,"attributed":1,"confidence":60}
```

| Field                | Type   | Meaning |
|----------------------|--------|---------|
| `ssid`               | string | shared SSID |
| `real_bssid`         | string | when `attributed` is 1, the legit AP's BSSID (lowercase hex); when 0, simply the lower of the two BSSIDs |
| `twin_bssid`         | string | when `attributed` is 1, the suspected-rogue AP's BSSID; when 0, simply the higher of the two — **not an accusation** |
| `enc`                | string | shared encryption mode (`WPA2`, `WPA3`, …) |
| `real_rssi`          | int    | last observed signal of the real AP (dBm; 0 = unseen) |
| `twin_rssi`          | int    | last observed signal of the twin AP |
| `rssi_swing_dbm`     | int    | max RSSI swing on the twin in last 60 s (0 = unseen) |
| `attack_in_progress` | int    | 1 if the chain rule tainted `twin_bssid` (DEAUTH_FLOOD seen within 5 s) |
| `attacker_oui`       | int    | 1 if `twin_bssid`'s OUI is Hak5 or Espressif |
| `hash_mismatch`      | int    | 1 if the vendor-IE fingerprint hashes disagree |
| `attributed`         | int    | additive, #89 — 1 when something other than radio physics established which half is the impostor (an operator-designated BSSID, a tainted BSSID from the deauth chain, or an attacker-tool OUI). **0 means unattributed**: the pair is a candidate and the two BSSID fields are only in canonical byte order |
| `confidence`         | int    | additive, #89 — same percentage the pair's `EVIL_TWIN` alert carries |

**Cadence**: snapshot — one record per detected pair per poll (≈1 Hz).
The consumer rebuilds its table from the latest snapshot keyed by
`(ssid, real_bssid, twin_bssid)`. When a pair stops appearing on the
RF, its records simply stop arriving — there's no explicit "closed"
record.

**"Real" vs "twin" assignment.** Ranked by what the signal actually
establishes: an operator-designated BSSID (#52) is never the impostor;
then a BSSID `rule_evil_twin_attack_chain` has tainted; then an OUI in
the Hak5 / Espressif attacker tables. Any of those sets
`attributed: 1`. With none of them the pair is **unattributed**
(`attributed: 0`) and the two BSSID fields hold it in canonical byte
order — a stable identity for the pair, not a verdict on either half.

Before #89 the fallback was "the stronger signal is the impostor". RSSI
is not ownership: it is a fact about distance and antennas, and in the
commonest case it is backwards, because the operator's own AP is the
closest radio in the room. A consumer that read `twin_bssid` as an
accusation must now gate on `attributed`. The canonical order is also
why the `(ssid, real_bssid, twin_bssid)` key is now stable — it used to
swap, and so duplicate, whenever the two RSSIs crossed.

## State snapshot record types

These records carry the current contents of each view-backing table.
**Snapshot semantics — one record per entry per poll**, emitted by
`jsonl_emit_state_snapshots()` after `poll_data()` finishes. Consumers
(the iOS client; any other view-rebuilding consumer) reconstruct the
table from the latest snapshot keyed by the natural-identity field
indicated below. Late-joining clients pick up state on the next tick.

**Change-only emission (issue #42).** The high-volume snapshot types are
not re-serialised every tick when nothing about a row changed. Each row
is reduced to a 64-bit signature over its identity + observation fields
(everything except the envelope `ts`); a row is written only when it is
new, its signature changed, or `JSONL_HEARTBEAT_SECS` (300 s) have
elapsed since it was last emitted. This suppresses the idle-repeat
firehose (≈45 % of production volume was unchanged `seqnum_client` /
`pnl_client` rows) while the heartbeat guarantees every live entity still
refreshes at least every 5 minutes, so windowed queries ("who was here
2–4 AM?") keep working. Consumers see fewer rows but the same
latest-state-per-key reconstruction; the cache resets on sink (re)open so
a fresh file always starts with a full baseline.

A data-socket client that connects mid-run is a fresh sink in the same
sense, and resets the cache too (issue #47) — otherwise it would see only
what happens to change after it connects, and steady-state entities would
stay invisible to it until their next 5-minute heartbeat. The reset is
per *accept*, not per tick, so a reconnecting tailer always re-syncs; the
cost is one redundant baseline re-broadcast to any clients already
attached, which consumers already tolerate from the heartbeat. Currently applied to
`pnl_client` and `seqnum_client`; other snapshot types follow the same
pattern as they are converted.

| Record               | Identity key      | Fields |
|----------------------|-------------------|--------|
| `iface`              | `name`            | `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `rx_drops`, `tx_errors`, `tx_drops`, `rx_rate`, `tx_rate`, `mtu`, `speed_mbps` |
| `arp`                | `mac`+`ip`        | `mac`, `ip`, `iface` |
| `dhcp_lease`         | `ip`              | `ip`, `hostname`, `expire` (epoch; 0 = unknown) |
| `wifi_ap`            | `bssid`           | `ssid`, `bssid`, `signal_dbm`, `channel`, `enc`, `status` |
| `wifi_sta`           | `mac`             | `mac`, `signal_dbm`, `tx_rate_kbps`, `rx_rate_kbps`, `connected_secs`, `inactive_ms`, `tx_bytes`, `rx_bytes` |
| `top_host`           | `ip`              | `ip`, `hostname`, `owner`, `first_seen`, `last_seen`, `conn_count`, `rx_rate`, `tx_rate`, `rx_bytes`, `tx_bytes` |
| `device`             | `mac`             | `mac`, `ip`, `hostname`, `vendor`, `last_ssid`, `is_ap`, `signal_dbm`, `probe_count`, `sources` (bitmask of `DEV_SRC_*`), `last_seen` |
| `beacon`             | `bssid`           | `ssid`, `bssid`, `signal_dbm`, `channel`, `enc`, `beacon_ms`, `pairwise`, `group`, `akm`, `mfp` (0/1/2), `vendor`, `has_wps`, `wps_state`, `wps_locked`, `wps_config_methods` + `wps_device_pwd_id` (additive, #82 — raw WPS IE attributes 0x1008/0x1012; `0` means not observed for both, `0x0004` on the latter means an active Push-Button session right now; live, not sticky — reflects only the most recent beacon; not persisted to `--db`; see `docs/views/beacons.md`), `phy`, `revealed`, `last_seen`, `frame_count`, `fp_flags` (`AP_FP_FLAG_*` bitset), `vendor_ies_hash`, `ie_order_hash` + `ie_order_count` (additive, #77 — FNV-1a over beacon element identity in order, bodies excluded, transient CSA/Quiet elements skipped; `0` = not decoded; see `docs/views/beacons.md`), `rssi_min_60s`, `rssi_max_60s`, `ssid_history[]`, `neighbors[{bssid, channel, phy_type}]`, `fuzz_ie_overruns`/`fuzz_oversize_ssid`/`fuzz_truncated_rsn` (malformed-IE counters, emitted only when non-zero — feed the `MGMT_FUZZ` alert), `downgrade_flags` (`WPA_DG_*` bits — the weaker lanes this AP advertises beside its primary one, #62), `akm_bits` (00-0F-AC suite-type bitmap; the `akm` string above caps at three entries and cannot answer "PSK and SAE both?"), `operating_width` (MHz — 20/40/80/160/320, or 8080 for non-contiguous 80+80; **0 means not decoded**, which is not the same as 20, #66), `primary_channel` + `channel_source` (1=DS-Param 2=HT-Oper 3=HE-6GHz 4=EHT-Oper — much 6 GHz gear omits DS Param entirely, so this says where the number came from), `secondary_offset` (HT convention: 0 none, 1 above, 3 below), `wps_manufacturer`/`wps_model_name`/`wps_model_number`/`wps_serial` (additive, #77 — WPS IE vendor-string attributes when the beacon leaks them, `""` when absent; not persisted to `--db`, see `docs/views/beacons.md`), `tbtt_jitter_us` + `tbtt_jitter_samples` + `tbtt_jitter_resets` (additive, #77 — standard deviation in µs of the residual between the observed TSF delta and the nearest whole multiple of the beacon interval, i.e. the AP's own medium-access deferral measured on the AP's clock; `0` µs with `0` samples means not enough beacons, not a perfectly-scheduled AP, so read the pair together; `resets` counts baselines discarded on a TSF that ran backwards, a changed beacon interval, or a gap past `BEACON_AGE_SECS`; monitor-mode only, no threshold or verdict attached, not persisted to `--db`, see `docs/views/beacons.md`) |
| `deauth`             | `bssid`+`src`+`dst`+`subtype` | `src`, `dst`, `bssid`, `reason`, `subtype`, `first_seen`, `last_seen`, `count`, `flood`, plus (additive, #88) `reason_valid` (**`reason` is meaningless when 0** — a PMF-protected body is ciphertext, a truncated one has no field), `retries` / `protected` / `truncated` (subsets of `count`; retries are Retry-bit repeats of the previous sequence number and do not count toward a flood), `flood_last` (epoch the 5-frames-in-5-s window threshold was last met; 0 = never). `flood` is *current* and decays 10 s after `flood_last`. The identity was documented as `bssid`+`dst` but rows were keyed `(src, dst)` with the BSSID overwritten; since #88 it is the four fields shown. `src` is the claimed transmitter — spoofable. The alert-driving `(BSSID, victim)` aggregate is not a JSONL record; it surfaces through the `DEAUTH_FLOOD` alert |
| `probe_client`       | `mac`             | `mac`, `ssid`, `signal_dbm`, `channel`, `first_seen`, `last_seen`, `frame_count` (lifetime, not a rate), plus (additive, #88) `flood` (decays), `flood_last` (epoch; 0 = never), `burst_frames` + `burst_span_ms` (the requests that met the 30-in-5-s threshold and the time between the first and last of them) |
| `pnl_client`         | `mac`             | `mac`, `mac_random`, `probe_count`, `os_fp`, `phy`, `phy_confirmed` (1 = the tier was corroborated by an association request rather than inferred from probes, #60), `first_seen`, `last_seen`, `ssids[]` |
| `seqnum_client`      | `mac`             | `mac`, `mac_random`, `last_seen`, `frame_count`, `hist[]` (12-bit seqnums in observation order) |
| `seqnum_correlation` | `mac_a`+`mac_b`   | `mac_a`, `mac_b`, `mac_a_random`, `mac_b_random`, `gap`, `dt_ms`, `a_count`, `b_count` |
| `channel_summary`    | `channel`         | `channel`, `ap_count`, `assoc_count`, `best_signal`, `top_ssid`, `ctrl_total` / `ctrl_rts` / `ctrl_cts` / `ctrl_ack` / `ctrl_blockack` (observed control-frame volume, #64 — the *measured* half of channel occupancy, as distinct from the QBSS Load IE an AP self-reports; per-channel because CTS and ACK carry no transmitter address), `last_seen` |
| `assoc`              | `bssid`+`sta_mac` | `bssid`, `sta_mac`, `ssid`, `sta_random`, `source` (`ASSOC_SRC_*`), `channel`, `signal_dbm`, `first_seen`, `last_seen`, `frame_count` |
| `wifi_assoc_req`     | `bssid`+`sta_mac` | what the client *asked* for (#60), beside the `assoc` grant: `requested_ssid`, `is_reassoc`, `listen_interval`, `capability_info`, `akm_bits`, `pairwise_bits` (00-0F-AC suite-type bitmaps — see `RSN_AKM_*`), `requested_mfp` (0/1/2), `supported_rates`, `phy`, `vendor_ie_hash`, `downgrade_flags` (`ASSOC_DG_*`), `prev_akm_bits`, `prev_mfp`, `last_seen` |
| `captive_portal_event` | `host`+`ts`     | connectivity-check interception (#69). `kind` is a `CP_KIND_*` bit — body hijack, DNS spoof, DNS unexpected, or TLS MITM — and they are independent signals, so which one fired tells a consumer how the portal gave itself away. `evidence` carries what was seen instead |
| `wifi_mld`           | `mld_mac`         | Wi-Fi 7 Multi-Link Devices (#67). `mld_mac` is the **stable identity**; `link_0_mac` … `link_n_mac` are the per-link addresses its radios use simultaneously. This is the mapping that stops one handset being counted as three devices — MLO defeats sequence-number correlation structurally, because an MLD's radios have independent sequence spaces and never correlate. `links_truncated` when more affiliated links were advertised than sloth holds |
| `rrm_beacon_request` | `bssid`+`sta_mac` | 802.11k survey activity (#61). `targeted_reqs` (named an SSID) and `broadcast_reqs` (did not) are **separate fields** because only the first is the signal — a request with no SSID subelement is ordinary steering. `reports_seen` is separate again: a reply is evidence a survey *succeeded*, not that one was attempted, and folding it in would let a chatty client incriminate its own AP. Plus `last_ssid`, `last_channel`, `measurement_mode` (0 passive, 1 active, 2 table) |
| `wifi_csa_event`     | `bssid`+`ts`      | channel-switch announcements (#63), every one — legitimate DFS included, since a consumer judging one needs the ordinary traffic around it. `ta` is the **real transmitter** and `bssid` the BSS it claims to speak for: a difference is the forgery signal and storing only one would erase it. Plus `new_channel`, `new_op_class` (0 when only tag 37 was present), `switch_mode` (1 = stop transmitting until the switch), `switch_count` (TBTTs), `source` (0=beacon 1=probe-resp 2=action), `from_channel` |
| `btm_request`        | `bssid`+`sta_mac` | 802.11v steering (#59). `req_count` is every BTM Request for the pair; `imminent_count` is the subset carrying Disassociation Imminent — **the field to key on**, since ordinary load balancing and a forced roam are otherwise the same record. Plus `request_mode`, `disassoc_timer` (beacon intervals), `validity_interval`, `candidate_count`, `candidates_truncated`, `candidate_0`…`candidate_n` (where the AP is pointing the client), `first_seen`, `last_seen` |
| `eapol`              | `bssid`+`sta_mac` | `bssid`, `sta_mac`, `ssid`, `event_ts`, `msg_num`, `has_pmkid`, `handshake_complete`, `signal_dbm`, `channel`. Three additive fields (#97) keep apart what one flag used to blur: `handshake_complete` is a **candidate message pair** — this M2 and a live M1 carry the same Key Replay Counter and landed within `EAPOL_PAIR_WINDOW_S` of each other, the only state a hashcat 22000 EAPOL record is exported from. `handshake_progress` (0-4) is how far M1..M4 got inside that attempt, reporting only. `assoc_evidence` is the one that means the AP committed to this client (M3, key install) — a consumer reading `handshake_complete` as "associated" was reading a half-exchange, since an M1 goes to whoever asks and an M2 can be replayed. `replay_counter_ok` records that the pairing was decided by an actual byte comparison. None of it is cryptographic verification: sloth never checks the MIC |
| `mdns_service`       | `instance`        | `instance`, `service`, `host`, `ip`, `port`, `last_seen` |
| `nbns_name`          | `name`+`ip`       | `name`, `ip`, `suffix`, `last_seen` |
| `ssdp_device`        | `usn`             | `ip`, `kind` (the SSDP `NT`/`ST` value; renamed from `type` to avoid colliding with the envelope's `type` field), `usn`, `location`, `nts`, `last_seen` |
| `scan_entry`         | `ip`              | `ip`, `port_count`, `first_seen`, `last_seen`, `flagged`, `ports[]` |
| `packet`             | `(ts_sec, ts_usec, src, dst)` | `ts_sec`, `ts_usec`, `src`, `dst`, `src_port`, `dst_port`, `proto`, `len`, `info`. Raw frame bytes are intentionally not emitted. |
| `process`            | `pid`             | `pid` (-1 = unresolved bucket), `proc`, `ppid`, `depth`, `conn_count`, `tcp_count`, `udp_count`, `tx_bytes`, `rx_bytes`, `tx_rate`, `rx_rate`, `ports[]`. Synthesis record — aggregated from `connections` by PID; lets consumers reproduce the Processes view without re-implementing the aggregation. |
| `ndp_ra`             | `src_ip`          | `src_ip` (IPv6 source — usually link-local), `src_mac` + optional (present iff RA carried a Source Link-Layer Address option), `cur_hop_limit`, `flags`, `router_lifetime` (seconds; 0 = NOT a default router), `prefixes[]` (formatted `addr/len`), `first_seen`, `last_seen`, `count`. IPv6 NDP Router Advertisement tracker — feeds the `ROGUE_RA` alert. NS/NA neighbor cache is not yet emitted; see `docs/wiki/ipv6-ndp.md` for the scope decision. |
| `smb_session`        | `(client_ip, server_ip, server_port)` | `client_ip`, `server_ip`, `server_port` (445 or 139), `dialect` (`SMB1` or `SMB2`; sticky to `SMB1` once observed), `first_seen`, `last_seen`, `count`. Feeds the `SMB1_USE` alert — sessions with `dialect == "SMB1"` are CRIT-flagged because SMBv1 has been deprecated since 2017 (EternalBlue / WannaCry). See `docs/wiki/smb-snoop.md`. |
| `kerb_event`         | `src_ip`          | `src_ip`, `as_req_count`, `as_rep_count`, `tgs_req_count`, `tgs_rep_count`, `preauth_required_count` (KRB-ERROR 25 — normal first-AS-REQ response), `preauth_failed_count` (KRB-ERROR 24 — password spray indicator), `principal_unknown_count` (KRB-ERROR 6 — username enumeration indicator), `error_other_count`, `first_seen`, `last_seen`. Feeds the `KERB_PREAUTH_BURST` alert when `preauth_failed_count` exceeds the spray threshold. See `docs/wiki/kerberos-snoop.md`. |
| `ldap_event`         | `src_ip`          | `src_ip`, `bind_count`, `bind_anon_count` (empty-DN binds), `search_count`, `search_ref_count` (SearchResultReference; referral leakage indicator), `first_seen`, `last_seen`. Feeds the `LDAP_SEARCH_FLOOD` alert when `search_count` exceeds the BloodHound / ldapdomaindump threshold. See `docs/wiki/ldap-snoop.md`. |
| `bgp_session`        | `(peer_a, peer_b)` | `peer_a` and `peer_b` (peering endpoints — sorted lexically so traffic in either direction folds to one record), `open_count`, `update_count`, `notification_count`, `keepalive_count`, `first_seen`, `last_seen`. Feeds the `BGP_NOTIFICATION_BURST` alert when `notification_count` exceeds the session-instability / hijack-precursor threshold. See `docs/wiki/bgp-snoop.md`. |
| `ssh_flow`           | `(src_ip, dst_ip)` | `src_ip` (SSH client), `dst_ip` (SSH server), `banner_count` (server-banner exchanges observed; one per TCP connection that reached the SSH handshake), `server_banner` (last RFC 4253 §4.2 banner string seen — `SSH-2.0-OpenSSH_8.9` etc., truncated at CR/LF or non-printable), `first_seen`, `last_seen`. Feeds the `SSH_BRUTE_FORCE` alert when `banner_count` exceeds the hydra/medusa/ncrack threshold. See `docs/wiki/ssh-snoop.md`. |
| `rdp_flow`           | `(src_ip, dst_ip)` | `src_ip` (RDP client), `dst_ip` (RDP server), `connect_req_count` (X.224 Class 0 CR TPDUs observed; one per TCP connection that reached the RDP negotiation), `last_cookie` (last `mstshash=` username seen in the Cookie field — the username the attacker is guessing against), `proto_mask` (bitwise-OR of requested protocols across all CRs on the flow; 0x01=RDP, 0x02=SSL, 0x04=HYBRID/NLA, 0x08=HYBRID_EX), `first_seen`, `last_seen`. Feeds the `RDP_BRUTE_FORCE` alert when `connect_req_count` exceeds the xfreerdp-loop/NLBrute threshold. See `docs/wiki/rdp-snoop.md`. |
| `snmp_flow`          | `(src_ip, dst_ip)` | `src_ip` (querier — flipped from packet direction so responses attribute back to the original requester), `dst_ip` (agent), `version` (0=v1, 1=v2c, 3=v3), `get_count`, `getnext_count`, `getbulk_count`, `set_count` (rare — write attempts are a post-exploit signal), `response_count`, `trap_count`, `community_count` (distinct community strings seen, capped at 8), `last_community` (most recent community string — sanitised to printable ASCII, dropped if it contained non-printable bytes), `first_seen`, `last_seen`. Feeds the `SNMP_COMMUNITY_BRUTE` alert when `community_count` exceeds the snmpwalk-wordlist threshold. See `docs/wiki/snmp-snoop.md`. |
| `mqtt_flow`          | `(src_ip, dst_ip)` | `src_ip` (MQTT client — flipped on CONNACK so the conversation stays attributed to the client), `dst_ip` (broker), `connect_count` (CONNECT packets observed), `connack_fail_count` (CONNACK reason codes that mean bad-auth / not-authorised), `subscribe_count`, `publish_count`, `proto_level` (3 / 4 / 5 from the most recent CONNECT), `last_username` (Username field from the most recent CONNECT — sanitised to printable ASCII, dropped if it contained non-printable bytes), `first_seen`, `last_seen`. Feeds the `MQTT_BROKER_BRUTE` alert via dual thresholds (`connect_count ≥ 10` OR `connack_fail_count ≥ 5`). See `docs/wiki/mqtt-snoop.md`. |
| `sensor`             | `kind`+`iface`    | `kind` (`wifi`/`ble`/`zigbee`/`sdr`/`gps`/`adsb`/`meshtastic`/`can`), `state` (`present`/`active`/`hidden`/`error`), `name`, `iface`, `observed` (cumulative observation count), `first_seen`, `last_seen`. The passive sensor registry — one record per detected observation source. See `docs/wiki/non-ip-sensors.md`. |
| `wifi_merged`        | `key`             | `key` (observed entity — AP BSSID or STA MAC), `seen_by` (distinct radios that heard it), `sensor_mask` (bitmask, bit *i* = sensor id *i*), `best_rssi` (strongest signal in dBm across radios; 0 = none sampled), `best_sensor` (radio id that heard it strongest; -1 = none), `channel`, `freq_mhz`, `observations` (total merged hits), `first_seen`, `last_seen`. Multi-radio merged 802.11 world model — folds several monitor adapters into one entity-keyed view while retaining observer metadata. See `docs/wiki/wifi-sigint.md`. |
| `sensor_health`      | *(singleton)*     | The sensor's own state rather than an observation — one line per tick, not one per table row (#91). Monitor radio's requested vs **confirmed** channel plus lifetime retune failures; both capture workers' `_open`/`_running` liveness, the classified `_exit` reason and libpcap's raw `_exit_detail`; `pcap_stats()` lifetime totals and per-tick deltas for received / libpcap-dropped / NIC-dropped; and the bounded-table eviction tally. `_open` 1 with `_running` 0 is a dead capture thread behind a still-open handle — the case that used to be indistinguishable from a quiet segment. Change-only with a 300 s heartbeat. Full field list and the eviction tally's coverage limits in the section below. |

### `sensor_health` — the sensor's self-report (#91)

Every record above answers "what did sloth see". This one answers "was
sloth able to see". It is the only **singleton** record in the stream:
one line per tick describing the collector itself, not one line per row
of a table.

It exists because "healthy with no detections" and "not observing" were
indistinguishable to a consumer. A capture thread that died left its
pcap handle open and its tables static; a `--hop` retune that failed
left the UI on the intended channel; NIC and libpcap drops were never
read at all. All three look exactly like a quiet segment, and a quiet
segment is the normal state of a well-placed sensor — so the absence of
records carried no information either way.

**Additive.** A new record type. No existing record, field or field name
changes, so nothing downstream breaks (MISSION §4.3). A consumer that
does not know the type ignores it, as it would any other.

| Field | Meaning |
|-------|---------|
| `capture_iface` | device the IP data-stream handle is bound to (`any`, or a fallback device name); `""` = capture never opened |
| `monitor_iface` | the 802.11 monitor radio; `""` = none found |
| `monitor_err` | last monitor open/retarget error, `""` = none |
| `chan_requested` | channel `--hop` last asked the radio for; `0` = the hopper has never ticked |
| `chan_confirmed` | channel the platform last **acknowledged** — where the radio actually is |
| `chan_confirmed_ok` | `1` when those agree (or nothing has been requested yet), `0` on a live unconfirmed retune |
| `chan_retune_failures` | lifetime failed `set_channel()` calls; never reset, so a flapping radio stays visible |
| `capture_*` / `monitor_*` | the per-stream block below, once for each of the two handles |
| `evictions` | total observations discarded by a full bounded table, lifetime |
| `evict_alert`, `evict_top_host`, `evict_pnl_client`, `evict_pnl_ssid`, `evict_dhcp_event`, `evict_eap_session`, `evict_device` | the same total broken out per table |

Per-stream block, with `<s>` being `capture` or `monitor`:

| Field | Meaning |
|-------|---------|
| `<s>_open` | a pcap handle exists |
| `<s>_running` | the worker thread is dispatching. **`_open` 1 with `_running` 0 is the failure mode this record was added for** — an open handle behind a dead thread |
| `<s>_exit` | why the worker ended: `none` (still running), `stopped` (clean shutdown), `iface_gone`, `perm_lost`, `not_activated`, `error` |
| `<s>_exit_detail` | libpcap's own error text at exit, verbatim, `""` = none. Always read this beside `_exit`: `error` is the honest bucket for wording sloth does not recognise, not a claim that nothing more is known |
| `<s>_stats_valid` | at least one `pcap_stats()` sample has landed; `0` means the counters below are not yet meaningful |
| `<s>_recv`, `<s>_drop`, `<s>_ifdrop` | lifetime packets received, dropped by libpcap's buffer, and dropped by the NIC |
| `<s>_recv_delta`, `<s>_drop_delta`, `<s>_ifdrop_delta` | the same three over the **last tick only** |

The lifetime totals are accumulated by sloth from the per-tick deltas
rather than copied from libpcap. libpcap's counters are 32-bit and a
handle restart zeroes them; a sample lower than the previous one is read
as a reset (the new value becomes that tick's delta) so the exported
total is monotonic and a consumer differencing two samples never sees a
negative rate. A true 2^32 wrap on one handle would under-count by one
wrap period — ~4.3 G packets — and is the deliberate trade for keeping
the common case exact.

**Cadence.** Change-only, on the same cache as the entity snapshots: a
healthy sensor emits one line per 300 s heartbeat, and any degradation
emits immediately. The signature covers liveness, exit reasons, the
channel pair, retune failures, the cumulative drop/ifdrop counters and
the eviction total — deliberately **not** `recv` or any of the deltas.
`recv` climbs every tick on a working sensor, so including it would mean
one line per second forever and the suppression would be decorative. A
drop counter moving is genuinely news; a packet counter moving is not.

```json
{"type":"sensor_health","ts":1700000000,"capture_iface":"any","monitor_iface":"alfa0","monitor_err":"","chan_requested":11,"chan_confirmed":6,"chan_confirmed_ok":0,"chan_retune_failures":2,"capture_open":1,"capture_running":1,"capture_exit":"none","capture_exit_detail":"","capture_stats_valid":1,"capture_recv":184320,"capture_drop":12,"capture_ifdrop":0,"capture_recv_delta":903,"capture_drop_delta":4,"capture_ifdrop_delta":0,"monitor_open":1,"monitor_running":0,"monitor_exit":"iface_gone","monitor_exit_detail":"The interface went down","monitor_stats_valid":1,"monitor_recv":51201,"monitor_drop":0,"monitor_ifdrop":3,"monitor_recv_delta":0,"monitor_drop_delta":0,"monitor_ifdrop_delta":0,"evictions":5,"evict_alert":1,"evict_top_host":0,"evict_pnl_client":0,"evict_pnl_ssid":4,"evict_dhcp_event":0,"evict_eap_session":0,"evict_device":0}
```

**What the eviction tally does and does not cover.** Counted: alerts,
top hosts, PNL clients, per-client PNL SSIDs, DHCP events, 802.1X EAP
sessions, and the device table (which refuses a new entry rather than
evicting an old one — different mechanism, same meaning). **Not** yet
counted: the probe-client, beacon, seqnum, assoc and per-protocol flow
rings. Treat `evictions` as "loss on the instrumented tables", not "all
loss" — that distinction is stated rather than papered over, because a
tally that silently omitted a table would read as "no loss" when it
means "not measured".

All BSSIDs / MACs are lowercase colon-separated hex (`aa:bb:cc:dd:ee:ff`).
All timestamps are Unix epoch seconds. Rates (`rx_rate`/`tx_rate`) are
bytes/second as float with 2 decimal places.

**Cadence**: one tick per `poll_data()` call (≈1 Hz). Every active
entry in every table emits a record each tick. When an entry is aged
out of the source table its records simply stop appearing — there is
no explicit "closed" record.

**Volume**: a typical home network with ~100 ARP entries, ~30 beacons,
~50 connections, ~20 devices, etc., emits on the order of 1 KB/s. The
forwarder's `--type` filter lets consumers subscribe to only the
record types they need.

## `socket_gap` (socket-only)

```json
{"type":"socket_gap","ts":1700000000,"seq":600,"dropped":77,"dropped_total":77}
```

Written only on `--data-socket`, only to the one connection that lost
records, never to `-o FILE` (the file sink has no queue and never
drops). Added in #93; purely additive — consumers that ignore unknown
`type` values keep working, and a connection that never overflows never
receives one.

| Field | Type | Meaning |
|-------|------|---------|
| `ts` | int | wall-clock time the marker was queued |
| `seq` | int | records offered to this connection before the marker (delivered + dropped); starts at 0 per connection |
| `dropped` | int | records dropped since the previous marker on this connection |
| `dropped_total` | int | records dropped over the life of this connection |

The marker is a record like any other: under `--out-format cef` or
`syslog` it is emitted in that format (`socket_gap` is its CEF
signature / syslog MSGID), and it does not count towards `seq` itself.

## Versioning

- **No version field.** Fields are append-only; existing names and
  semantics don't change. `count` on `alert` is the standing example:
  #98 documented what it had always measured (rule evaluations) and
  added `observations` beside it rather than redefining it.
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

## Reference SIEM forwarder

For shipping the stream to a SIEM, a sibling reference at
[`examples/forwarder/sloth-forward.py`](../../examples/forwarder/sloth-forward.py)
implements batched, retrying forwarders to:

- **Splunk HEC** — JSON envelopes over HTTPS POST.
- **RFC 5424 syslog** — UDP or TCP.
- **Elasticsearch Bulk API** — NDJSON to `/_bulk`, time-rolled
  indices via strftime patterns (`sloth-events-%Y.%m.%d`),
  `@timestamp` derived from each record's `ts`, basic auth or API
  key. Partial failures (Elastic returns 200 with `errors:true`
  even when individual docs are rejected) surface as batch
  failures so the retry loop sees them.

The sink interface is a two-method class (`name`, `send(batch)`), so
adding Loki / Elasticsearch / Datadog / an in-house collector is ~30
lines. Delivery semantics are deliberately non-durable to match the
data socket's design: failed batches are dropped after retries, with
a stats line to stderr. If you need durability, pair the socket sink
with `-o FILE` and ship the file separately. Full notes in
[`examples/forwarder/README.md`](../../examples/forwarder/README.md).

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
