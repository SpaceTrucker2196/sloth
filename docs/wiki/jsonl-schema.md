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
{"type":"twin_episode","ts":1700000007,"ssid":"Cafe-Net","real_bssid":"aa:bb:cc:01:02:03","twin_bssid":"11:22:33:44:55:66","enc":"WPA2","real_rssi":-70,"twin_rssi":-45,"rssi_swing_dbm":25,"attack_in_progress":1,"attacker_oui":1,"hash_mismatch":1}
```

| Field                | Type   | Meaning |
|----------------------|--------|---------|
| `ssid`               | string | shared SSID |
| `real_bssid`         | string | legit AP's BSSID (lowercase hex) |
| `twin_bssid`         | string | rogue / suspected-rogue AP's BSSID |
| `enc`                | string | shared encryption mode (`WPA2`, `WPA3`, …) |
| `real_rssi`          | int    | last observed signal of the real AP (dBm; 0 = unseen) |
| `twin_rssi`          | int    | last observed signal of the twin AP |
| `rssi_swing_dbm`     | int    | max RSSI swing on the twin in last 60 s (0 = unseen) |
| `attack_in_progress` | int    | 1 if the chain rule tainted `twin_bssid` (DEAUTH_FLOOD seen within 5 s) |
| `attacker_oui`       | int    | 1 if `twin_bssid`'s OUI is Hak5 or Espressif |
| `hash_mismatch`      | int    | 1 if the vendor-IE fingerprint hashes disagree |

**Cadence**: snapshot — one record per detected pair per poll (≈1 Hz).
The consumer rebuilds its table from the latest snapshot keyed by
`(ssid, real_bssid, twin_bssid)`. When a pair stops appearing on the
RF, its records simply stop arriving — there's no explicit "closed"
record.

**"Real" vs "twin" assignment** defaults to the lower-RSSI side being
real (typical for a distant legit AP overshadowed by a close rogue).
When `rule_evil_twin_attack_chain` has tainted a BSSID, that override
pins the assignment regardless of signal strength.

## State snapshot record types

These records carry the current contents of each view-backing table.
**Snapshot semantics — one record per entry per poll**, emitted by
`jsonl_emit_state_snapshots()` after `poll_data()` finishes. Consumers
(the iOS client; any other view-rebuilding consumer) reconstruct the
table from the latest snapshot keyed by the natural-identity field
indicated below. Late-joining clients pick up state on the next tick.

| Record               | Identity key      | Fields |
|----------------------|-------------------|--------|
| `iface`              | `name`            | `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets`, `rx_errors`, `rx_drops`, `tx_errors`, `tx_drops`, `rx_rate`, `tx_rate`, `mtu`, `speed_mbps` |
| `arp`                | `mac`+`ip`        | `mac`, `ip`, `iface` |
| `dhcp_lease`         | `ip`              | `ip`, `hostname`, `expire` (epoch; 0 = unknown) |
| `wifi_ap`            | `bssid`           | `ssid`, `bssid`, `signal_dbm`, `channel`, `enc`, `status` |
| `wifi_sta`           | `mac`             | `mac`, `signal_dbm`, `tx_rate_kbps`, `rx_rate_kbps`, `connected_secs`, `inactive_ms`, `tx_bytes`, `rx_bytes` |
| `top_host`           | `ip`              | `ip`, `hostname`, `owner`, `first_seen`, `last_seen`, `conn_count`, `rx_rate`, `tx_rate`, `rx_bytes`, `tx_bytes` |
| `device`             | `mac`             | `mac`, `ip`, `hostname`, `vendor`, `last_ssid`, `is_ap`, `signal_dbm`, `probe_count`, `sources` (bitmask of `DEV_SRC_*`), `last_seen` |
| `beacon`             | `bssid`           | `ssid`, `bssid`, `signal_dbm`, `channel`, `enc`, `beacon_ms`, `pairwise`, `group`, `akm`, `mfp` (0/1/2), `vendor`, `has_wps`, `wps_state`, `wps_locked`, `phy`, `revealed`, `last_seen`, `frame_count`, `fp_flags` (`AP_FP_FLAG_*` bitset), `vendor_ies_hash`, `rssi_min_60s`, `rssi_max_60s`, `ssid_history[]`, `neighbors[{bssid, channel, phy_type}]` |
| `deauth`             | `bssid`+`dst`     | `src`, `dst`, `bssid`, `reason`, `subtype`, `first_seen`, `last_seen`, `count`, `flood` |
| `probe_client`       | `mac`             | `mac`, `ssid`, `signal_dbm`, `channel`, `first_seen`, `last_seen`, `frame_count` |
| `pnl_client`         | `mac`             | `mac`, `mac_random`, `probe_count`, `os_fp`, `phy`, `first_seen`, `last_seen`, `ssids[]` |
| `seqnum_client`      | `mac`             | `mac`, `mac_random`, `last_seen`, `frame_count`, `hist[]` (12-bit seqnums in observation order) |
| `seqnum_correlation` | `mac_a`+`mac_b`   | `mac_a`, `mac_b`, `mac_a_random`, `mac_b_random`, `gap`, `dt_ms`, `a_count`, `b_count` |
| `channel_summary`    | `channel`         | `channel`, `ap_count`, `assoc_count`, `best_signal`, `top_ssid`, `last_seen` |
| `assoc`              | `bssid`+`sta_mac` | `bssid`, `sta_mac`, `ssid`, `sta_random`, `source` (`ASSOC_SRC_*`), `channel`, `signal_dbm`, `first_seen`, `last_seen`, `frame_count` |
| `eapol`              | `bssid`+`sta_mac` | `bssid`, `sta_mac`, `ssid`, `event_ts`, `msg_num`, `has_pmkid`, `handshake_complete`, `signal_dbm`, `channel` |
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
