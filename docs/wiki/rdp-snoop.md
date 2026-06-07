---
name: RDP observability — RDP_BRUTE_FORCE alert
description: Detecting xfreerdp-loop / NLBrute / Crowbar brute-force on TCP/3389 via X.224 CR counting
type: feature
---

# RDP observability

RDP runs on TCP/3389 and is the Windows lateral-movement and
remote-administration substrate. The connection setup is cleartext
even when CredSSP/NLA is negotiated — the TPKT envelope (RFC 1006),
the X.224 Class 0 Connection Request TPDU, the optional cookie
`Cookie: mstshash=USERNAME\r\n`, and the RDP Negotiation Request
(MS-RDPBCGR §2.2.1.1) all sit ahead of the TLS/CredSSP wrap.

Sloth's first RDP pass is narrow: count X.224 Connection Request
TPDUs per (client_ip, server_ip), pull the username out of the
mstshash cookie when present, OR-accumulate the requested-protocol
bitmask, and fire `RDP_BRUTE_FORCE` when one client opens ≥10 CRs
to one server inside the active window. Same shape as
[[ssh-snoop]] — the encrypted auth itself is invisible, but brute
force is a connection-cadence signal, not a payload signal.

## What we detect

The TPKT envelope (RFC 1006 §6):

```
0       1       2 3
+-------+-------+---+---+
| ver=3 | rsvd  | length |
+-------+-------+---+---+
```

Carrying an X.224 (T.0) Class 0 Connection Request TPDU:

```
0     1     2 3     4 5     6        ... user data ...
+-----+-----+--+--+--+--+----+----------------------------+
| LI  | 0xE0| 0000 | SRC| co | cookie | RDP_NEG_REQ TLV   |
+-----+-----+--+--+--+--+----+----------------------------+
```

| Byte/field | Meaning |
|------------|---------|
| TPKT byte 0 | version, always `0x03` |
| TPKT bytes 2-3 | total length, big-endian |
| X.224 byte 0 | length indicator (LI) — bytes that follow |
| X.224 byte 1 | TPDU code; `0xE0` = Connection Request |
| X.224 bytes 2-3 | DST-REF, always `0x0000` in Class 0 |
| Cookie field | `Cookie: mstshash=USERNAME\r\n` (optional) |
| RDP_NEG_REQ | `0x01 flags 0x0008 protos(LE u32)` |

`protos` is a bitmask: 0x01 = vanilla RDP, 0x02 = SSL/TLS, 0x04 =
HYBRID (CredSSP/NLA), 0x08 = HYBRID_EX. Sloth OR-accumulates what
it sees across all CRs on a flow.

Per-(client_ip, server_ip) aggregation: 64 flows tracked,
oldest-by-last-seen evicted on overflow.

## Alert: `RDP_BRUTE_FORCE`

```
RDP_BRUTE_FORCE: 203.0.113.7->10.0.0.20: 47 RDP CRs
(brute-force; user=administrator)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `connect_req_count ≥ 10` per (client_ip, server_ip) |
| Dedup key | `rdp-brute:<client>-><server>` |
| `match_ip` | `src_ip` (the attacking client) |
| `match_port` | 3389 |

Why 10: matches the SSH threshold. Both protocols share the same
brute-force shape (one TCP connection per credential attempt) and
both have similar legitimate-reconnect baselines (a handful per
session for users behind NAT or VPN with sleep/wake cycles). Ten
distinct CRs to one server in the active window is unambiguous.

## What's normal

- `connect_req_count` low — typically 1–3 per legitimate user
  session per server.
- `proto_mask` containing `HYBRID` (0x04) — modern Windows
  defaults to NLA.
- `last_cookie` consistent across observations (the user's own
  account or no cookie at all when client doesn't send one).
- Few flows per active user.

## What's suspicious

- `connect_req_count ≥ 10` from one source to one server —
  fires the alert.
- `last_cookie` cycling through different usernames against the
  same `dst_ip` — password spray. The `rdp_flow` record only
  remembers the *last* cookie; a SIEM-side rule walking the
  record stream catches the rotation.
- `proto_mask` containing *only* legacy RDP (0x01) — client
  refuses NLA, possibly because it's an attack tool that
  doesn't bother implementing the modern auth.
- High flow count from one source to many servers — a
  sweep-style scan trying RDP on every reachable host.
  Not currently a dedicated alert; the `rdp_flow` records
  expose the pattern for SIEM rules.
- `last_cookie` = `administrator`, `admin`, or any of the
  classic guess-list usernames. Worth surfacing on its own
  even below the count threshold; not currently a dedicated
  alert.

## Deliberately out of scope (for now)

- **RDP Negotiation Response.** The server's response carries
  `selectedProtocol` plus failure codes if it rejects the
  client's request. Currently not parsed; would let us
  distinguish accepted from rejected CRs.
- **NLA / CredSSP user enumeration.** Some CredSSP failure
  paths leak which usernames exist. Beyond Tier 1 scope.
- **Connection-rate / per-second cadence.** A flow that crams
  20 CRs into 5 seconds is more brute-force-shaped than one
  that does it over an hour. The current count threshold
  catches both but doesn't differentiate.
- **MS-RDPEDC client-channel inspection.** Once TLS wraps the
  session, the DRDYNVC virtual channels are opaque to a
  passive observer.

## References

- RFC 1006 — ISO Transport Service on top of TCP (TPKT).
- ITU-T X.224 — Connection-oriented Transport Protocol
  specification.
- [MS-RDPBCGR] — Microsoft Remote Desktop Protocol: Basic
  Connectivity and Graphics Remoting.
- MITRE ATT&CK T1110.001 — Brute Force: Password Guessing
  (RDP variant).
- MITRE ATT&CK T1021.001 — Remote Services: Remote Desktop
  Protocol.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `rdp_flow` wire format.
- [[ssh-snoop]] — the sibling remote-access brute-force
  observable. The detection model is the same.
