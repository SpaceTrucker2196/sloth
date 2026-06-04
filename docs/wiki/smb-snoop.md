---
name: SMB observability — SMB1_USE alert
description: Detecting SMBv1 traffic on the wire as a lateral-movement signal
type: feature
---

# SMB observability

SMB (Server Message Block) is the Windows file-share, named-pipe,
and printer protocol. It lives on TCP/445 (direct, no NetBIOS
framing) and TCP/139 (with the NetBIOS Session Service framing
header). Sloth's first pass at SMB visibility is narrow: detect the
**SMB1 vs SMB2/3 magic header** and fire `SMB1_USE` on any observed
SMB1 traffic. NTLM authentication parsing, tree-connect to admin
shares, and NULL session detection are documented out of scope at
the bottom of this page.

## Why SMB1 alone is worth a CRIT

- Microsoft deprecated SMBv1 in 2017 and disables it by default on
  Windows 10 (Fall Creators Update onward) and Windows Server 2016+.
- The 2017 NSA/Shadow Brokers leak yielded **EternalBlue
  (MS17-010)** — an unauthenticated remote code execution exploit
  targeting SMBv1. WannaCry, NotPetya, and Bad Rabbit campaigns
  shipped EternalBlue as payload.
- CISA's
  [emergency directive](https://us-cert.cisa.gov/ncas/current-activity/2017/06/22/SambaCryptocurrencyMining)
  was unambiguous: disable SMBv1 everywhere.
- Modern attackers still find SMBv1 on the wire because of
  unpatched embedded devices (printers, NAS appliances), legacy
  domain members, and configuration drift after an admin tested
  something "temporarily."

Observing SMBv1 on the wire post-2024 is therefore by itself a
finding worth surfacing — no further parsing required.

## What sloth captures

`src/smb_snoop.c` checks the first 4 bytes of every TCP/445 or
TCP/139 payload for one of:

- `\xFF S M B` — SMB1
- `\xFE S M B` — SMB2 / SMB3 (the two are not distinguished —
  see "Why not split SMB2/3" below)

If a 4-byte NetBIOS Session Service header precedes the SMB
payload (common on port 139, also seen on 445 from older stacks),
the check is repeated at offset 4.

For each unique `(client_ip, server_ip, server_port)` tuple a
session is recorded with:

| Field | Notes |
|-------|-------|
| `client_ip`, `server_ip`, `server_port` | Server side is whichever endpoint is on 445 or 139. |
| `dialect` | `"SMB1"` or `"SMB2"`. **Sticky to SMB1** — once a flow has been observed using v1, subsequent v2 frames on the same flow do not downgrade the recorded dialect. Mid-flow SMB1 negotiation is precisely the attacker-forced pattern we want to catch. |
| `first_seen`, `last_seen`, `count` | Bookkeeping. |

Up to `MAX_SMB_SESSIONS = 64` distinct sessions; oldest-evicted on
overflow.

## Alert: `SMB1_USE`

```
SMB1_USE: SMBv1 traffic 10.0.0.5 -> 10.0.0.10:445 (count=42). SMBv1
has been deprecated since 2017 (EternalBlue / WannaCry); the
endpoint serving v1 should be patched or v1 disabled.
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Dedup key | `smb1:<client_ip>><server_ip>:<port>` — one alert per (client, server, port) tuple so an operator can pivot to the exact endpoint pair. |
| `match_ip` | server IP (the side that should be patched / hardened) |
| `match_port` | server port (445 or 139) |

The rule fires once per (client, server, port) tuple per poll if
its recorded dialect is `"SMB1"`. The alert engine's dedup means
the same tuple stays as a single persistent alert; new
endpoint pairs mint new alerts.

## What's normal

- No SMB sessions tracked at all (most observation targets aren't
  Windows file servers).
- All sessions reporting `dialect == "SMB2"`.

## What's suspicious

- Any session with `dialect == "SMB1"` — that's the alert. Pivot
  with `match_ip` to identify the SMB1-speaking server.
- A previously-SMB2 server suddenly showing `dialect == "SMB1"`
  on a new client — possible attacker forcing a v1 negotiation.
- A printer / NAS as the server side with SMB1 — common, almost
  always a misconfigured legacy device that needs firmware update
  or replacement.

## Why not split SMB2/3

The SMB2 and SMB3 dialects share the `\xFE S M B` magic header.
Distinguishing requires parsing the dialect field of a Negotiate
response message body. For the SMB1-detection use case the split
adds complexity without value — the alert fires on v1, and
operators don't need to differentiate v2 vs v3 to decide whether
to investigate.

When a future use case (e.g. flagging SMB2 sessions without
signing / encryption) needs the distinction, the parser can be
extended without disturbing the v1 path.

## Deliberately out of scope (for now)

- **NTLMSSP authentication parsing.** Username + domain leak in
  plaintext through the NTLM Type 1 / Type 2 / Type 3 exchange.
  A future iteration can extract these for lateral-movement
  surface.
- **Tree-connect path tracking.** Connecting to `ADMIN$`, `C$`,
  or `IPC$` (especially NULL session) is high-signal for
  PSExec-style lateral movement.
- **SMB signing / encryption posture.** Not enforcing signing
  leaves SMB sessions vulnerable to relay attacks.
- **DCE/RPC subprotocols.** SAMR, LSARPC, DRSUAPI traffic over
  SMB is the substrate for AD-targeted attacks; the metadata is
  observable when the session isn't encrypted.

Each of these is a tractable follow-up; documented here so the
next agent knows what's left.

## References

- [MS-SMB] / [MS-SMB2] — Microsoft SMB protocol specs.
- CVE-2017-0144 — EternalBlue.
- CISA AA20-345A — joint advisory on SMBv1 mitigation.
- [hashcat 22000 format](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2) — adjacent context for the EAPOL path; SMB has its own NTLMSSP cracking flow.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `smb_session` wire format.
- [[architecture]] — where `smb_snoop.c` fits in the source tree.
- [[ipv6-ndp]] — companion passive-observability page, same
  shape (mitm6 / Slaacers detection).
