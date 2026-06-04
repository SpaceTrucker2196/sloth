---
name: SSH observability — SSH_BRUTE_FORCE alert
description: Detecting hydra / medusa / ncrack brute-force on TCP/22 via banner-exchange counting
type: feature
---

# SSH observability

SSH runs on TCP/22 and is the universal remote-shell substrate.
The wire protocol begins with a cleartext banner exchange
(RFC 4253 §4.2) before any key exchange happens — that's the
only field a passive observer can read. Sloth's first SSH pass
is narrow: match the server banner ("SSH-2.0-..." or
"SSH-1.99-..."), aggregate per (client_ip, server_ip), and fire
`SSH_BRUTE_FORCE` when one client establishes ≥10 banner
exchanges with one server inside the active aggregation window.

The encrypted auth attempts themselves are not visible. They
don't have to be — brute-force is a TCP-shape signal (many
connections per second), not a payload signal. Hydra, medusa,
and ncrack all open a fresh TCP connection per credential
attempt and complete the banner exchange each time before
testing creds.

## What we detect

Per RFC 4253 §4.2, the banner is:

```
SSH-protoversion-softwareversion SP comments CR LF
```

`protoversion` is `1.99` (server speaks both 1 and 2) or `2.0`.
We require the literal `SSH-` prefix plus a second `-` within
the first 12 bytes so arbitrary cleartext beginning with
`SSH-` doesn't trigger detection.

| Side | Counted? | Why |
|------|----------|-----|
| Server (src_port = 22) | yes | exactly one per connection; the count is connection cadence |
| Client (dst_port = 22) | no | counting both would double every connection |

The server banner string itself is kept (truncated at CR/LF or
the first non-printable byte) so the alert detail and the
`ssh_flow` JSONL record can carry the fingerprint —
`OpenSSH_8.9`, `dropbear_2022.83`, etc. Useful for asset
inventory and version-vulnerability cross-reference.

Per-(client_ip, server_ip) aggregation: 64 flows tracked,
oldest-by-last-seen evicted on overflow.

## Alert: `SSH_BRUTE_FORCE`

```
SSH_BRUTE_FORCE: 203.0.113.5->10.0.0.10: 47 SSH banners
(brute-force; SSH-2.0-OpenSSH_8.9)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `banner_count ≥ 10` per (client_ip, server_ip) |
| Dedup key | `ssh-brute:<client>-><server>` |
| `match_ip` | `src_ip` (the attacking client) |
| `match_port` | 22 |

Why 10: a normal user might re-connect a handful of times in a
session after VPN blips or sleep/wake. Ten distinct banner
exchanges to the same server inside the active window is
unambiguous brute-force shape. fail2ban's default ban threshold
is 5 with a wider window; we're a bit higher to stay
surprise-free for noisy laptops behind NAT.

## What's normal

- `banner_count` low — typically 1–3 per legitimate user
  session per server.
- One distinct `server_banner` per `dst_ip` — the SSHd software
  string is stable.
- New flows appear when a new user starts using a new server;
  steady state has few flows per active user.

## What's suspicious

- `banner_count ≥ 10` from one source to one server — fires
  the alert.
- High flow count from one source to many servers — a
  sweep-style scan trying SSH on every reachable host. Not
  currently a dedicated alert; the `ssh_flow` records expose
  the pattern for SIEM rules.
- Many flows from many sources to one server — distributed
  brute-force (zombies). Each individual source may sit below
  the threshold; SIEM-side aggregation by `dst_ip` catches it.
- A `server_banner` that doesn't match the operator's expected
  SSHd build — drift indicator or unauthorised sshd on a
  client machine.

## Deliberately out of scope (for now)

- **KEX-method / cipher list extraction.** After the banner the
  client and server exchange supported algorithms in
  cleartext (`SSH_MSG_KEXINIT`, RFC 4253 §7.1). Parsing those
  would let us flag weak-cipher offers or fingerprint clients
  (HASSH). Tier 2 follow-up.
- **HASSH client fingerprinting.** Salesforce's HASSH hash
  over the client's KEX-init field is the SSH analogue to
  JA3 — a per-client signature that survives source-IP
  changes. Useful for tracking the same attacker tool across
  multiple botnet egress points. Requires the KEX-init walk
  above.
- **Failed-auth detection.** SSH's auth-failure messages are
  encrypted, so we can't see them. The closest passive signal
  is connection-shape (TCP RST quickly after banner = auth
  failed), which is fragile and OS-dependent. Sloth's
  connection-count heuristic gets there from the other
  direction.
- **Tunnelled-protocol detection.** Some C2 frameworks tunnel
  over SSH. The connection-byte-cadence + beacon detection
  ([[beaconing]]) catches that pattern at the higher layer;
  SSH-specific tunnel detection isn't planned.

## References

- RFC 4253 — SSH Transport Layer Protocol.
- MITRE ATT&CK T1110.001 — Brute Force: Password Guessing.
- MITRE ATT&CK T1110.003 — Brute Force: Password Spraying
  (single-credential variant; dst-aggregation catches it).
- [HASSH](https://github.com/salesforce/hassh) — SSH client
  fingerprinting (Tier 2 target).

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `ssh_flow` wire format.
- [[ldap-snoop]] / [[kerberos-snoop]] / [[smb-snoop]] /
  [[bgp-snoop]] — the other passive infrastructure-substrate
  observables. SSH joins them as the universal remote-access
  signal.
