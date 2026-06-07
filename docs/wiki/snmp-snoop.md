---
name: SNMP observability — SNMP_COMMUNITY_BRUTE alert
description: Detecting snmpwalk / metasploit community-string sweeps on UDP/161
type: feature
---

# SNMP observability

SNMP runs on UDP/161 (agent queries) and UDP/162 (traps). v1
(RFC 1157) and v2c (RFC 1901-1908) carry the community string —
the SNMP analogue of a password — in cleartext ASN.1 BER. v3
(RFC 3411+) finally added real authentication and encryption,
but v3 is rare on the LAN: almost every embedded device,
printer, switch, and IP camera ships with v2c enabled by
default.

Sloth's SNMP pass parses the outer BER envelope on UDP/161 and
UDP/162, extracts the version, the community string, and the
PDU tag, and aggregates per (src_ip, dst_ip). Tier 1 fires
`SNMP_COMMUNITY_BRUTE` when one source tries five or more
distinct community strings against one destination — the
exact shape of `snmpwalk -c <wordlist>` and the metasploit
`auxiliary/scanner/snmp/snmp_login` module.

## What we detect

SNMPv1/v2c message envelope:

```
Message ::= SEQUENCE {
    version   INTEGER (0=v1, 1=v2c, 3=v3),
    community OCTET STRING,           -- v1/v2c only
    data      ANY                      -- the PDU
}
```

PDU tags are `[APPLICATION 0..8]`, which BER-encodes as
context-specific constructed tags `0xA0..0xA8`:

| Tag  | PDU              | RFC      | What we infer            |
|------|------------------|----------|--------------------------|
| 0xA0 | GetRequest       | 1157 4.1 | single-OID read          |
| 0xA1 | GetNextRequest   | 1157 4.1 | walk step                |
| 0xA2 | GetResponse      | 1157 4.1 | agent reply              |
| 0xA3 | SetRequest       | 1157 4.1 | write — rare, suspicious |
| 0xA4 | Trap (v1)        | 1157 4.1 | agent notification       |
| 0xA5 | GetBulkRequest   | 1905     | bulk walk (v2+)          |
| 0xA6 | InformRequest    | 1905     | acked notification       |
| 0xA7 | SNMPv2-Trap      | 1905     | agent notification       |
| 0xA8 | Report           | 3411     | v3 protocol report       |

For v3 we record the version and that's it — the security name
is buried in the msgUserSecurityModel field which doesn't
follow the v1/v2c shape, and v3 brute-force has a different
signature anyway.

Each unique community string seen is stored (up to 8 per flow);
the `last_community` field is the most recent one. The flow
direction is normalised so the requester is always `src_ip` —
GetResponse packets attribute back to the querier, not the
agent.

Per-(src_ip, dst_ip) aggregation: 48 flows tracked,
oldest-by-last-seen evicted.

## Alert: `SNMP_COMMUNITY_BRUTE`

```
SNMP_COMMUNITY_BRUTE: 10.0.0.5->10.0.0.10: 7 SNMP communities
tried (last=private)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `community_count ≥ 5` per (src_ip, dst_ip) |
| Dedup key | `snmp-brute:<src>-><dst>` |
| `match_ip` | `src_ip` (the guesser) |
| `match_port` | 161 |

Why 5: a legitimate monitoring host uses *one* community
string per agent it polls — usually `public` for reads or a
site-specific token. Even an operator typing the wrong string
a couple times stays well below 5. Metasploit's default
community wordlist starts with `public / private / cisco /
community / admin` — five hits trips immediately.

## What's normal

- `community_count == 1`. One agent, one collector, one community.
- High `get_count` and `getnext_count` from monitoring hosts on
  a regular cadence. Bulk walks (`getbulk_count`) appear when
  the collector speaks v2c+.
- `set_count == 0` for almost all flows. Writes are rare in
  monitoring traffic.
- `trap_count > 0` only on flows where `dst_port == 162` and
  the agent is the source.

## What's suspicious

- `community_count ≥ 5` from one source — fires the alert.
- `set_count > 0` after a brute-force window — the attacker
  found a writable community and is rewriting agent config.
  Not currently a dedicated alert; the `snmp_flow` records
  expose the count for SIEM rules.
- Many flows from one source to many destinations with the
  same `last_community` — a confirmed-credential sweep.
  Not currently a dedicated alert.
- `version == 3` traffic from an unfamiliar source — v3 is
  uncommon, and a probe might be testing for v3 user
  enumeration vulnerabilities.

## Deliberately out of scope (for now)

- **OID inspection.** The varbind list in a GetRequest carries
  the OIDs being queried. Flagging known-sensitive OIDs
  (e.g. `1.3.6.1.4.1.9.9.23.1.2.1` — Cisco config rewrite)
  would catch post-credential reconnaissance, but requires
  full PDU decode beyond the tag.
- **SNMPv3 USM parsing.** The msgUserSecurityModel SEQUENCE
  carries the security name in cleartext. Worth surfacing for
  the v3-deployments-with-weak-creds case, but out of Tier 1.
- **Walk-rate analysis.** snmpwalk against one community
  produces hundreds of GetNext messages in seconds. The
  current count tracker exposes the volume; rate-based
  detection (per-second) is a Tier 2 follow-up.
- **Reflective amplification source.** UDP/161 is a classic
  reflective DDoS amplifier (GetBulk responses can be 100×
  the request size). The connection-cadence detector for that
  belongs to the [[beaconing]] / amplification side, not the
  SNMP observable per se.

## References

- RFC 1157 — Simple Network Management Protocol (v1).
- RFC 1901-1908 — Community-based SNMPv2.
- RFC 3411+ — SNMPv3 framework.
- MITRE ATT&CK T1110.001 — Brute Force: Password Guessing
  (SNMP community variant).
- MITRE ATT&CK T1046 — Network Service Scanning (SNMP
  enumeration variant).

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `snmp_flow` wire format.
- [[ssh-snoop]] / [[rdp-snoop]] — sibling brute-force
  observables; SNMP's variant is community-rotation rather
  than connection-count.
