---
name: LDAP observability — LDAP_SEARCH_FLOOD alert
description: Detecting BloodHound / ldapdomaindump enumeration on TCP/389 + TCP/3268
type: feature
---

# LDAP observability

LDAP is the directory protocol Active Directory speaks. Domain
controllers expose it on TCP/389 (default) and TCP/3268 (Global
Catalog). Sloth's first pass at LDAP visibility is narrow: detect
`BindRequest`, `SearchRequest`, and `SearchResultReference`
messages via RFC 4511 BER framing, aggregate per source, and
fire `LDAP_SEARCH_FLOOD` when a single source emits ≥50
SearchRequest messages — the unmistakable shape of BloodHound,
ldapdomaindump, and the impacket AD-enumeration toolchain.

TLS variants — TCP/636 (LDAPS) and TCP/3269 (Global Catalog over
TLS) — are opaque past the handshake and not observed.

## What we detect

LDAP messages are ASN.1 BER per RFC 4511. The outer envelope is:

```
LDAPMessage ::= SEQUENCE {
    messageID  MessageID,           -- INTEGER
    protocolOp CHOICE { ... },      -- [APPLICATION n]
    controls   [0] Controls OPTIONAL
}
```

Sloth walks the envelope to expose the `protocolOp` tag and
recognises three:

| Tag byte | Message                  | RFC 4511 § |
|----------|--------------------------|------------|
| `0x60`   | `BindRequest`            | 4.2        |
| `0x63`   | `SearchRequest`          | 4.5.1      |
| `0x73`   | `SearchResultReference`  | 4.5.3      |

`BindResponse`, `SearchResultEntry`, `SearchResultDone`,
`UnbindRequest`, and the rest are intentionally **not counted**.
Including SearchResultEntry would inflate the search-flood
counter by every individual result row a server returns and
defeat the threshold.

For BindRequest, the body is walked one more level to check
whether the `name` field (LDAPDN, an OCTET STRING) is empty —
that's an **anonymous bind**, the classic enumeration starting
point.

Per-(client_ip) aggregation: 64 sources tracked, oldest-evicted
on overflow. Server-side traffic (src_port = 389/3268) is
attributed to the OTHER endpoint as client.

## Alert: `LDAP_SEARCH_FLOOD`

```
LDAP_SEARCH_FLOOD: 10.0.0.5: 142 LDAP SearchRequest messages
(AD enumeration indicator; bind=1, anon_bind=0, referrals=0)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `search_count ≥ 50` per source |
| Dedup key | `ldap-flood:<src_ip>` — one alert per enumerating source |
| `match_ip` | `src_ip` (the workstation to investigate) |
| `match_port` | 389 |

Why 50: a normal Windows workstation logon produces ~10–20 LDAP
searches against the DC (lookups for the user's group memberships,
GPO links, etc.). 50 searches per source per active window is
well above that baseline and well below what BloodHound's
`SharpHound` collector or ldapdomaindump produces in their first
2–5 seconds (typically 200–2000).

## What's normal

- `bind_count` low (≤ a few per source per hour for human users).
- `search_count` low (≤ 20 per logon transaction).
- `search_ref_count` zero or near-zero — AD servers rarely
  emit referrals to LAN clients.
- `bind_anon_count` zero. Anonymous binds are rare in modern AD
  deployments; their presence is by itself worth a glance even
  without a flood.

## What's suspicious

- `search_count ≥ 50` from one source — fires the alert.
- `bind_anon_count > 0` — not currently a dedicated alert; the
  `ldap_event` record exposes the count for SIEM queries to
  surface anon-bind enumeration sweeps.
- `search_ref_count > 0` — possible referral-following enumeration
  pattern or topology leakage from the DC. Not currently a
  dedicated alert.
- High `search_count` with low `bind_count` — a stolen / replayed
  TGT being used to query without re-binding.

## Deliberately out of scope (for now)

- **Per-attribute query inspection.** SearchRequest carries a
  filter and an attribute list; flagging searches for
  `servicePrincipalName` (kerberoasting precursor), `userPassword`
  (legacy / unsafe), or `msDS-AllowedToActOnBehalfOfOtherIdentity`
  (RBCD attack precursor) would let us distinguish enumeration
  intent from volume alone. The flood alert is the broad gate;
  the per-attribute follow-up belongs to a Tier 2 patch.
- **Result-size analysis.** A successful enumeration returns
  thousands of `SearchResultEntry` messages. Counting those would
  catch enumeration even when the request volume is throttled.
  Same Tier 2 bucket.
- **Referral content extraction.** SearchResultReference messages
  contain URLs that often leak internal topology
  (`ldap://dc01.corp.internal/...`). Sloth counts them but
  doesn't parse the URLs. Future addition.
- **LDAPS** (TCP/636 / 3269). Opaque past the TLS handshake; the
  signal that would survive — TLS handshake metadata — is already
  captured by [[ja3-fingerprinting]].

## References

- RFC 4511 — LDAPv3 protocol.
- MITRE ATT&CK T1087.002 — Account Discovery: Domain Account.
- MITRE ATT&CK T1069.002 — Permission Groups Discovery: Domain
  Groups.
- [BloodHound](https://bloodhound.specterops.io/) — the
  canonical AD enumeration tool; SharpHound's `Default`
  collection method sends ~300 LDAP searches against a small
  forest in under 10 seconds.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `ldap_event` wire format.
- [[smb-snoop]] / [[kerberos-snoop]] — the other AD-substrate
  passive observables; together they reconstruct the textbook
  lateral-movement footprint.
