---
name: Kerberos observability — KERB_PREAUTH_BURST alert
description: Detecting Kerberos password-spray bursts on TCP/UDP 88
type: feature
---

# Kerberos observability

Kerberos is the authentication protocol behind every Active
Directory environment. Clients exchange messages with a Key
Distribution Center (KDC, typically the domain controller) on
TCP / UDP port 88. Sloth's first pass at Kerberos visibility is
narrow: detect each Kerberos message type via the outer ASN.1
`[APPLICATION]` tag, parse the KRB-ERROR error code, and fire
`KERB_PREAUTH_BURST` when a single source produces a clean burst
of `KDC_ERR_PREAUTH_FAILED` responses (password spray).

Deeper Kerberos visibility — username/principal extraction,
AS-REP roasting detection, and kerberoasting service-ticket
tracking — is documented out of scope at the bottom of this
page.

## What we detect

Kerberos messages are tagged with an outer
`[APPLICATION n]` constructed identifier. Sloth recognises the
five operationally interesting ones by their first byte:

| Tag byte | Message      | RFC 4120 §  |
|----------|--------------|-------------|
| `0x6A`   | AS-REQ       | 5.4.1       |
| `0x6B`   | AS-REP       | 5.4.2       |
| `0x6C`   | TGS-REQ      | 5.4.1       |
| `0x6D`   | TGS-REP      | 5.4.2       |
| `0x7E`   | KRB-ERROR    | 5.9.1       |

For TCP/88 the wire format prefixes the Kerberos message with a
4-byte length; the parser checks for the magic tag at offset 0 or
4 to handle both transports.

When the message is a KRB-ERROR, we walk for the `[6]` error-code
field (DER: `A6 LEN 02 ilen <bytes>`) and bucket the code:

| Error                 | Code | Bucket                       |
|-----------------------|------|------------------------------|
| `KDC_ERR_PREAUTH_REQUIRED` | 25 | `preauth_required_count`     |
| `KDC_ERR_PREAUTH_FAILED`   | 24 | `preauth_failed_count`       |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | 6 | `principal_unknown_count` |
| (any other)               | …  | `error_other_count`          |

Per-source aggregation: every flow with a Kerberos message on
port 88 contributes to a `kerb_event` keyed on the client IP
(whichever endpoint is NOT on port 88). Up to 64 sources
tracked; oldest-evicted on overflow.

## Alert: `KERB_PREAUTH_BURST`

```
KERB_PREAUTH_BURST: 10.0.0.5: 12 Kerberos pre-auth failures
(spray indicator; unknown-principal=2, preauth-required=3)
```

| Field | Value |
|-------|-------|
| Severity | CRIT |
| Threshold | `preauth_failed_count ≥ 5` per source |
| Dedup key | `kerb-burst:<src_ip>` — one alert per spraying source |
| `match_ip` | `src_ip` (the spray origin to investigate) |
| `match_port` | 88 |

Why 5: a human mistyping their password and getting it right on
the third attempt produces at most 2 failures from a single
workstation, then succeeds. Five preauth failures across the
active aggregation window is a clean signal of automated
iteration over a username list.

## What's normal

- Per-user aggregates with `preauth_required_count > 0` and
  `preauth_failed_count` low (0–2). The PREAUTH_REQUIRED response
  is the standard "you need to include pre-auth data" reply to a
  first AS-REQ without it; every successful authentication
  produces one.
- `as_req_count` ≈ `as_rep_count + preauth_required_count + preauth_failed_count`.
  (REP responses are sent when pre-auth succeeds.)
- TGS-REQ / TGS-REP counts grow with the number of service tickets
  the client is granted — file shares, RPC endpoints, web SPNs.

## What's suspicious

- `preauth_failed_count ≥ 5` from one source — fires the alert.
- `principal_unknown_count > preauth_failed_count` from one source
  — username enumeration sweep ("does `aaron` exist? `abby`?
  `adam`?"). Not currently a dedicated alert; the `kerb_event`
  record exposes the count for ops to grep on in the SIEM.
- High `tgs_req_count` from a workstation that hasn't shown
  corresponding AS-REQ traffic — possible kerberoasting (an
  attacker with a stolen TGT requesting service tickets en
  masse). Not currently a dedicated alert.

## Deliberately out of scope (for now)

- **Username / principal extraction.** AS-REQ carries the
  `cname` field in plaintext; parsing it requires walking the
  ASN.1 `KDC-REQ-BODY` past the `padata`. The aggregate counts
  are enough for the burst alert; per-username detail would be
  nice for the SIEM but isn't on the critical path.
- **AS-REP roasting** (CVE-free attack class). Detection
  requires correlating an AS-REP returned WITHOUT a prior
  PREAUTH_REQUIRED error from the same client — needs request /
  response pairing the v1 tracker doesn't currently maintain.
  Documented as the natural Tier 2 follow-up.
- **Kerberoasting** detection — service-ticket request volumes,
  weak encryption (`etype=23` RC4-HMAC) flagging. Same Tier 2
  bucket.
- **Pre-auth bypass via NTLM fallback** — out of scope for the
  Kerberos parser; NTLMSSP travels inside SMB and would land in
  the SMB snooper's NTLMSSP follow-up.

Each is a tractable Tier 2 follow-up; the `kerb_event` JSONL
record already carries the counters needed for SIEM correlation
queries to surface them without C code changes.

## References

- RFC 4120 — The Kerberos Network Authentication Service (V5).
- RFC 4757 — RC4-HMAC encryption types (kerberoasting target).
- MITRE ATT&CK T1110.003 — Password Spraying.
- MITRE ATT&CK T1558.003 — Kerberoasting.
- MITRE ATT&CK T1558.004 — AS-REP Roasting.

## Related pages

- [[alerts]] — the rule that fires on the tracker's state.
- [[jsonl-schema]] — `kerb_event` wire format.
- [[smb-snoop]] — companion lateral-movement page; SMB and
  Kerberos travel together in AD environments.
- [[ipv6-ndp]] — the other recently-landed passive observable.
