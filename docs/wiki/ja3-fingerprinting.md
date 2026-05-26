---
name: ja3-fingerprinting
description: How sloth derives a JA3 fingerprint from each TLS ClientHello, and what it's useful for
type: reference
---

# JA3 fingerprinting

**Summary**: JA3 is a stable MD5 hash of a TLS ClientHello's negotiation parameters — version, cipher suites, extensions, supported groups, EC point formats. Same client library + version → same JA3 across hosts. Sloth computes JA3 for every observed ClientHello on TCP/443.

**Sources**: `docs/views/tls.md`, `src/tls_log.c`, `src/md5.c`.

**Last updated**: 2026-05-25.

---

## Inputs

The JA3 string is a comma-joined concatenation of:

1. TLS legacy version (note: TLS 1.3 hides as `0x0303` in this field;
   sloth also reads `supported_versions` for the real version display).
2. Cipher suites.
3. Extensions.
4. Supported elliptic-curve groups.
5. EC point formats.

GREASE values per [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) are
filtered out so the hash stays stable across browser restarts.

The resulting string is MD5-hashed. The MD5 implementation in
`src/md5.c` is embedded (no OpenSSL dep) and verified against RFC 1321
test vectors.

## What sloth records per ClientHello

src, dst, host (SNI), TLS version (`1.3` / `1.2` / `1.1` / `1.0` /
unknown), 32-char hex JA3. The view shows a 12-char prefix; full hash
is available for export.

## Why it's useful

- **Implant detection**: malware often uses a custom TLS library whose
  JA3 doesn't match Chrome/Firefox even when the User-Agent claims it
  is one of those browsers. A JA3-vs-UA mismatch is a classic
  implant signature.
- **Cross-host correlation**: same JA3 from different source IPs
  suggests the same client software — useful for tracing a tool through
  a network.
- **Threat-intel pivoting**: known-bad JA3s are published in feeds (see
  [salesforce/ja3](https://github.com/salesforce/ja3)).

## What this misses

- ECH / encrypted ClientHello — when it lands, the SNI and most
  negotiation fields move inside an encrypted envelope.
- Clients that randomise their negotiation (rare today; some research
  builds do it).

## Related pages

- [[alerts]] — `THREAT_DOMAIN` fires when SNI hits the IOC list.
- [[threat-intel]] — IOC list format used for SNI matching.
- [[attack-map]] — TLS downgrade / weak crypto / implant fingerprint entries.
