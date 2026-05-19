# QUIC  `[u]`

QUIC session log — encrypted UDP transport, mainly HTTP/3 on UDP/443.

## Protocol

QUIC ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)) is the
encrypted-by-default transport that underlies HTTP/3 and a growing
number of other apps. Built on UDP, it has its own connection
handshake (long-header Initial packets) with version negotiation and
TLS 1.3 baked in.

Most of the wire is encrypted, but the first Initial packet has a
plaintext header containing the version and a destination
connection-id. Sloth parses just enough to identify QUIC, pull the
version label (`v1`, `v2`, `draft-NN`), and tag the flow.

## What sloth captures

Per session: src, dst, host (looked up via the DNS cache built from
the DNS log), version. The implementation in
[`src/quic_log.c`](../../src/quic_log.c) wraps `quic_detect()` from
the existing snoop.

## View

```
 ── QUIC sessions ──────────────────────────────────────────────
 Time      Src              Dst              Host                 Ver
 22:01:01  192.168.1.5      142.250.80.46    google.com           v1
 22:01:02  192.168.1.5      104.16.132.229   cloudflare.com       v1
 22:01:05  10.0.0.5         203.0.113.40     (unknown)            draft
```

`v2`: bright (newer). `draft-*`: dim (older / experimental). `v1`: normal.

## What's normal

- Most QUIC is browser-driven HTTP/3 over `v1`.
- The "Host" column populates a moment after the first DNS response
  to that IP arrives — there's an inevitable lag.

## What's suspicious

- **`draft-NN` versions** in production traffic from anything other
  than experimental clients (Chrome canary, etc.) — fingerprintable
  TLS-on-QUIC implementations like
  [quiche](https://github.com/cloudflare/quiche) sometimes still use
  draft versions for compatibility testing.
- **Unknown-host QUIC**: a UDP/443 session whose remote IP wasn't
  preceded by a DNS lookup. Apps that hard-code IPs (some game and
  telemetry clients) do this legitimately; malware also does it.
- **Long-lived QUIC** to one (unknown-host) IP, especially with
  regular keepalives — feeds `ALERT_BEACONING` detection. See
  [`alerts.md`](alerts.md#beaconing).

## Caveats

- Encrypted-Client-Hello (ECH) is rolling out — when present, the SNI
  is also encrypted and the "Host" column may stay empty even for
  known sites.

## See also

- Parser: [`src/quic_log.c`](../../src/quic_log.c).
- See [`tls.md`](tls.md) for the TCP/443 equivalent.
