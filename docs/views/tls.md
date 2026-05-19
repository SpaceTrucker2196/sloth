# TLS  `[t]`

ClientHello log: SNI hostname, TLS version, and JA3 fingerprint for
every encrypted-traffic handshake on TCP/443.

## Protocol

TLS (Transport Layer Security, [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)
for 1.3, [RFC 5246](https://www.rfc-editor.org/rfc/rfc5246) for 1.2)
encrypts the rest of the conversation but the first frame (ClientHello)
is plaintext. Sloth pulls out:

- Server name from the SNI extension (the hostname the client wanted).
- Negotiated version — `legacy_version` field plus the
  `supported_versions` extension. TLS 1.3 hides itself behind `1.2` in
  the legacy field, so sloth checks both.
- Cipher suites, extensions, supported groups, EC point formats — fed
  into [JA3](https://github.com/salesforce/ja3): a stable MD5 hash of
  the client's negotiation parameters.

## What sloth captures

Per entry: src, dst, host (SNI), version (`TLS 1.3` / `1.2` / `1.1` /
`1.0` / unknown), and the 32-char hex JA3. GREASE values (RFC 8701) are
filtered out of the JA3 inputs so the hash stays stable across browser
restarts.

## View

```
 ── TLS connections  /443/ ───────────────────────────────────────────
 Time      Src              Host (SNI)             Ver       JA3          Dst
 19:42:01  192.168.1.5      google.com             TLS 1.3   deadbeefcafe  142.250.80.46
 19:42:02  192.168.1.5      api.github.com         TLS 1.3   771,4865-486… 140.82.121.6
 19:42:03  10.0.0.5         (no SNI)               TLS 1.2   e7d705a3286e  93.184.216.34
                            ^                      ^         ^
                            brand-coloured        bright     12-char prefix
                            (google, github, ...)            of the MD5
```

## What's normal

- Modern browsers and apps use TLS 1.3 almost exclusively. ~95% of
  traffic should show `TLS 1.3`.
- SNI is usually populated (eSNI / ECH is rare today).
- JA3 hashes for a given browser version are stable. The big browsers
  have well-known public fingerprints.

## What's suspicious

- **No SNI** on outbound 443: most apps include SNI; the few that don't
  are usually doing something deliberately privacy-preserving (or
  hiding). Worth a closer look on a client that normally browses.
- **TLS 1.0 / 1.1**: deprecated 2020. Either an old IoT gadget or an
  attacker trying to negotiate weak crypto. Renders in heat-orange.
- **JA3 mismatch**: the JA3 doesn't match what the host's User-Agent
  claims to be. Classic implant signature — malware often uses a
  custom TLS library whose JA3 doesn't match Chrome/Firefox even when
  the UA says it's a browser.
- **Threat-intel domain in SNI**: triggers `ALERT_THREAT_DOMAIN` CRIT.
- **Mass-flush of clienthellos** to many distinct SNIs in seconds:
  scanning behaviour, or browser cache rebuild.

## See also

- JA3 implementation: [`src/tls_log.c`](../../src/tls_log.c) — wraps
  the embedded MD5 in [`src/md5.c`](../../src/md5.c), verified against
  RFC 1321 test vectors.
- Catalogue of common JA3 fingerprints:
  [salesforce/ja3](https://github.com/salesforce/ja3).
- ssllabs.com → "Client" / "Server" for the version landscape.
