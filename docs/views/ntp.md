# NTP  `[p]`

Network Time Protocol traffic on UDP/123 — mode, stratum, reference ID.

## Protocol

NTP ([RFC 5905](https://www.rfc-editor.org/rfc/rfc5905)) is how nearly
every connected device keeps its clock accurate. Each packet has a
fixed 48-byte header carrying:

- **Mode**: client (3), server (4), sym-active (1), sym-passive (2),
  broadcast (5), control (6).
- **Stratum**: 0 = unspec, 1 = primary (reference clock like a
  GPS), 2..15 = secondary, 16 = unsynchronised.
- **Reference Identifier**: a 4-byte field that's either ASCII
  ("GPS", "PPS", "DCF", "INIT", "STEP") for stratum 0/1/16, or an
  IPv4 address of the upstream server for stratum 2..15.

## What sloth captures

Per packet: src, dst, mode (string), version (1..4), stratum,
reference identifier.

## View

```
 ── NTP packets ────────────────────────────────────────────────
 src              dst              Mode      V    St   Ref
 192.168.1.5      pool.ntp.org     client    4    0    -
 10.0.0.1         192.168.1.5      server    4    1    GPS       ← stratum-1 GPS
 17.253.14.251    192.168.1.5      server    4    3    17.253.14.251
 1.2.3.4          192.168.1.5      server    4    16   INIT      ← unsynced
```

Stratum 1 = bright (primary clock). Stratum 0 or 16 = heat orange
(unsynced). The rest: normal.

## What's normal

- Your devices talk to a small set of NTP servers — `pool.ntp.org`,
  `time.apple.com`, `time.google.com`, or your router.
- Stratum 2 or 3 for most responses (true stratum-1 is rare on the
  open internet).

## What's suspicious

- **Mode 6 (control)** or **mode 7 (private)** packets from anything
  but you running `ntpq -c rv`. These modes have been used for
  reflection/amplification attacks
  ([CVE-2013-5211](https://nvd.nist.gov/vuln/detail/CVE-2013-5211),
  the `monlist` query had a 5000x amplification factor before being
  disabled).
- **Stratum 0 with a kiss-code** like `RATE`, `DENY`, or `DROP`:
  the server is rate-limiting or rejecting you. Investigate why.
- **An unexpected NTP server IP** showing up in client queries —
  someone deployed a rogue time source on the network. Time
  drift can break Kerberos, TLS validity windows, and HMAC nonces.
- **Multiple time sources with widely different stratum/ref** —
  client is confused or being attacked
  ([Khronos / Chronos](https://www.cs.bu.edu/~goldbe/papers/NTP_thesis.pdf)).
- **NTP traffic to / from a host that has no business with time
  sync** — likely a tunnel.

## See also

- Parser: [`src/ntp_log.c`](../../src/ntp_log.c).
- Amplification reference:
  [CERT VU#348126](https://www.kb.cert.org/vuls/id/348126).
