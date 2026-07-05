# HTTP  `[h]`

Plaintext HTTP request log: method, host, path.

## Protocol

HTTP/1.x ([RFC 9110-9112](https://www.rfc-editor.org/rfc/rfc9110)) is
the unencrypted web protocol. Most modern traffic on port 80/8080/8000
is either:

- Captive-portal probing (NCSI from Windows, captiveportal.kde.org,
  etc.).
- Old apps / IoT gadgets that never moved to HTTPS.
- HTTP-to-HTTPS redirects.

Anything important on these ports today is suspect.

## What sloth captures

Per entry: src, host (`Host:` header), method (`GET`, `POST`, etc.),
path, and the 49-char **JA4H** client fingerprint. The parser in
[`src/http_log.c`](../../src/http_log.c) bails on the first
non-printable byte, so binary protocols on these ports don't
pollute the log.

### JA4H

FoxIO's JA4H — the HTTP sibling of JA3/JA4 for TLS — encodes the
client's HTTP behaviour in 49 chars: `a(10) _ b(12) _ c(12) _ d(12)`.

```
   ge 11 n n 08 en _ 8daaf6152771 _ 000000000000 _ 000000000000
   │  │  │ │ │  │    └── sha256[:12] of sorted cookie name=value pairs
   │  │  │ │ │  │        (all zeros when no cookies)
   │  │  │ │ │  └────── first 2 chars of first Accept-Language tag
   │  │  │ │ └───────── count of non-cookie / non-referer headers
   │  │  │ └────────── 'r' if Referer header present, 'n' if not
   │  │  └─────────── 'c' if Cookie header present, 'n' if not
   │  └────────────── HTTP version: "11" / "10" / "20"
   └───────────────── first 2 chars of method, lowercased ("ge",
                      "po", "pu", "de", "co")
```

Section b hashes the header names in **observed order** (unlike
JA4's sort-then-hash — HTTP clients don't reorder headers between
runs, so order carries signal). Sections c and d hash the sorted
cookie names and sorted cookie name=value pairs, so cookie ordering
doesn't affect the fingerprint. Emitted alongside the other HTTP
fields in JSONL as `ja4h`.

## View

```
 ── HTTP log ────────────────────────────────────────────────────
 Time      Src              Host                   Method  Path
 21:00:01  192.168.1.5      detectportal.firefox…  GET     /success.txt
 21:00:01  192.168.1.5      www.msftncsi.com       GET     /ncsi.txt
 21:00:02  192.168.1.20     iot-device.local:80    POST    /api/update
 21:00:03  192.168.1.5      old-internal-app       GET     /login
```

## What's normal

- Captive-portal probes from OS background services.
- A handful of internal sites still on HTTP.

## What's suspicious

- **Cleartext credentials**: `POST /login` to a non-HTTPS host carrying
  sensitive content. The path doesn't tell you the body, but the
  pattern is a flag.
- **Long random-looking paths**: command-and-control beacons sometimes
  use HTTP/80 with random URIs to blend in. Pair with
  [BEACONING](alerts.md#beaconing) alerts.
- **Unusual User-Agent in path** (some malware encodes UA into the
  URL because they don't bother forging the real header).
- **Threat-intel host hit**: hosts matching the embedded IOC list
  fire [`ALERT_THREAT_DOMAIN`](alerts.md#threat_domain).
- **HTTP on a host that should only do HTTPS** (browsers, mail
  clients): could mean a proxy is downgrading the connection
  (intentional MITM, or
  [sslstrip](https://github.com/moxie0/sslstrip)).

## See also

- Parser: [`src/http_log.c`](../../src/http_log.c)
- TLS for the encrypted equivalent: [`tls.md`](tls.md).
