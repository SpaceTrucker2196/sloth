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
path. The parser in [`src/http_log.c`](../../src/http_log.c) bails on
the first non-printable byte, so binary protocols on these ports
don't pollute the log.

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
