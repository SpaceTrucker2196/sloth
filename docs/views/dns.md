# DNS  `[r]`

Structured log of every DNS query and response seen on UDP/53.

## Protocol

DNS (Domain Name System, [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034)
+ [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)) is the lookup service
that turns names into IPs. The wire format is plaintext over UDP/53 (TCP/53
for large responses + zone transfers). Sloth parses the header (12 bytes),
the question section, and the first answer record — it does **not** call
out to a resolver; only what's already crossing the wire.

## What sloth captures

Per entry: source IP, qname (query name), qtype (`A`, `AAAA`, `PTR`, `MX`,
`NS`, `CNAME`, `TXT`, `SRV`), the first A/AAAA answer or `NXDOMAIN`, and
the Q/R flag. The independent parser in `src/dns_log.c` (own
`read_name()`, own compression-pointer handling) means a malformed
packet here won't poison the DNS resolver cache used elsewhere.

## View

```
 ── DNS log  /chrome/ ───────────────────────────────────────────────
 Time      Src              Q/R  Type   Name                  Answer
 18:16:40  192.168.1.5      R    A      google.com            142.250.80.46
 18:16:40  192.168.1.5      Q    AAAA   reddit.com            -
 18:16:40  192.168.1.10     R    A      ghost.local           NXDOMAIN
 18:16:40  192.168.1.5      R    A      cloudflare.com        104.16.132.229
 18:16:40  10.0.0.50        R    A      <random>.example.org  93.184.216.34
                                        └──────────────┘
                                        brand-coloured: google
                                        rainbow, cloudflare red,
                                        firefox orange, example.org grey
```

Q-row colour: dim. R-row with IP answer: bright Fallout phosphor.
NXDOMAIN: heat orange. AAAA: cool teal.

## What's normal

- Most queries are `A` and `AAAA` for popular domains; responses come back
  within a fraction of a second.
- A burst on startup, then steady-state of 1–10 q/s per active client.
- NXDOMAIN ratio under 5% — typos, autofill misses.

## What's suspicious

- **NXDOMAIN burst**: ≥10 NXDOMAIN responses to one source in 60 s.
  Triggers `ALERT_NXDOMAIN_BURST`. Common signal for [DGA-based
  malware](https://en.wikipedia.org/wiki/Domain_generation_algorithm) —
  the implant tries hundreds of random-looking names until one resolves.
- **High-entropy qnames**: `gfh3jksdfh92.example.com`-style labels —
  DGA, DNS tunnelling (data exfil), or cache busting.
- **Long TXT queries**: TXT records carrying base64 are a tunnel
  signature ([iodine](https://github.com/yarrick/iodine),
  [dnscat2](https://github.com/iagox86/dnscat2)).
- **Threat-intel hits**: qname matches the embedded IOC list →
  `ALERT_THREAT_DOMAIN` fires CRIT.
- **Resolver redirection**: queries going to an IP that isn't your
  configured resolver may indicate DNS hijack (router compromise, ARP
  spoof + transparent proxy).

## See also

- The brand colouriser highlights `google` letter-by-letter (Google
  logo colours), and `firefox` / `cloudflare` / `example.org` in their
  brand colours.
- Threat intel list lives in [`src/threat_intel.c`](../../src/threat_intel.c).
