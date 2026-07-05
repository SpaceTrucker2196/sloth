# sloth v1.5.1 — HTTP fingerprint + cleartext-cred breadth

Point release rolling up the follow-up work called out in the v1.5.0
notes: JA4H (HTTP client fingerprint), the remaining cleartext-cred
protocols, and the stateful AUTH LOGIN exchange for SMTP. No new
alert types, no new views — this is protocol breadth and provenance
depth on top of the v1.5 baseline.

## JA4H — HTTP client fingerprint

TLS handshakes have carried JA3 + JA4 since v1.5.0. HTTP requests
now get **JA4H**, the same-family fingerprint for HTTP/1.x clients,
following the FoxIO spec. Emitted alongside the other HTTP fields
in JSONL as `ja4h`, and computed during the existing header walk
(no new capture surface).

Format is 49 chars: `a(10) _ b(12) _ c(12) _ d(12)`.

```
ge 11 n n 02 en _ 8daaf6152771 _ 000000000000 _ 000000000000
│  │  │ │ │  │
│  │  │ │ │  └── first 2 chars of Accept-Language ("00" if absent)
│  │  │ │ └───── count of non-cookie / non-referer headers
│  │  │ └─────── 'r' if Referer header present, 'n' if not
│  │  └───────── 'c' if Cookie header present, 'n' if not
│  └──────────── HTTP version: "11" / "10" / "20"
└─────────────── first 2 chars of method, lowercased
```

Section b hashes header names in **observed order** (HTTP clients
don't reorder headers between runs, so order carries signal, unlike
JA4 for TLS which sorts). Sections c and d hash sorted cookie names
and sorted cookie name=value pairs, so cookie insertion order
doesn't affect the fingerprint.

See [`docs/views/http.md`](docs/views/http.md) for the section
breakdown and [`docs/wiki/jsonl-schema.md`](docs/wiki/jsonl-schema.md)
for the wire format.

## Cleartext-cred coverage expanded

`CLEARTEXT_CRED` (T1040) fired on HTTP Basic and FTP in v1.5. It now
covers six protocols:

| Protocol         | Port(s)     | Shape                                     |
|------------------|-------------|-------------------------------------------|
| HTTP Basic       | 80/8080/8000| `Authorization: Basic <b64>` header       |
| FTP              | 21          | `USER <name>` / `PASS <value>`            |
| **POP3**         | **110**     | `USER <name>` / `PASS <value>`            |
| **IMAP**         | **143**     | `<tag> LOGIN <user> <pass>` (quoted OK)   |
| **SMTP AUTH PLAIN** | **25/587** | Single-shot `AUTH PLAIN <b64>` SASL     |
| **SMTP AUTH LOGIN** | **25/587** | Three-line stateful SASL exchange       |

Each protocol has its own snoop module (`src/pop3_snoop.c`,
`src/imap_snoop.c`, `src/smtp_snoop.c`) modelled on the FTP shape.

**AUTH LOGIN** needed per-flow state because the username arrives on
a separate line after the `AUTH LOGIN` verb. Small ring of 16 flow
records inside `smtp_snoop.c`, keyed by `(client, server, port)`,
LRU-evicted. Server-directed payloads (334 prompts) don't touch
state — the direction check is `dst_port == 25 || dst_port == 587`.

**Guardrail preserved across all six**: the password value is never
inspected past marking the flow. The recorder's public API has no
password parameter, enforcing the invariant at the module boundary.
The posture report and JSONL schema doc both call this out
explicitly.

Only **Telnet** remains uncovered — char-by-char across many small
packets, needs multi-packet reassembly, doesn't fit sloth's current
line-oriented snoop shape. Deferred to a follow-up when the snoop
layer gains per-flow byte reassembly.

## Test hygiene

The updater tests hard-coded literal `1.4.0` / `1.5.0` strings when
they were written pre-v1.5. After the v1.5.0 version bump, one
assertion regressed. Decoupled the tests from `SLOTH_VERSION` — the
"up to date" test uses `SLOTH_VERSION` itself, the "newer" test uses
`"99.99.0"` and the "older" test uses `"0.0.1"`, so future bumps
won't red the suite.

## Stats

- 3 substantive commits since v1.5.0
- 6 cleartext-cred protocols (+4)
- 3252 test assertions (+135)

## Upgrade

```
git pull
make
```

Nothing removed; the JSONL schema is additive (new `ja4h` field on
`http` records, more `protocol` values on `cleartext_cred`). Existing
consumers keep working.
