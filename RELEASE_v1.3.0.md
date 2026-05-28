# sloth v1.3 — integration + hardening

The integration release. v1.2 added detection rules; v1.3 opens sloth to the outside world with a read-only data socket and reference SIEM integrations, adds three new HTTP/TLS alert rules, introduces the OSI synthesis view, and hardens the test suite with a 9-round mutation-testing campaign.

## Data socket — live JSONL streaming

New `--data-socket SPEC` flag opens a **read-only** UNIX or TCP stream that emits every observed event as newline-delimited JSON. External tools consume the stream without touching sloth internals.

Spec formats:
- `unix:/tmp/sloth.sock` — UNIX domain socket (filesystem path)
- `tcp:127.0.0.1:9200` — TCP listener (loopback recommended)

Contract: connect, receive JSONL, reconnect on EOF. No auth, no write path, no control surface.

## Reference examples

| Path | What it does |
|---|---|
| `examples/consumer/` | Python stdlib-only data-socket consumer — connect, parse, filter, reconnect |
| `examples/forwarder/` | SIEM forwarder with three sinks: **Splunk HEC** (HTTPS JSON), **RFC 5424 syslog** (UDP/TCP), **Elasticsearch Bulk API** (NDJSON, time-rolled indices). Batching, exponential-backoff retries, pluggable sink interface |

## New alert rules

| Rule | Severity | Signal |
|---|---|---|
| `WEAK_TLS` | WARN | TLS 1.0/1.1 or weak cipher suites negotiated |
| `ATTACK_PATH` | CRIT | HTTP requests to sensitive paths (.env, wp-admin, phpinfo, etc.) |
| `ATTACK_TOOL_UA` | WARN | Known attack-tool User-Agents (sqlmap, nikto, gobuster, etc.) |

**16 total alert rules** (was 14 in v1.2).

## New views

| Key | View | What it shows |
|---|---|---|
| `l` | OSI / TCP-IP stack | Layer-by-layer synthesis — L7 protocols, L4 connections, L3 hosts, L2 devices, L1 interface |

**30 total views** (was 29 in v1.2).

## Dashboard improvements

- **Three-tier severity palette** — WARN=yellow, HIGH=orange, CRIT=red across all panels
- **Dashboard refactor** — monolithic 1863-line dashboard.c split into orchestrator + primitives + bands + grid
- **Alert-hot IP colouring** now covers all three severity tiers

## Platform

- **macOS (Darwin) build support** — Makefile detects platform and adjusts linker flags

## Test hardening — mutation testing

9-round mutation-testing campaign using a custom harness (tools/mutate/):
- 2311 total mutants generated across core modules
- 938 killed / 1844 considered (51% kill rate; remaining are equivalent mutants)
- Protocol parsers, alert engines, export paths, DNS snoop, host cache, threat intel, DGA covered
- **2122 test assertions** (was 1936 in v1.2)

## Stats

- 31 commits since v1.2
- 16 alert rules
- 30 views
- 2122 test assertions
- 3 new example programs

## Upgrade

```
git pull
make
sudo ./sloth --data-socket unix:/tmp/sloth.sock --eapol-dir /tmp/sloth-eapol -o /tmp/sloth.jsonl
```
