# sloth-forward — reference SIEM forwarder

A Python 3 program that reads the live JSONL stream from a running
sloth's `--data-socket SPEC` and pushes the records to a SIEM. Three
sinks ship in this reference:

| Sink      | Use                                                          |
|-----------|--------------------------------------------------------------|
| `hec`     | Splunk HTTP Event Collector — JSON envelopes over HTTPS POST |
| `syslog`  | RFC 5424 syslog over UDP or TCP                              |
| `elastic` | Elasticsearch Bulk API (`POST /_bulk`) — NDJSON, time-rolled indices, basic auth or API key |

Stdlib only. Python 3.7+. The sink interface is two lines of code
(`name`, `send(batch)`); use it as a template for Loki, Elasticsearch,
Datadog, your in-house collector — ~30 lines per sink.

The wire-format contract this script codes against is
[`docs/wiki/jsonl-schema.md`](../../docs/wiki/jsonl-schema.md). The
read loop is identical to the reference consumer in
[`../consumer/`](../consumer/) — start there if you haven't read it.

---

## Delivery semantics (important)

This forwarder mirrors sloth's own design (MISSION.md §4): the data
socket is **non-durable**, and the forwarder doesn't pretend otherwise.

- If the downstream sink fails after `--max-retries`, the batch is
  **dropped** and a count is logged to stderr.
- If the source disconnects (sloth restart, kernel reset, slow-client
  reap), the in-flight batch is flushed and the loop reconnects with
  a 1 s backoff. Records emitted during the disconnect window are
  gone.
- The stats line (every `--stats-interval` seconds, default 30 s) is
  the operator's ground truth: `received` ≥ `forwarded + dropped`.

**If your deployment needs durability**, also pass `-o /var/log/sloth.jsonl`
to sloth and ship the file with a log-shipping agent (filebeat,
vector, fluent-bit) on a separate path. That pipeline gives you
durability; this one gives you low-latency triage.

---

## Splunk HEC

```sh
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --sink hec \
    --hec-url   https://splunk.example.com:8088/services/collector \
    --hec-token aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

Each sloth record is wrapped in the standard HEC envelope and the
batch is POSTed as one body of newline-delimited envelopes:

```json
{
  "time":       1700000000.0,
  "host":       "sloth-monitor-01",
  "source":     "sloth",
  "sourcetype": "sloth:jsonl",
  "event":      { "type":"dns", "ts":1700000000, "src":"...", ... }
}
```

- `--hec-source` / `--hec-sourcetype` / `--hec-host` / `--hec-index`
  override the defaults.
- `--hec-token-env SLOTH_HEC_TOKEN` reads the token from an
  environment variable so it doesn't appear in `ps`.
- `--hec-insecure` disables TLS cert verification. **Test only.**
  A real deployment should pin the certificate via the system trust
  store.

---

## RFC 5424 syslog

```sh
# UDP (default, classic syslog port)
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --sink syslog \
    --syslog-host siem.example.com \
    --syslog-port 514

# TCP — newline-delimited framing (non-TLS)
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --sink syslog --syslog-proto tcp \
    --syslog-host siem.example.com --syslog-port 6514
```

One syslog message per sloth record. Layout (RFC 5424 §6):

```
<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
```

- `PRI` defaults to **134** (`local0.info` = `16*8 + 6`). Override
  with `--syslog-pri`.
- `VERSION` is `1`. `TIMESTAMP` is the record's `ts` in UTC ISO-8601.
- `MSGID` is the record's `type` (`dns` / `tls` / `alert` / …).
- `STRUCTURED-DATA` is `-` (none).
- `MSG` is the raw JSON record. Most modern collectors index this
  cleanly under a JSON-aware parser.

`PROCID` is hard-coded to `-` in this reference. If you have multiple
forwarders feeding the same SIEM, override the hostname per-instance
via `--syslog-hostname` so the collector can distinguish them.

---

## Elasticsearch

```sh
# Time-rolled index (one per UTC day), API key auth
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --sink elastic \
    --es-url       https://elastic.example.com:9200 \
    --es-index     'sloth-events-%Y.%m.%d' \
    --es-api-key-env SLOTH_ES_API_KEY

# Basic auth, single fixed index
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --sink elastic \
    --es-url      https://elastic.example.com:9200 \
    --es-index    sloth-events \
    --es-username elastic \
    --es-password-env SLOTH_ES_PASSWORD
```

Each batch is sent as one POST to `<es-url>/_bulk` with
`Content-Type: application/x-ndjson`. Body shape:

```
{"index":{"_index":"sloth-events-2024.05.27"}}
{"@timestamp":"2024-05-27T12:34:56.000Z","type":"dns","src":"...","qname":"..."}
{"index":{"_index":"sloth-events-2024.05.27"}}
{"@timestamp":"...","type":"alert","sev":2,...}
```

Highlights:

- **`@timestamp` is derived from each record's `ts` field** (ISO-8601
  UTC, millisecond precision). Elastic's default index template uses
  this for time-based search. The original `ts` (Unix seconds) is left
  on the document untouched.
- **Index name supports strftime tokens.** `sloth-events-%Y.%m.%d`
  resolves per-record from `ts`, so records emitted near midnight
  land in the correct daily index even if the forwarder is batching
  across the boundary.
- **Auth.** Pass either `--es-api-key(-env)` *or* `--es-username` +
  `--es-password(-env)`. API key wins if both are set (stronger
  credential). Use the `-env` variants on shared hosts to keep secrets
  out of `ps`.
- **Partial failures are batch-fatal.** Elastic's `_bulk` returns 200
  even when individual docs are rejected (mapping conflicts, illegal
  field names) — the body's `errors: true` flag distinguishes. This
  forwarder treats *any* per-item failure as a batch failure so the
  retry loop sees it. The first per-doc error is included in the
  stderr drop message so you know what to fix.
- **TLS.** `--es-insecure` disables cert verification. Test only.
- **Cloud / managed Elastic.** Point `--es-url` at the cloud cluster
  endpoint and pass the API key issued by Kibana → Stack Management
  → API keys. The Bulk API is the same.

A common production pattern is to define an index template on the
ES side that maps the sloth fields (`type`, `src`, `dst`, `ja3`, etc.)
to keyword/IP/text as appropriate, with a dynamic mapping fallback
for unknown fields. The forwarder itself stays schema-agnostic.

**OpenSearch compatibility.** OpenSearch's `_bulk` endpoint is
wire-compatible with Elasticsearch's; the same sink works against
an OpenSearch cluster with `--es-url` pointed at the OpenSearch
endpoint. Auth options (`--es-username` / `--es-password(-env)` /
`--es-api-key(-env)`) carry over.

## Grafana Loki

```sh
sloth-forward.py unix:/run/sloth.sock \
    --sink loki \
    --loki-url http://loki.example.com:3100 \
    --loki-job sloth \
    --loki-source edge-1
```

Records are POSTed to `/loki/api/v1/push` grouped by the `type` field
— each record-type becomes its own Loki stream so the label set stays
low-cardinality. Per-record fields (src, qname, ja3, …) ride in the
log line as raw JSON; query with `{job="sloth", type="alert"} | json
sev=~"2"` etc. to filter inside Grafana.

- **Multi-tenant Loki.** `--loki-tenant <id>` sets the
  `X-Scope-OrgID` header that Loki's gateway uses to scope tenants.
- **Basic auth.** `--loki-username` + `--loki-password(-env)`.
- **TLS.** `--loki-insecure` skips cert verification (test only).

See `examples/compose/` for a one-command stack that brings up a
local Loki + Grafana with this sink pre-wired.

## Datadog Logs

```sh
sloth-forward.py unix:/run/sloth.sock \
    --sink datadog \
    --dd-api-key-env DD_API_KEY \
    --dd-tags env:prod,region:us-east
```

POSTs `application/json` to Datadog's Logs intake (`/api/v2/logs`)
with each record wrapped in the documented envelope:

```json
{"ddsource": "sloth", "service": "sloth", "hostname": "...",
 "ddtags": "env:prod", "message": "<raw sloth JSON record>"}
```

`message` carries the raw sloth record so Datadog's automatic JSON
parsing pulls per-record fields (`type`, `src`, `qname`, `ja3`, …)
into Logs facets you can filter on.

- **Region / site.** `--dd-url` defaults to the US-1 site
  (`https://http-intake.logs.datadoghq.com/api/v2/logs`); override
  for EU, US3, US5, etc.
- **Source / service / hostname.** Override the default
  identifiers with `--dd-source` / `--dd-service` / `--dd-hostname`
  to integrate with your existing service catalog.
- **TLS.** `--dd-insecure` for self-signed test endpoints.

## Generic webhook

```sh
sloth-forward.py unix:/run/sloth.sock \
    --sink webhook \
    --webhook-url https://collector.example.com/ingest \
    --webhook-header "Authorization: Bearer $TOKEN" \
    --webhook-header "X-Service: sloth"
```

POSTs `application/json` with the batch wrapped as
`{"records": [...]}`. Useful as a primitive for any downstream
that takes JSON over HTTP — serverless functions, in-house
collectors, IFTTT, Zapier.

- **Auth.** `--webhook-header KEY:VAL` is repeatable; covers
  Bearer tokens, `X-API-Key`, basic auth, etc.
- **Slack / Discord.** The incoming-webhook formats for those
  services expect a `{"text": "..."}` body that's outside this
  sink's schema-agnostic remit. Write a tiny transform proxy if
  you need it (or use `--type alert` to keep volume sane and
  format in a Slack app rather than via the raw webhook).

## Filters and batching

```sh
# Forward only alerts
python3 sloth-forward.py unix:/tmp/sloth.sock --type alert \
    --sink hec --hec-url ... --hec-token ...

# Larger batches for high-volume deployments (HEC payload limit ~1MB)
python3 sloth-forward.py unix:/tmp/sloth.sock \
    --batch-size 500 --batch-ms 500 \
    --sink hec --hec-url ... --hec-token ...

# Restrict to traffic from a single source IP for targeted forwarding
python3 sloth-forward.py unix:/tmp/sloth.sock --src 10.0.0.5 \
    --sink syslog --syslog-host ... --syslog-port 514
```

The defaults (`--batch-size 100`, `--batch-ms 1000`) suit a few-events-
per-second deployment. Tune up for higher volumes — most SIEMs prefer
fewer, larger requests.

---

## Operating

- **One forwarder per sink.** The forwarder is single-threaded and
  synchronous. Running two forwarder processes (one per sink) is
  simpler than building multi-sink fan-out and gives you independent
  back-pressure handling.
- **Run under a supervisor** (systemd, runit, supervisord). The
  forwarder exits 0 on SIGINT and otherwise loops forever — your
  supervisor handles restarts on crash.
- **Watch the stats**: a non-zero `dropped` over a long window means
  the sink can't keep up (or is intermittently failing). Increase
  `--max-retries`, increase `--batch-size`, or fix the sink.

Example systemd unit:

```ini
# /etc/systemd/system/sloth-forward.service
[Service]
Type=simple
ExecStart=/usr/local/bin/python3 /opt/sloth/examples/forwarder/sloth-forward.py \
    unix:/var/run/sloth.sock \
    --sink hec \
    --hec-url https://splunk.example.com:8088/services/collector \
    --hec-token-env SLOTH_HEC_TOKEN
EnvironmentFile=/etc/sloth-forward.env
Restart=on-failure
User=sloth
NoNewPrivileges=true
```

with `/etc/sloth-forward.env` (0600, owned by `sloth`):

```
SLOTH_HEC_TOKEN=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
```

---

## Adding a sink

Two lines of contract. Look at `HECSink` / `SyslogSink` and copy the
shape:

```python
class MySink:
    name = "mysink"

    def __init__(self, ...):
        ...

    def send(self, batch: list) -> None:
        """Send `batch` (list of dicts). Raise on failure; the retry
        loop will catch (HTTPError, URLError, OSError) and decide
        whether to retry or drop."""
        ...
```

Wire it into `build_sink()` and add the `--sink mysink` plus any
`--mysink-*` CLI flags. The retry loop, batching, filtering, stats,
and reconnect logic all stay in `main()` — you only own the sink.

---

## Smoke-testing

A self-contained test in the same pattern as
[`../consumer/`](../consumer/) — spin up an in-process fake sloth
(UNIX-domain socket) and a fake HEC HTTP server, run the forwarder
against both, assert envelopes arrive in the expected shape. Useful
as a CI step for changes to the sink layer.
