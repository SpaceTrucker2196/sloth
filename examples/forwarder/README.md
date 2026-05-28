# sloth-forward — reference SIEM forwarder

A Python 3 program that reads the live JSONL stream from a running
sloth's `--data-socket SPEC` and pushes the records to a SIEM. Two
sinks ship in this reference:

| Sink     | Use                                                          |
|----------|--------------------------------------------------------------|
| `hec`    | Splunk HTTP Event Collector — JSON envelopes over HTTPS POST |
| `syslog` | RFC 5424 syslog over UDP or TCP                              |

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
