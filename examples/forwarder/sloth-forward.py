#!/usr/bin/env python3
"""
sloth-forward — reference SIEM forwarder for the sloth JSONL data socket.

Reads records from a running sloth's `--data-socket SPEC`, batches them,
and pushes them to a downstream SIEM. Three sinks ship in this reference:

  hec     — Splunk HTTP Event Collector (POST batched JSON to /services/collector)
  syslog  — RFC 5424 syslog, UDP or TCP
  elastic — Elasticsearch Bulk API (POST NDJSON to /_bulk)

Stdlib only — Python 3.7+. The sink abstraction is deliberately small
so you can read the source as a template and add Loki, Elasticsearch,
Datadog, or your in-house collector with ~30 lines per sink.

DELIVERY SEMANTICS

This forwarder mirrors sloth's own design (MISSION.md §4): the data
socket is non-durable, and the forwarder doesn't pretend otherwise.
When the downstream sink fails after the configured retries, the
batch is **dropped** and a count is logged to stderr. If your
deployment needs durability, also pass `-o /var/log/sloth.jsonl`
to sloth and use a separate log-shipping agent (filebeat, vector,
fluent-bit) — that pipeline gives you durability, this one gives you
low-latency triage.

USAGE

  # Splunk HEC
  sloth-forward unix:/tmp/sloth.sock \\
      --sink hec --hec-url https://splunk.example.com:8088/services/collector \\
      --hec-token aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

  # Syslog (UDP, RFC 5424)
  sloth-forward unix:/tmp/sloth.sock \\
      --sink syslog --syslog-host siem.example.com --syslog-port 514

  # Elasticsearch Bulk API, time-rolled index
  sloth-forward unix:/tmp/sloth.sock \\
      --sink elastic \\
      --es-url   https://elastic.example.com:9200 \\
      --es-index 'sloth-events-%Y.%m.%d' \\
      --es-api-key-env SLOTH_ES_API_KEY

  # Filter to alerts only, batch every 200 events or 2 seconds
  sloth-forward tcp:127.0.0.1:8765 \\
      --type alert \\
      --sink hec --hec-url https://... --hec-token ... \\
      --batch-size 200 --batch-ms 2000

OPERATOR NOTES

  - HEC tokens are credentials. Pass via env var (`--hec-token-env
    SLOTH_HEC_TOKEN`) on shared hosts to keep them out of `ps`.
  - The forwarder is single-threaded and synchronous. One forwarder
    process per sink. Use systemd, runit, or your favourite supervisor.
  - For high-volume deployments, set --batch-size large (HEC payload
    limit is typically 1MB; ~500 sloth records per batch is comfortable)
    and --batch-ms small (200-500ms) — most SIEMs prefer fewer, larger
    requests.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Iterator, Optional


# ── Source: sloth data socket ────────────────────────────────────────

def parse_spec(spec: str) -> tuple:
    if spec.startswith("unix:"):
        return ("unix", spec[5:])
    if spec.startswith("tcp:"):
        rest = spec[4:]
        i = rest.rfind(":")
        if i < 0:
            raise ValueError(f"tcp spec needs HOST:PORT, got {spec!r}")
        return ("tcp", rest[:i], int(rest[i+1:]))
    raise ValueError(f"spec must start with 'unix:' or 'tcp:', got {spec!r}")


def connect_source(spec: tuple, timeout: float = 10.0) -> socket.socket:
    if spec[0] == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(spec[1])
    else:
        s = socket.create_connection((spec[1], spec[2]), timeout=timeout)
    s.settimeout(None)
    return s


def stream_lines(sock: socket.socket) -> Iterator[bytes]:
    buf = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            return
        buf += chunk
        while True:
            i = buf.find(b"\n")
            if i < 0:
                break
            yield buf[:i]
            buf = buf[i+1:]


# ── Sinks ────────────────────────────────────────────────────────────
#
# A sink exposes:
#   .name        — short string for stats / logs
#   .send(batch) — raises on failure; returns silently on success
#
# Failure surfaces to the retry loop which decides whether to retry
# or drop. The sink does no buffering of its own.

class HECSink:
    """Splunk HTTP Event Collector. Newline-delimited JSON envelopes,
    one envelope per sloth record, POSTed in a single body.

    Reference: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
    """

    name = "hec"

    def __init__(self, url: str, token: str,
                 source: str = "sloth",
                 sourcetype: str = "sloth:jsonl",
                 host: Optional[str] = None,
                 index: Optional[str] = None,
                 verify_tls: bool = True,
                 timeout: float = 10.0):
        self.url = url
        self.token = token
        self.source = source
        self.sourcetype = sourcetype
        self.host = host or socket.gethostname()
        self.index = index
        self.timeout = timeout
        if verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl._create_unverified_context()

    def _envelope(self, r: dict) -> dict:
        env = {
            "time":       float(r.get("ts", time.time())),
            "host":       self.host,
            "source":     self.source,
            "sourcetype": self.sourcetype,
            "event":      r,
        }
        if self.index:
            env["index"] = self.index
        return env

    def send(self, batch: list) -> None:
        body = "\n".join(json.dumps(self._envelope(r)) for r in batch)
        req = urllib.request.Request(
            self.url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Splunk {self.token}",
                "Content-Type":  "application/json",
                "User-Agent":    "sloth-forward/1",
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout,
                                     context=self.ssl_ctx) as resp:
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, resp.reason, resp.headers, None,
                )


class SyslogSink:
    """RFC 5424 syslog. UDP or TCP. The structured payload is the raw
    JSON record as the syslog MSG; STRUCTURED-DATA is `-` (none).

    Reference: https://datatracker.ietf.org/doc/html/rfc5424
    """

    name = "syslog"

    # PRI = (facility * 8) + severity. local0 + info = 16*8 + 6 = 134.
    DEFAULT_PRI = 134

    def __init__(self, host: str, port: int,
                 proto: str = "udp",
                 app_name: str = "sloth",
                 hostname: Optional[str] = None,
                 pri: int = DEFAULT_PRI,
                 timeout: float = 10.0):
        if proto not in ("udp", "tcp"):
            raise ValueError("syslog proto must be 'udp' or 'tcp'")
        self.host = host
        self.port = port
        self.proto = proto
        self.app_name = app_name
        self.hostname = hostname or socket.gethostname()
        self.pri = pri
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def _ensure_connected(self) -> None:
        if self.sock is not None:
            return
        if self.proto == "udp":
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout,
            )

    def _drop_connection(self) -> None:
        try:
            if self.sock is not None:
                self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _format(self, r: dict) -> bytes:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S",
                            time.gmtime(float(r.get("ts", time.time()))))
        msgid = r.get("type", "-") or "-"
        # `MSG` is the JSON record verbatim. RFC 5424 allows arbitrary
        # printable octets; some collectors (rsyslog, syslog-ng) prepend
        # `\xef\xbb\xbf` (BOM) on the MSG; we don't, but a real
        # deployment may need to.
        msg = json.dumps(r, separators=(",", ":"))
        line = (f"<{self.pri}>1 {ts}Z {self.hostname} "
                f"{self.app_name} - {msgid} - {msg}")
        return line.encode("utf-8", "replace")

    def send(self, batch: list) -> None:
        self._ensure_connected()
        try:
            for r in batch:
                payload = self._format(r)
                if self.proto == "udp":
                    self.sock.sendto(payload, (self.host, self.port))
                else:
                    # RFC 6587 §3.4.2 — Octet Counting framing. Common
                    # for TLS-wrapped syslog. Plain TCP often uses
                    # LF-delimited; we use LF here to keep the example
                    # readable.
                    self.sock.sendall(payload + b"\n")
        except OSError:
            self._drop_connection()
            raise


class ESSink:
    """Elasticsearch Bulk API. NDJSON body of (action, doc) pairs POSTed
    to `<es-url>/_bulk`. Adds `@timestamp` to every doc derived from the
    record's `ts` field (Elastic's idiomatic time field). Index name
    supports strftime tokens for time-rolled indices (e.g.
    `sloth-events-%Y.%m.%d`).

    Reference: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-bulk.html
    """

    name = "elastic"

    def __init__(self, url: str,
                 index_pattern: str = "sloth-events",
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 api_key: Optional[str] = None,
                 verify_tls: bool = True,
                 timeout: float = 10.0):
        self.url = url.rstrip("/") + "/_bulk"
        self.index_pattern = index_pattern
        self.timeout = timeout
        self.auth_header = self._auth_header(username, password, api_key)
        if verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl._create_unverified_context()

    @staticmethod
    def _auth_header(username, password, api_key) -> Optional[str]:
        # API key wins when both are set — it's the stronger credential.
        if api_key:
            return f"ApiKey {api_key}"
        if username and password:
            import base64
            tok = base64.b64encode(f"{username}:{password}".encode()).decode()
            return f"Basic {tok}"
        return None

    def _index_for(self, r: dict) -> str:
        ts = float(r.get("ts", time.time()))
        return time.strftime(self.index_pattern, time.gmtime(ts))

    @staticmethod
    def _doc(r: dict) -> dict:
        # Elastic indexes on `@timestamp` by default. Add it without
        # mutating the input record (the same dict may be in another
        # sink's batch).
        doc = dict(r)
        ts = float(r.get("ts", time.time()))
        doc["@timestamp"] = time.strftime(
            "%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(ts),
        )
        return doc

    def send(self, batch: list) -> None:
        # NDJSON body: alternating action / doc lines. Trailing newline
        # required by ES.
        lines = []
        for r in batch:
            action = {"index": {"_index": self._index_for(r)}}
            lines.append(json.dumps(action))
            lines.append(json.dumps(self._doc(r)))
        body = ("\n".join(lines) + "\n").encode("utf-8")

        headers = {
            "Content-Type": "application/x-ndjson",
            "User-Agent":   "sloth-forward/1",
        }
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=self.timeout,
                                     context=self.ssl_ctx) as resp:
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, resp.reason, resp.headers, None,
                )
            # ES Bulk returns 200 even when *individual* docs were
            # rejected (mapping conflicts, illegal field names). Check
            # the `errors` flag and raise so the retry loop can see it.
            payload = resp.read()
            try:
                result = json.loads(payload.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                return  # ES should always be JSON; tolerate if not
            if not result.get("errors"):
                return
            items = result.get("items", [])
            failed = []
            for item in items:
                # Each item is {"<op>": {...}} where op is index/create.
                for op, info in item.items():
                    if "error" in info:
                        failed.append(info.get("error"))
                        break
            raise OSError(
                f"elastic _bulk partial failure: "
                f"{len(failed)}/{len(items)} docs rejected; "
                f"first error: {failed[0] if failed else '?'}"
            )


class LokiSink:
    """Grafana Loki push API. POSTs `application/json` to
    `<loki-url>/loki/api/v1/push` with the documented "streams" envelope:
    one stream per `type` field so Loki indexes the labels separately.

    Loki labels are intentionally low-cardinality — we expose `type`
    and the configured `job`/`source` only. Per-record fields (src,
    qname, ja3, …) ride in the log line as the raw JSON.

    Reference: https://grafana.com/docs/loki/latest/reference/api/#push-log-entries-to-loki
    """

    name = "loki"

    def __init__(self, url: str, job: str = "sloth", source: str = "sloth",
                 tenant_id: Optional[str] = None,
                 username: Optional[str] = None,
                 password: Optional[str] = None,
                 verify_tls: bool = True,
                 timeout: float = 10.0):
        self.url = url.rstrip("/") + "/loki/api/v1/push"
        self.job = job
        self.source = source
        self.tenant_id = tenant_id
        self.timeout = timeout
        if username and password:
            import base64
            tok = base64.b64encode(f"{username}:{password}".encode()).decode()
            self.auth_header = f"Basic {tok}"
        else:
            self.auth_header = None
        if verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl._create_unverified_context()

    def send(self, batch: list) -> None:
        # Group records by `type` so each record-type gets its own stream
        # (= label set). Loki rejects pushes where timestamps in a stream
        # aren't monotonic; we sort each stream by ts to be safe.
        streams: dict = {}
        for r in batch:
            t = r.get("type", "unknown")
            streams.setdefault(t, []).append(r)

        stream_arr = []
        for t, recs in streams.items():
            recs.sort(key=lambda x: float(x.get("ts", 0)))
            values = []
            for r in recs:
                # Loki ts is nanoseconds since epoch, as a string.
                ts_ns = int(float(r.get("ts", time.time())) * 1e9)
                values.append([str(ts_ns), json.dumps(r)])
            stream_arr.append({
                "stream": {
                    "job":    self.job,
                    "source": self.source,
                    "type":   t,
                },
                "values": values,
            })

        body = json.dumps({"streams": stream_arr}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "sloth-forward/1",
        }
        if self.tenant_id:
            headers["X-Scope-OrgID"] = self.tenant_id
        if self.auth_header:
            headers["Authorization"] = self.auth_header

        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=self.timeout,
                                     context=self.ssl_ctx) as resp:
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, resp.reason, resp.headers, None,
                )


class DatadogSink:
    """Datadog Logs intake. POSTs `application/json` to the configured
    site URL (default US-1) carrying a batch of log entries. Each
    entry uses the documented Datadog envelope:
      { ddsource, ddtags, hostname, service, message }
    `message` is the raw sloth JSON record so Datadog's automatic
    JSON parsing pulls the per-record fields into facets.

    Reference: https://docs.datadoghq.com/api/latest/logs/#send-logs
    """

    name = "datadog"

    def __init__(self, api_key: str,
                 url: str = "https://http-intake.logs.datadoghq.com/api/v2/logs",
                 source: str = "sloth",
                 service: str = "sloth",
                 hostname: Optional[str] = None,
                 tags: Optional[str] = None,
                 verify_tls: bool = True,
                 timeout: float = 10.0):
        self.api_key = api_key
        self.url = url
        self.source = source
        self.service = service
        self.hostname = hostname or socket.gethostname()
        self.tags = tags
        self.timeout = timeout
        if verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl._create_unverified_context()

    def send(self, batch: list) -> None:
        # Datadog accepts an array of envelope objects per request,
        # up to 1000 entries / 5 MB. The forwarder's batch sizes (≤100
        # by default) stay well inside that window.
        envelopes = []
        for r in batch:
            env = {
                "ddsource": self.source,
                "service":  self.service,
                "hostname": self.hostname,
                "message":  json.dumps(r),
            }
            if self.tags:
                env["ddtags"] = self.tags
            envelopes.append(env)
        body = json.dumps(envelopes).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "sloth-forward/1",
            "DD-API-KEY":   self.api_key,
        }
        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=self.timeout,
                                     context=self.ssl_ctx) as resp:
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, resp.reason, resp.headers, None,
                )


class WebhookSink:
    """Generic webhook — POSTs `application/json` to an arbitrary URL
    with the batch wrapped as `{"records": [...]}`. Useful as a primitive
    for any downstream that takes JSON over HTTP (in-house collectors,
    serverless functions, IFTTT, Zapier).

    For Slack / Discord incoming webhooks, write a tiny transform proxy:
    those expect a `{"text": "..."}` shape that's outside this sink's
    schema-agnostic remit.

    Custom headers via --webhook-header KEY:VAL (repeatable) cover the
    common auth patterns (Bearer tokens, X-API-Key, basic auth, etc.).
    """

    name = "webhook"

    def __init__(self, url: str,
                 headers: Optional[list] = None,
                 verify_tls: bool = True,
                 timeout: float = 10.0):
        self.url = url
        self.timeout = timeout
        self.headers = {}
        for kv in (headers or []):
            if ":" not in kv:
                raise SystemExit(
                    f"--webhook-header value {kv!r} must be KEY:VAL"
                )
            k, v = kv.split(":", 1)
            self.headers[k.strip()] = v.strip()
        if verify_tls:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl._create_unverified_context()

    def send(self, batch: list) -> None:
        body = json.dumps({"records": batch}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "User-Agent":   "sloth-forward/1",
        }
        headers.update(self.headers)
        req = urllib.request.Request(
            self.url, data=body, method="POST", headers=headers,
        )
        with urllib.request.urlopen(req, timeout=self.timeout,
                                     context=self.ssl_ctx) as resp:
            if resp.status >= 400:
                raise urllib.error.HTTPError(
                    self.url, resp.status, resp.reason, resp.headers, None,
                )


# ── Batch + retry ────────────────────────────────────────────────────

class Stats:
    """Periodic counters. Printed to stderr every `interval_s`."""

    def __init__(self, interval_s: float = 30.0):
        self.interval = interval_s
        self.received = 0
        self.forwarded = 0
        self.dropped = 0
        self.retries = 0
        self.last_print = time.monotonic()

    def maybe_print(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self.last_print < self.interval:
            return
        print(f"# sloth-forward: received={self.received} "
              f"forwarded={self.forwarded} "
              f"dropped={self.dropped} retries={self.retries}",
              file=sys.stderr, flush=True)
        self.last_print = now


def send_with_retry(sink, batch: list, max_retries: int,
                     backoff_s: float, stats: Stats) -> bool:
    """Send `batch`, retrying on transient errors. Returns True on
    success, False if the batch was dropped after max_retries."""
    attempt = 0
    delay = backoff_s
    while True:
        try:
            sink.send(batch)
            return True
        except (urllib.error.HTTPError, urllib.error.URLError,
                OSError) as e:
            attempt += 1
            stats.retries += 1
            if attempt > max_retries:
                print(f"# sink {sink.name} failed after {max_retries} "
                      f"retries; dropping {len(batch)} record(s): {e}",
                      file=sys.stderr, flush=True)
                return False
            print(f"# sink {sink.name} attempt {attempt} failed: {e}; "
                  f"retrying in {delay:.1f}s",
                  file=sys.stderr, flush=True)
            time.sleep(delay)
            delay *= 2.0


# ── CLI / sink construction ──────────────────────────────────────────

def build_sink(args) -> object:
    if args.sink == "hec":
        if not args.hec_url:
            raise SystemExit("--sink hec needs --hec-url")
        token = args.hec_token
        if not token and args.hec_token_env:
            token = os.environ.get(args.hec_token_env)
        if not token:
            raise SystemExit(
                "--sink hec needs --hec-token or --hec-token-env "
                "pointing at an env var that holds the token"
            )
        return HECSink(
            url=args.hec_url,
            token=token,
            source=args.hec_source,
            sourcetype=args.hec_sourcetype,
            host=args.hec_host,
            index=args.hec_index,
            verify_tls=not args.hec_insecure,
        )
    if args.sink == "syslog":
        return SyslogSink(
            host=args.syslog_host,
            port=args.syslog_port,
            proto=args.syslog_proto,
            app_name=args.syslog_app,
            hostname=args.syslog_hostname,
            pri=args.syslog_pri,
        )
    if args.sink == "elastic":
        if not args.es_url:
            raise SystemExit("--sink elastic needs --es-url")
        password = args.es_password
        if not password and args.es_password_env:
            password = os.environ.get(args.es_password_env)
        api_key = args.es_api_key
        if not api_key and args.es_api_key_env:
            api_key = os.environ.get(args.es_api_key_env)
        if not (api_key or (args.es_username and password)):
            raise SystemExit(
                "--sink elastic needs either --es-api-key(-env) or "
                "--es-username + --es-password(-env)"
            )
        return ESSink(
            url=args.es_url,
            index_pattern=args.es_index,
            username=args.es_username,
            password=password,
            api_key=api_key,
            verify_tls=not args.es_insecure,
        )
    if args.sink == "loki":
        if not args.loki_url:
            raise SystemExit("--sink loki needs --loki-url")
        password = args.loki_password
        if not password and args.loki_password_env:
            password = os.environ.get(args.loki_password_env)
        return LokiSink(
            url=args.loki_url,
            job=args.loki_job,
            source=args.loki_source,
            tenant_id=args.loki_tenant,
            username=args.loki_username,
            password=password,
            verify_tls=not args.loki_insecure,
        )
    if args.sink == "datadog":
        api_key = args.dd_api_key
        if not api_key and args.dd_api_key_env:
            api_key = os.environ.get(args.dd_api_key_env)
        if not api_key:
            raise SystemExit(
                "--sink datadog needs --dd-api-key or --dd-api-key-env"
            )
        return DatadogSink(
            api_key=api_key,
            url=args.dd_url,
            source=args.dd_source,
            service=args.dd_service,
            hostname=args.dd_hostname,
            tags=args.dd_tags,
            verify_tls=not args.dd_insecure,
        )
    if args.sink == "webhook":
        if not args.webhook_url:
            raise SystemExit("--sink webhook needs --webhook-url")
        return WebhookSink(
            url=args.webhook_url,
            headers=args.webhook_header,
            verify_tls=not args.webhook_insecure,
        )
    raise SystemExit(f"unknown sink {args.sink!r}")


def passes_filter(r: dict, types: Optional[set], src_sub: Optional[str]) -> bool:
    if types is not None and r.get("type") not in types:
        return False
    if src_sub is not None and src_sub not in r.get("src", ""):
        return False
    return True


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("source", help="data socket spec: unix:/path or tcp:HOST:PORT")

    p.add_argument("--type", default=None,
                   help="comma-separated record types to forward "
                        "(dns,tls,quic,http,ntp,icmp,alert)")
    p.add_argument("--src", default=None,
                   help="filter records by `src` field substring match")

    p.add_argument("--batch-size", type=int, default=100,
                   help="flush after this many records (default 100)")
    p.add_argument("--batch-ms", type=int, default=1000,
                   help="flush after this many ms even if batch not full "
                        "(default 1000)")
    p.add_argument("--max-retries", type=int, default=3,
                   help="per-batch retries before dropping (default 3)")
    p.add_argument("--retry-backoff", type=float, default=0.5,
                   help="initial retry backoff in seconds; doubles each "
                        "attempt (default 0.5)")
    p.add_argument("--stats-interval", type=float, default=30.0,
                   help="seconds between stats prints to stderr "
                        "(default 30)")
    p.add_argument("--no-reconnect", action="store_true",
                   help="exit on first source disconnect (one-shot / test mode)")

    p.add_argument("--sink",
                   choices=["hec", "syslog", "elastic", "loki",
                            "datadog", "webhook"],
                   required=True, help="downstream sink to use")

    # HEC options
    p.add_argument("--hec-url", default=None,
                   help="Splunk HEC URL (e.g. https://host:8088/services/collector)")
    p.add_argument("--hec-token", default=None,
                   help="HEC token (consider --hec-token-env for shared hosts)")
    p.add_argument("--hec-token-env", default=None,
                   help="env var name holding the HEC token")
    p.add_argument("--hec-source", default="sloth")
    p.add_argument("--hec-sourcetype", default="sloth:jsonl")
    p.add_argument("--hec-host", default=None,
                   help="override the `host` field; defaults to local hostname")
    p.add_argument("--hec-index", default=None,
                   help="Splunk index name (optional)")
    p.add_argument("--hec-insecure", action="store_true",
                   help="disable TLS cert verification (test only)")

    # Syslog options
    p.add_argument("--syslog-host", default="localhost")
    p.add_argument("--syslog-port", type=int, default=514)
    p.add_argument("--syslog-proto", choices=["udp", "tcp"], default="udp")
    p.add_argument("--syslog-app", default="sloth")
    p.add_argument("--syslog-hostname", default=None,
                   help="override hostname field; defaults to local hostname")
    p.add_argument("--syslog-pri", type=int, default=134,
                   help="RFC 5424 PRI (default 134 = local0.info)")

    # Elasticsearch options
    p.add_argument("--es-url", default=None,
                   help="Elastic base URL (e.g. https://elastic.example.com:9200)")
    p.add_argument("--es-index", default="sloth-events",
                   help="index name; supports strftime tokens for time-rolled "
                        "indices (e.g. sloth-events-%%Y.%%m.%%d). "
                        "Default: sloth-events")
    p.add_argument("--es-username", default=None,
                   help="ES basic-auth username")
    p.add_argument("--es-password", default=None,
                   help="ES basic-auth password (consider --es-password-env)")
    p.add_argument("--es-password-env", default=None,
                   help="env var name holding the ES password")
    p.add_argument("--es-api-key", default=None,
                   help="ES API key (consider --es-api-key-env)")
    p.add_argument("--es-api-key-env", default=None,
                   help="env var name holding the ES API key")
    p.add_argument("--es-insecure", action="store_true",
                   help="disable TLS cert verification (test only)")

    # Loki options
    p.add_argument("--loki-url", default=None,
                   help="Loki base URL (e.g. http://loki:3100)")
    p.add_argument("--loki-job", default="sloth",
                   help="value of the `job` label (default: sloth)")
    p.add_argument("--loki-source", default="sloth",
                   help="value of the `source` label (default: sloth)")
    p.add_argument("--loki-tenant", default=None,
                   help="multi-tenant header X-Scope-OrgID (optional)")
    p.add_argument("--loki-username", default=None,
                   help="Basic-auth username (optional)")
    p.add_argument("--loki-password", default=None,
                   help="Basic-auth password (consider --loki-password-env)")
    p.add_argument("--loki-password-env", default=None,
                   help="env var name holding the Loki password")
    p.add_argument("--loki-insecure", action="store_true",
                   help="disable TLS cert verification (test only)")

    # Datadog options
    p.add_argument("--dd-url",
                   default="https://http-intake.logs.datadoghq.com/api/v2/logs",
                   help="Datadog Logs intake URL "
                        "(default: US-1 site; change for EU / US3 / US5 / etc.)")
    p.add_argument("--dd-api-key", default=None,
                   help="Datadog API key (consider --dd-api-key-env)")
    p.add_argument("--dd-api-key-env", default=None,
                   help="env var name holding the DD API key")
    p.add_argument("--dd-source",   default="sloth",
                   help="value of the `ddsource` field (default: sloth)")
    p.add_argument("--dd-service",  default="sloth",
                   help="value of the `service` field (default: sloth)")
    p.add_argument("--dd-hostname", default=None,
                   help="value of the `hostname` field; defaults to local hostname")
    p.add_argument("--dd-tags",     default=None,
                   help="CSV of `ddtags` (e.g. env:prod,region:us-east)")
    p.add_argument("--dd-insecure", action="store_true",
                   help="disable TLS cert verification (test only)")

    # Webhook options
    p.add_argument("--webhook-url", default=None,
                   help="POST application/json with body "
                        "{\"records\": [...]} to this URL")
    p.add_argument("--webhook-header", action="append", default=None,
                   help="extra header KEY:VAL (repeatable). "
                        "Auth examples: 'Authorization: Bearer XXX', "
                        "'X-API-Key: XXX'.")
    p.add_argument("--webhook-insecure", action="store_true",
                   help="disable TLS cert verification (test only)")

    args = p.parse_args()

    try:
        source_spec = parse_spec(args.source)
    except ValueError as e:
        print(f"sloth-forward: {e}", file=sys.stderr)
        return 2

    sink = build_sink(args)
    print(f"# sloth-forward: source={args.source} sink={sink.name}",
          file=sys.stderr, flush=True)

    type_filter = None
    if args.type:
        type_filter = {t.strip() for t in args.type.split(",") if t.strip()}

    stats = Stats(interval_s=args.stats_interval)
    batch: list = []
    last_flush = time.monotonic()

    def flush() -> None:
        nonlocal batch, last_flush
        if not batch:
            return
        ok = send_with_retry(
            sink, batch,
            max_retries=args.max_retries,
            backoff_s=args.retry_backoff,
            stats=stats,
        )
        if ok:
            stats.forwarded += len(batch)
        else:
            stats.dropped += len(batch)
        batch = []
        last_flush = time.monotonic()

    while True:
        try:
            sock = connect_source(source_spec)
        except (OSError, ConnectionRefusedError) as e:
            print(f"# source connect failed: {e}; retrying in 1s",
                  file=sys.stderr, flush=True)
            time.sleep(1)
            continue

        print(f"# source connected: {args.source}",
              file=sys.stderr, flush=True)
        try:
            for line in stream_lines(sock):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not passes_filter(r, type_filter, args.src):
                    continue
                stats.received += 1
                batch.append(r)
                now = time.monotonic()
                if (len(batch) >= args.batch_size
                        or (now - last_flush) * 1000 >= args.batch_ms):
                    flush()
                stats.maybe_print()
        except KeyboardInterrupt:
            flush()
            stats.maybe_print(force=True)
            return 0
        except OSError as e:
            print(f"# source disconnected: {e}", file=sys.stderr, flush=True)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        # Flush whatever we collected before the disconnect.
        flush()
        stats.maybe_print(force=True)
        if args.no_reconnect:
            return 0
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
