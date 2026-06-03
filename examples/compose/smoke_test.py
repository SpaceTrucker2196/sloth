#!/usr/bin/env python3
"""Smoke test — end-to-end without Docker.

Spawns the synthetic producer (mock-sloth.py), the forwarder
(../forwarder/sloth-forward.py) pointed at a tiny in-process fake
sink, and asserts every record type that the producer emits arrives
at the sink within a bounded time window. Run via:

    python3 examples/compose/smoke_test.py

Returns 0 on success, 1 on missing record types, 2 on subprocess
failure. Designed to run in CI (no daemon dependencies; uses random
free ports; cleans up on exit).

Why this exists: every new record type we add in jsonl.{c,h} should
flow end-to-end through mock-sloth → sloth-forward → SIEM. The smoke
test catches drift between sloth's wire format and the
forwarder/mock at PR time, before it lands on an iOS client or a
deployed Loki.
"""
import json
import os
import signal
import socket
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "examples" / "compose"
FORWARDER = REPO / "examples" / "forwarder" / "sloth-forward.py"
MOCK_SLOTH = COMPOSE / "mock-sloth.py"


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_sink_handler(sink_name: str):
    """Build a BaseHTTPRequestHandler subclass that parses the body
    shape for the given sink and records each record's `type` field
    into a per-handler class attribute. One handler class per sink so
    the test can run them in sequence with isolated state."""

    class Handler(BaseHTTPRequestHandler):
        seen_types: set = set()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8", "replace")
            try:
                doc = json.loads(body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            self._absorb(doc)
            self.send_response(204)
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args):
            pass

        def _absorb(self, doc):
            if sink_name == "loki":
                for stream in doc.get("streams", []):
                    t = stream.get("stream", {}).get("type")
                    if t:
                        Handler.seen_types.add(t)
            elif sink_name == "datadog":
                # Datadog body is a JSON array of envelopes whose
                # `message` is the raw sloth record string.
                for env in (doc if isinstance(doc, list) else []):
                    try:
                        rec = json.loads(env.get("message", ""))
                    except json.JSONDecodeError:
                        continue
                    t = rec.get("type")
                    if t:
                        Handler.seen_types.add(t)
            elif sink_name == "webhook":
                # Webhook body is {"records": [...]}.
                for rec in doc.get("records", []):
                    t = rec.get("type")
                    if t:
                        Handler.seen_types.add(t)

    return Handler


def expected_record_types() -> set:
    """Pull the canonical type list out of mock-sloth.py so we don't
    duplicate the source of truth here. Anything mock-sloth knows about,
    the test asserts arrived at the fake Loki."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("mock_sloth", MOCK_SLOTH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return {tmpl["type"] for tmpl in mod.TEMPLATES}


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


SINK_CONFIGS = {
    "loki": {
        "url_path": "",
        "forwarder_args": lambda port: [
            "--sink", "loki",
            "--loki-url", f"http://127.0.0.1:{port}",
            "--loki-job", "smoke",
            "--loki-source", "smoke-test",
        ],
    },
    "datadog": {
        "url_path": "",
        "forwarder_args": lambda port: [
            "--sink", "datadog",
            "--dd-url", f"http://127.0.0.1:{port}",
            "--dd-api-key", "smoke-test-key",
            "--dd-source", "smoke",
        ],
    },
    "webhook": {
        "url_path": "",
        "forwarder_args": lambda port: [
            "--sink", "webhook",
            "--webhook-url", f"http://127.0.0.1:{port}/hook",
            "--webhook-header", "X-Smoke: yes",
        ],
    },
}


def run_one_sink(sink_name: str, expected: set) -> bool:
    """Run the producer → forwarder → fake-sink pipeline for one sink
    and return True iff every expected type was seen."""
    producer_port = free_port()
    sink_port = free_port()

    handler_cls = make_sink_handler(sink_name)
    server = HTTPServer(("127.0.0.1", sink_port), handler_cls)
    server_t = Thread(target=server.serve_forever, daemon=True)
    server_t.start()

    producer = subprocess.Popen(
        [sys.executable, str(MOCK_SLOTH),
         "--bind", f"127.0.0.1:{producer_port}",
         "--interval", "0.05"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if not wait_for_port("127.0.0.1", producer_port, timeout=5.0):
        producer.kill()
        server.shutdown()
        print(f"FAIL[{sink_name}]: mock-sloth never bound",
              file=sys.stderr)
        return False

    forwarder = subprocess.Popen(
        [sys.executable, str(FORWARDER),
         f"tcp:127.0.0.1:{producer_port}",
         *SINK_CONFIGS[sink_name]["forwarder_args"](sink_port),
         "--batch-size", "5",
         "--batch-ms", "100",
         "--stats-interval", "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if expected.issubset(handler_cls.seen_types):
            break
        time.sleep(0.1)

    forwarder.terminate()
    producer.terminate()
    try:
        forwarder.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        forwarder.kill()
    try:
        producer.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        producer.kill()
    server.shutdown()

    seen = handler_cls.seen_types
    missing = expected - seen
    print(f"# [{sink_name}] saw {len(seen)}/{len(expected)} types",
          flush=True)
    if missing:
        print(f"FAIL[{sink_name}]: missing {sorted(missing)}",
              file=sys.stderr)
        return False
    return True


def main() -> int:
    expected = expected_record_types()
    print(f"# expecting {len(expected)} record types from mock-sloth",
          flush=True)
    all_ok = True
    for sink_name in ("loki", "datadog", "webhook"):
        if not run_one_sink(sink_name, expected):
            all_ok = False
    if not all_ok:
        return 1
    print("OK", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
