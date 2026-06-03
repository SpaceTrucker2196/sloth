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


class FakeLokiHandler(BaseHTTPRequestHandler):
    """Accepts /loki/api/v1/push, records every received record's
    `type` label so the test can assert coverage. Other paths return
    200 (so /ready-style probes succeed)."""

    seen_types: set = set()
    received_lines: list = []

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", "replace")
        try:
            doc = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        for stream in doc.get("streams", []):
            t = stream.get("stream", {}).get("type")
            if t:
                FakeLokiHandler.seen_types.add(t)
            for ts_ns, line in stream.get("values", []):
                FakeLokiHandler.received_lines.append(line)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        # Silence default access logging — keep test output focused.
        pass


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


def main() -> int:
    producer_port = free_port()
    fake_loki_port = free_port()
    expected = expected_record_types()
    print(f"# expecting {len(expected)} record types from mock-sloth",
          flush=True)

    # Fake Loki on a background thread.
    server = HTTPServer(("127.0.0.1", fake_loki_port), FakeLokiHandler)
    server_t = Thread(target=server.serve_forever, daemon=True)
    server_t.start()

    # Producer.
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
        print("FAIL: mock-sloth never bound the producer port",
              file=sys.stderr)
        return 2

    # Forwarder.
    forwarder = subprocess.Popen(
        [sys.executable, str(FORWARDER),
         f"tcp:127.0.0.1:{producer_port}",
         "--sink", "loki",
         "--loki-url", f"http://127.0.0.1:{fake_loki_port}",
         "--loki-job", "smoke",
         "--loki-source", "smoke-test",
         "--batch-size", "5",
         "--batch-ms", "100",
         "--stats-interval", "60"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    # mock-sloth at interval=0.05 cycles through N templates in ~N*0.05s.
    # We poll for the full set with a generous ceiling so a slow CI
    # runner doesn't false-alarm.
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if expected.issubset(FakeLokiHandler.seen_types):
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

    missing = expected - FakeLokiHandler.seen_types
    extras  = FakeLokiHandler.seen_types - expected
    print(f"# saw {len(FakeLokiHandler.seen_types)}/{len(expected)} "
          f"types; {len(FakeLokiHandler.received_lines)} lines total",
          flush=True)
    if missing:
        print(f"FAIL: missing {sorted(missing)}", file=sys.stderr)
        return 1
    if extras:
        # Not fatal — just noise. Print so it's visible in CI logs.
        print(f"# note: also saw {sorted(extras)} (not in mock-sloth)",
              flush=True)
    print("OK", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
