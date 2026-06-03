"""mock-sloth — synthetic JSONL producer over TCP.

Emits one record per second on each accepted connection, cycling
through every record type sloth supports. The wire format matches
sloth's `--data-socket tcp:HOST:PORT` output, so swapping this
producer for a real sloth instance in docker-compose.yml is a
one-line change.

This is a demo aid for examples/compose/ — NOT a parser test fixture.
"""
import argparse
import itertools
import json
import socket
import sys
import threading
import time

# A small canned set covering each record type sloth ships. Loki
# indexes the `type` label so each one shows up as a separate stream.
TEMPLATES = [
    {"type": "dns",   "src": "10.0.0.5", "qname": "example.com",
     "qtype": "A", "answer": "93.184.216.34", "is_resp": 1},
    {"type": "tls",   "src": "10.0.0.5", "dst": "93.184.216.34",
     "host": "example.com", "ver": "TLS 1.3",
     "ja3": "deadbeefcafef00d00112233445566ff"},
    {"type": "quic",  "src": "10.0.0.5", "dst": "1.1.1.1",
     "host": "cloudflare.com", "ver": "v1"},
    {"type": "http",  "src": "10.0.0.5", "host": "example.com",
     "method": "GET", "path": "/index.html"},
    {"type": "ntp",   "src": "10.0.0.1", "dst": "192.168.1.5",
     "mode": "server", "version": 4, "stratum": 1, "ref": "GPS"},
    {"type": "icmp",  "src": "192.168.1.5", "dst": "8.8.8.8",
     "desc": "Echo Req", "ty": 8, "code": 0, "seq": 42, "v6": 0},
    {"type": "alert", "title": "THREAT_DOMAIN",
     "detail": "10.0.0.5 queried malware.testing.com (IOC ...)",
     "key": "threat-d:malware.testing.com", "sev": 2, "ty": 3, "count": 1},
    {"type": "connections", "src": "10.0.0.5:49152",
     "dst": "93.184.216.34:443", "proto": "tcp",
     "state": "ESTABLISHED", "rtt_ms": 12.4, "retx": 0,
     "rx_bytes": 12345, "tx_bytes": 6789},
    {"type": "twin_episode", "ssid": "Cafe-Net",
     "real_bssid": "aa:bb:cc:01:02:03",
     "twin_bssid": "11:22:33:44:55:66",
     "enc": "WPA2", "real_rssi": -70, "twin_rssi": -45,
     "rssi_swing_dbm": 25, "attack_in_progress": 1,
     "attacker_oui": 1, "hash_mismatch": 1},
]


def serve(conn: socket.socket, addr) -> None:
    print(f"# client connected: {addr}", file=sys.stderr, flush=True)
    cycle = itertools.cycle(TEMPLATES)
    try:
        for tmpl in cycle:
            rec = dict(tmpl)
            rec["ts"] = int(time.time())
            line = (json.dumps(rec) + "\n").encode("utf-8")
            conn.sendall(line)
            time.sleep(1.0)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        print(f"# client disconnected: {addr}", file=sys.stderr, flush=True)
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bind", default="0.0.0.0:8765",
                   help="bind address HOST:PORT (default 0.0.0.0:8765)")
    args = p.parse_args()
    host, port_s = args.bind.rsplit(":", 1)
    port = int(port_s)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    print(f"# mock-sloth: listening on {host}:{port}",
          file=sys.stderr, flush=True)

    try:
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(target=serve, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        return 0
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
