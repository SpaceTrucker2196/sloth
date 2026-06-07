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
    # ── State snapshot record types (iOS reproduction set) ──
    {"type": "iface", "name": "eth0",
     "rx_bytes": 1234567, "tx_bytes": 89012,
     "rx_packets": 1500, "tx_packets": 800,
     "rx_errors": 0, "rx_drops": 0, "tx_errors": 0, "tx_drops": 0,
     "rx_rate": 1024.0, "tx_rate": 512.0,
     "mtu": 1500, "speed_mbps": 1000},
    {"type": "arp", "ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff",
     "iface": "eth0"},
    {"type": "dhcp_lease", "ip": "10.0.0.50", "hostname": "laptop",
     "expire": 1700003600},
    {"type": "wifi_ap", "ssid": "Office",
     "bssid": "11:22:33:44:55:66", "signal_dbm": -55, "channel": 36,
     "enc": "WPA2", "status": 1},
    {"type": "wifi_sta", "mac": "aa:bb:cc:dd:ee:ff", "signal_dbm": -50,
     "tx_rate_kbps": 866000, "rx_rate_kbps": 866000,
     "connected_secs": 3600, "inactive_ms": 100,
     "tx_bytes": 12345, "rx_bytes": 67890},
    {"type": "top_host", "ip": "1.1.1.1", "hostname": "one.one.one.one",
     "owner": "Cloudflare", "first_seen": 1700000000,
     "last_seen": 1700000060, "conn_count": 5,
     "rx_rate": 2048.0, "tx_rate": 256.0,
     "rx_bytes": 102400, "tx_bytes": 12800},
    {"type": "device", "mac": "aa:bb:cc:dd:ee:ff", "ip": "10.0.0.50",
     "hostname": "laptop", "vendor": "Apple", "last_ssid": "Office",
     "is_ap": 0, "signal_dbm": -50, "probe_count": 12, "sources": 7,
     "last_seen": 1700000060},
    {"type": "beacon", "ssid": "Office",
     "bssid": "11:22:33:44:55:66", "signal_dbm": -55, "channel": 36,
     "enc": "WPA2", "beacon_ms": 102,
     "pairwise": "CCMP", "group": "CCMP", "akm": "PSK", "mfp": 1,
     "vendor": "Cisco", "has_wps": 0, "wps_state": 0, "wps_locked": 0,
     "phy": "Wi-Fi 6", "revealed": 0,
     "last_seen": 1700000060, "frame_count": 600,
     "fp_flags": 14, "vendor_ies_hash": 3735928559,
     "rssi_min_60s": -60, "rssi_max_60s": -50,
     "ssid_history": ["Office"], "neighbors": []},
    {"type": "deauth", "src": "aa:bb:cc:dd:ee:ff",
     "dst": "ff:ff:ff:ff:ff:ff", "bssid": "11:22:33:44:55:66",
     "reason": 7, "subtype": 12,
     "first_seen": 1700000050, "last_seen": 1700000060,
     "count": 25, "flood": 1},
    {"type": "probe_client", "mac": "12:34:56:78:9a:bc",
     "ssid": "MyHomeNet", "signal_dbm": -65, "channel": 6,
     "first_seen": 1700000000, "last_seen": 1700000060,
     "frame_count": 8},
    {"type": "pnl_client", "mac": "12:34:56:78:9a:bc",
     "mac_random": 1, "probe_count": 20,
     "os_fp": "iPhone", "phy": "Wi-Fi 6",
     "first_seen": 1700000000, "last_seen": 1700000060,
     "ssids": ["MyHomeNet", "Coffee", "Airport-Wifi"]},
    {"type": "seqnum_client", "mac": "12:34:56:78:9a:bc",
     "mac_random": 1, "last_seen": 1700000060, "frame_count": 50,
     "hist": [1024, 1025, 1026, 1027]},
    {"type": "seqnum_correlation",
     "mac_a": "12:34:56:78:9a:bc", "mac_b": "fe:dc:ba:98:76:54",
     "mac_a_random": 1, "mac_b_random": 1,
     "gap": 2, "dt_ms": 500, "a_count": 30, "b_count": 25},
    {"type": "channel_summary", "channel": 36, "ap_count": 4,
     "assoc_count": 12, "best_signal": -45, "top_ssid": "Office",
     "last_seen": 1700000060},
    {"type": "assoc", "bssid": "11:22:33:44:55:66",
     "sta_mac": "aa:bb:cc:dd:ee:ff", "ssid": "Office",
     "sta_random": 0, "source": 1, "channel": 36, "signal_dbm": -50,
     "first_seen": 1700000000, "last_seen": 1700000060, "frame_count": 100},
    {"type": "eapol", "bssid": "11:22:33:44:55:66",
     "sta_mac": "aa:bb:cc:dd:ee:ff", "ssid": "Office",
     "event_ts": 1700000060, "msg_num": 1, "has_pmkid": 1,
     "handshake_complete": 0, "signal_dbm": -50, "channel": 36},
    {"type": "mdns_service", "instance": "My Printer._ipp._tcp.local",
     "service": "_ipp._tcp", "host": "printer.local", "ip": "10.0.0.20",
     "port": 631, "last_seen": 1700000060},
    {"type": "nbns_name", "name": "DESKTOP", "ip": "10.0.0.51",
     "suffix": 0, "last_seen": 1700000060},
    {"type": "ssdp_device", "ip": "10.0.0.30",
     "kind": "urn:schemas-upnp-org:device:MediaRenderer:1",
     "usn": "uuid:roku-12345::urn:schemas-upnp-org:device:MediaRenderer:1",
     "location": "http://10.0.0.30:8060/", "nts": "alive",
     "last_seen": 1700000060},
    {"type": "scan_entry", "ip": "10.0.0.99", "port_count": 3,
     "first_seen": 1700000050, "last_seen": 1700000060, "flagged": 0,
     "ports": [22, 80, 443]},
    {"type": "packet",
     "ts_sec": 1700000060, "ts_usec": 123456,
     "src": "10.0.0.5", "dst": "8.8.8.8",
     "src_port": 49152, "dst_port": 53, "proto": 17,
     "len": 64, "info": "DNS query example.com"},
    {"type": "process", "pid": 1234, "proc": "firefox",
     "ppid": 1, "depth": 0,
     "conn_count": 3, "tcp_count": 2, "udp_count": 1,
     "tx_bytes": 12345, "rx_bytes": 67890,
     "tx_rate": 100.0, "rx_rate": 500.0,
     "ports": [443, 853]},
    {"type": "ndp_ra", "src_ip": "fe80::1",
     "src_mac": "aa:bb:cc:dd:ee:01",
     "cur_hop_limit": 64, "flags": 0, "router_lifetime": 1800,
     "first_seen": 1700000000, "last_seen": 1700000060, "count": 30,
     "prefixes": ["2001:db8::/64"]},
    {"type": "smb_session", "client_ip": "10.0.0.5",
     "server_ip": "10.0.0.10", "server_port": 445, "dialect": "SMB2",
     "first_seen": 1700000000, "last_seen": 1700000060, "count": 42},
    {"type": "kerb_event", "src_ip": "10.0.0.5",
     "as_req_count": 4, "as_rep_count": 2,
     "tgs_req_count": 6, "tgs_rep_count": 6,
     "preauth_required_count": 4, "preauth_failed_count": 1,
     "principal_unknown_count": 0, "error_other_count": 0,
     "first_seen": 1700000000, "last_seen": 1700000060},
    {"type": "ldap_event", "src_ip": "10.0.0.5",
     "bind_count": 1, "bind_anon_count": 0,
     "search_count": 14, "search_ref_count": 0,
     "first_seen": 1700000000, "last_seen": 1700000060},
    {"type": "bgp_session", "peer_a": "10.0.0.1", "peer_b": "10.0.0.2",
     "open_count": 1, "update_count": 3,
     "notification_count": 0, "keepalive_count": 42,
     "first_seen": 1700000000, "last_seen": 1700000060},
    {"type": "ssh_flow", "src_ip": "10.0.0.5", "dst_ip": "10.0.0.10",
     "banner_count": 3, "server_banner": "SSH-2.0-OpenSSH_8.9",
     "first_seen": 1700000000, "last_seen": 1700000060},
    {"type": "rdp_flow", "src_ip": "203.0.113.7", "dst_ip": "10.0.0.20",
     "connect_req_count": 18, "last_cookie": "administrator",
     "proto_mask": 11, "first_seen": 1700000000, "last_seen": 1700000060},
]


def serve(conn: socket.socket, addr, interval: float) -> None:
    print(f"# client connected: {addr}", file=sys.stderr, flush=True)
    cycle = itertools.cycle(TEMPLATES)
    try:
        for tmpl in cycle:
            rec = dict(tmpl)
            rec["ts"] = int(time.time())
            line = (json.dumps(rec) + "\n").encode("utf-8")
            conn.sendall(line)
            time.sleep(interval)
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
    p.add_argument("--interval", type=float, default=1.0,
                   help="seconds between records (default 1.0; the "
                        "smoke test passes 0.05 for fast cycling)")
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
            t = threading.Thread(target=serve, args=(conn, addr, args.interval),
                                 daemon=True)
            t.start()
    except KeyboardInterrupt:
        return 0
    finally:
        srv.close()


if __name__ == "__main__":
    sys.exit(main())
