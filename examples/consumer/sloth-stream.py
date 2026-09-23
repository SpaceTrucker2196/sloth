#!/usr/bin/env python3
"""
sloth-stream — reference consumer for the sloth read-only JSONL data socket.

Connects to a running sloth's `--data-socket SPEC` and prints / filters
the live JSONL records. Stdlib only — Python 3.7+.

This is a *reference* consumer: it exercises every record type in the
JSONL schema documented at `docs/wiki/jsonl-schema.md` and demonstrates
the connect / read / parse / filter / reconnect loop that any
production consumer (SIEM forwarder, a dashboard backend, etc.) will
follow. Read the source as the worked example.

USAGE

    sloth-stream unix:/var/run/sloth.sock
    sloth-stream tcp:100.64.0.5:8765                 # e.g. a Tailscale IP

    # filter to one or more record types
    sloth-stream unix:/tmp/sloth.sock --type alert
    sloth-stream unix:/tmp/sloth.sock --type dns,tls,quic

    # the alert lifecycle (#98) — escalations, not just first sightings
    sloth-stream unix:/tmp/sloth.sock \
        --type alert.create,alert.escalate,alert.update,alert.resolve

    # filter by `src` field substring (any record with a `src`)
    sloth-stream unix:/tmp/sloth.sock --src 10.0.0.5

    # raw mode — pass-through JSON lines (no pretty-printing)
    sloth-stream unix:/tmp/sloth.sock --raw

    # tally mode — count records by type, print every 5s
    sloth-stream unix:/tmp/sloth.sock --count

    # one-shot — exit on disconnect instead of retrying
    sloth-stream unix:/tmp/sloth.sock --no-reconnect

CONTRACT

The sloth side of this is documented in MISSION.md §4 and
docs/wiki/jsonl-schema.md. Highlights:

  - One JSON object per line, terminated by exactly one `\n`.
  - Sloth never reads from us. The socket is one-way; access control
    is the operator's job (bind address, UNIX perms, Tailscale ACLs).
  - Whole records or none. A slow consumer gets a bounded queue;
    on overflow sloth drops whole records and reports them with a
    socket-only {"type":"socket_gap",...} record. A consumer that
    accepts nothing for 30 s is disconnected. Reconnect to resume;
    lines emitted during the disconnect window are gone, and bytes
    after the last newline at EOF are never a record.
  - Fields are append-only. Consumers ignore unknown keys and unknown
    `type` values gracefully.
  - `{"type":"alert",...}` is written only when a dedup key is *new*.
    Everything that happens to an alert afterwards rides the
    `alert.create` / `alert.update` / `alert.escalate` /
    `alert.resolve` lifecycle records (#98). A consumer that pages on
    CRIT must read `alert.escalate` — an alert created at WARN that
    becomes CRIT never produces a second `alert` record.
  - `count` on an alert is **rule evaluations**, not packets or
    incidents; every rule re-evaluates once per poll. `observations`
    on the lifecycle records is the count that only moves when the
    evidence does.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
from typing import Iterator, Optional


# ── Connection ───────────────────────────────────────────────────────

def parse_spec(spec: str) -> tuple:
    """Parse a --data-socket-style spec. Returns:

      ('unix', path)
      ('tcp', host, port)
    """
    if spec.startswith("unix:"):
        return ("unix", spec[5:])
    if spec.startswith("tcp:"):
        rest = spec[4:]
        i = rest.rfind(":")
        if i < 0:
            raise ValueError(f"tcp spec needs HOST:PORT, got {spec!r}")
        try:
            port = int(rest[i+1:])
        except ValueError:
            raise ValueError(f"tcp port is not an integer in {spec!r}")
        return ("tcp", rest[:i], port)
    raise ValueError(f"spec must start with 'unix:' or 'tcp:', got {spec!r}")


def connect(spec: tuple, timeout: float = 10.0) -> socket.socket:
    """Connect to the parsed spec. Raises socket.error on failure."""
    if spec[0] == "unix":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(spec[1])
    else:
        s = socket.create_connection((spec[1], spec[2]), timeout=timeout)
    s.settimeout(None)   # blocking reads once connected — we want to wait
    return s


def stream_lines(sock: socket.socket) -> Iterator[bytes]:
    """Yield bytes lines (no trailing \\n) until the peer closes."""
    buf = b""
    while True:
        chunk = sock.recv(8192)
        if not chunk:
            return                       # EOF — peer closed
        buf += chunk
        while True:
            i = buf.find(b"\n")
            if i < 0:
                break
            yield buf[:i]
            buf = buf[i+1:]


# ── Pretty-print formatters ──────────────────────────────────────────
#
# One formatter per record type from docs/wiki/jsonl-schema.md.
# Each returns a single line; the caller prefixes the timestamp.

C_RESET = "\x1b[0m"
C_RED   = "\x1b[31m"
C_ORN   = "\x1b[33m"
C_YEL   = "\x1b[93m"
C_CYAN  = "\x1b[36m"
C_DIM   = "\x1b[2m"
C_BLD   = "\x1b[1m"


def colored(use_color: bool) -> dict:
    if use_color:
        return {"reset": C_RESET, "red": C_RED, "orn": C_ORN,
                "yel": C_YEL, "cyan": C_CYAN, "dim": C_DIM, "bld": C_BLD}
    return {k: "" for k in ("reset","red","orn","yel","cyan","dim","bld")}


def fmt_dns(r, c):
    direction = "<-" if r.get("is_resp") else "qry"
    src   = r.get("src", "")
    qname = r.get("qname", "")
    qtype = r.get("qtype", "")
    ans   = r.get("answer", "")
    out = f"{c['cyan']}dns{c['reset']}      {src:<16} {direction:>4} {qname:<32.32} {qtype:<6}"
    if ans:
        out += f" {c['dim']}{ans}{c['reset']}"
    return out


def fmt_tls(r, c):
    src  = r.get("src", "")
    dst  = r.get("dst", "")
    host = r.get("host", "")
    ver  = r.get("ver", "")
    ja3  = r.get("ja3", "")
    ver_c = c["red"] if ver in ("TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0") else ""
    out = f"{c['cyan']}tls{c['reset']}      {src:<16}  ->  {dst:<16} {ver_c}{ver:<8}{c['reset']} {host:<32.32}"
    if ja3:
        out += f" {c['dim']}ja3:{ja3[:8]}…{c['reset']}"
    return out


def fmt_quic(r, c):
    return (f"{c['cyan']}quic{c['reset']}     "
            f"{r.get('src',''):<16}  ->  {r.get('dst',''):<16} "
            f"{r.get('ver','v?'):<8} {r.get('host',''):<32.32}")


def fmt_http(r, c):
    return (f"{c['cyan']}http{c['reset']}     "
            f"{r.get('src',''):<16}  ->  {r.get('host',''):<32.32} "
            f"{c['bld']}{r.get('method',''):<7}{c['reset']} {r.get('path','')}")


def fmt_ntp(r, c):
    return (f"{c['cyan']}ntp{c['reset']}      "
            f"{r.get('src',''):<16}  ->  {r.get('dst',''):<16} "
            f"v{r.get('version','?')} stratum={r.get('stratum','?')} "
            f"{r.get('mode','')} {r.get('ref','')}")


def fmt_icmp(r, c):
    fam  = "v6" if r.get("v6") else "v4"
    return (f"{c['cyan']}icmp{c['reset']}     "
            f"{r.get('src',''):<16}  ->  {r.get('dst',''):<16} "
            f"{r.get('desc',''):<14} ty={r.get('ty','?')}/{r.get('code','?')} "
            f"seq={r.get('seq','?')} {fam}")


def fmt_alert(r, c):
    sev = r.get("sev", 0)
    sev_c = {2: c["red"], 1: c["orn"], 0: c["yel"]}.get(sev, "")
    bang  = "!"
    out = (f"{sev_c}alert  {bang} "
           f"{r.get('title',''):<18}{c['reset']} "
           f"{r.get('detail','')}")
    if r.get("count", 1) > 1:
        out += f" {c['dim']}(count={r['count']}){c['reset']}"
    return out


SEV_NAME = {0: "LOW", 1: "WARN", 2: "CRIT"}


def fmt_alert_event(r, c):
    """Lifecycle record (#98).

    The escalate case is the one worth copying into a real consumer:
    an alert that was created at WARN and became CRIT produces no
    second `alert` record, only this.
    """
    sev = r.get("sev", 0)
    sev_c = {2: c["red"], 1: c["orn"], 0: c["yel"]}.get(sev, "")
    kind = r.get("type", "")[len("alert."):]
    transition = SEV_NAME.get(sev, "?")
    if "prev_sev" in r:
        transition = f"{SEV_NAME.get(r['prev_sev'], '?')}->{transition}"
    out = (f"{sev_c}alert.{kind:<8} {transition:<11}"
           f"{r.get('title', ''):<18}{c['reset']} "
           f"{r.get('detail', '')}")
    tail = [f"inc={r.get('incident_id', '?')[:8]}"]
    if r.get("reason"):
        tail.append(f"reason={r['reason']}")
    # obs/eval is the #98 counter split: the first only moves when the
    # evidence does, the second is one per rule tick.
    tail.append(f"obs={r.get('observations', '?')}/"
                f"eval={r.get('evaluations', '?')}")
    return out + f" {c['dim']}({' '.join(tail)}){c['reset']}"


def _stream_state(r, prefix):
    """One capture stream's liveness, as the TUI health strip words it.

    `_open` true with `_running` false is the case `sensor_health`
    exists for: the pcap handle is still there, the worker thread is
    not, and the tables simply stop growing.
    """
    if not r.get(f"{prefix}_open"):
        return "off"
    if r.get(f"{prefix}_running"):
        return "up"
    return f"down({r.get(f'{prefix}_exit', '?')})"


def fmt_sensor_health(r, c):
    """The sensor's self-report (#91).

    The one record type a SILENT sensor still emits, which is what
    makes "healthy with no detections" separable from "not observing".
    A real consumer should alert on: a stream going `down` with an
    `_exit` other than `stopped`, `chan_confirmed_ok` dropping to 0,
    or any drop/eviction counter moving.
    """
    cap = _stream_state(r, "capture")
    mon = _stream_state(r, "monitor")
    bad = (cap.startswith("down") or mon.startswith("down")
           or not r.get("chan_confirmed_ok", 1))
    head_c = c["red"] if bad else c["dim"]
    out = f"{head_c}sensor_health{c['reset']}  cap={cap} mon={mon}"

    # Faults only — a healthy sensor should be one quiet line.
    tail = []
    for pfx in ("capture", "monitor"):
        for fld in ("drop", "ifdrop"):
            n = r.get(f"{pfx}_{fld}", 0)
            if n:
                tail.append(f"{pfx[:3]}_{fld}={n}"
                            f"(+{r.get(f'{pfx}_{fld}_delta', 0)})")
        detail = r.get(f"{pfx}_exit_detail", "")
        if detail:
            # Always read this beside `_exit`: "error" is the honest
            # bucket for libpcap wording sloth does not recognise.
            tail.append(f"{pfx[:3]}_err={detail!r}")
    if not r.get("chan_confirmed_ok", 1):
        tail.append(f"chan req={r.get('chan_requested')} "
                    f"confirmed={r.get('chan_confirmed')}")
    if r.get("chan_retune_failures"):
        tail.append(f"retune_fail={r['chan_retune_failures']}")
    if r.get("evictions"):
        per = " ".join(f"{k[len('evict_'):]}={v}"
                       for k, v in sorted(r.items())
                       if k.startswith("evict_") and v)
        tail.append(f"evict={r['evictions']} [{per}]")
    if tail:
        out += "  " + " ".join(tail)
    return out


FORMATTERS = {
    "dns":   fmt_dns,
    "tls":   fmt_tls,
    "quic":  fmt_quic,
    "http":  fmt_http,
    "ntp":   fmt_ntp,
    "icmp":  fmt_icmp,
    "alert": fmt_alert,
    "alert.create":   fmt_alert_event,
    "alert.update":   fmt_alert_event,
    "alert.escalate": fmt_alert_event,
    "alert.resolve":  fmt_alert_event,
    "sensor_health":  fmt_sensor_health,
}


def format_record(r: dict, c: dict) -> str:
    ts = r.get("ts", 0)
    ts_s = time.strftime("%H:%M:%S", time.localtime(ts))
    fn = FORMATTERS.get(r.get("type"))
    if fn:
        return f"{c['dim']}{ts_s}{c['reset']} {fn(r, c)}"
    # Unknown type — show raw fields so the schema growth is visible.
    return (f"{c['dim']}{ts_s}{c['reset']} "
            f"{c['dim']}{r.get('type','?')}{c['reset']}     {r}")


# ── Main loop ────────────────────────────────────────────────────────

def passes_filter(r: dict, types: Optional[set], src_sub: Optional[str]) -> bool:
    if types is not None and r.get("type") not in types:
        return False
    if src_sub is not None and src_sub not in r.get("src", ""):
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "spec",
        help="data socket spec: unix:/path or tcp:HOST:PORT",
    )
    parser.add_argument(
        "--type", default=None,
        help="comma-separated record types to keep "
             "(dns,tls,quic,http,ntp,icmp,alert, the #98 lifecycle "
             "records alert.create/update/escalate/resolve, and the "
             "#91 sensor_health self-report)",
    )
    parser.add_argument(
        "--src", default=None,
        help="filter records by `src` field substring match",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="emit raw JSON lines instead of pretty-formatting",
    )
    parser.add_argument(
        "--no-reconnect", action="store_true",
        help="exit on disconnect instead of waiting and retrying",
    )
    parser.add_argument(
        "--count", action="store_true",
        help="tally records by type; print a one-line summary every 5s",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable ANSI colour (auto-disabled when stdout is not a TTY)",
    )
    args = parser.parse_args()

    try:
        spec = parse_spec(args.spec)
    except ValueError as e:
        print(f"sloth-stream: {e}", file=sys.stderr)
        return 2

    type_filter = None
    if args.type:
        type_filter = {t.strip() for t in args.type.split(",") if t.strip()}

    use_color = (not args.no_color) and sys.stdout.isatty()
    c = colored(use_color)

    while True:
        try:
            sock = connect(spec)
        except (OSError, ConnectionRefusedError) as e:
            print(f"# connect failed: {e}", file=sys.stderr)
            if args.no_reconnect:
                return 1
            time.sleep(1)
            continue

        print(f"# sloth-stream: connected to {args.spec}", file=sys.stderr)
        counts: dict = {}
        last_print = time.monotonic()
        try:
            for line in stream_lines(sock):
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue          # silently drop garbage lines

                if not passes_filter(r, type_filter, args.src):
                    continue

                if args.count:
                    t = r.get("type", "?")
                    counts[t] = counts.get(t, 0) + 1
                    now = time.monotonic()
                    if now - last_print >= 5.0:
                        summary = " ".join(f"{k}={v}"
                                           for k, v in sorted(counts.items()))
                        print(summary, flush=True)
                        last_print = now
                elif args.raw:
                    sys.stdout.write(line.decode("utf-8", "replace") + "\n")
                    sys.stdout.flush()
                else:
                    print(format_record(r, c), flush=True)
        except KeyboardInterrupt:
            return 0
        except OSError as e:
            print(f"# disconnected: {e}", file=sys.stderr)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        if args.no_reconnect:
            return 1
        print("# reconnecting in 1s", file=sys.stderr)
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
