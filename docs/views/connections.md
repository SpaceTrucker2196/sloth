# Connections  `[2]`

Active TCP and UDP sockets with PID, RTT, retransmits, and per-socket
bandwidth.

## Source

Kernel state — sloth reads `/proc/net/tcp[6]` and `/proc/net/udp[6]`
for the socket table, then resolves each socket's inode to a PID via
`/proc/<pid>/fd/*`. RTT and retransmits come from `INET_DIAG` netlink
(kernel's TCP-info per socket). Per-socket bandwidth is computed by
diffing counters poll-to-poll and smoothing.

## What sloth captures

Per connection: local addr:port, remote addr:port, proto, state, PID,
process name, smoothed RTT (μs), retransmits, RX/TX rates, brief
sparkline history.

## View

```
 ── Connections ────────────────────────────────────────────────
 Local                  → Remote                    Proto State  PID   Process
 192.168.1.5:33445      → 142.250.80.46:443         TCP   ESTAB  1234  chrome
 192.168.1.5:53210      → 1.1.1.1:53                UDP   -        -    -
 192.168.1.5:22         → 192.168.1.99:54321        TCP   ESTAB    -    -      ← inbound SSH
 192.168.1.5:33450      → 192.0.2.66:443            TCP   ESTAB    -    -      ← THREAT_IP alert!
```

State, sort key, filter:

| Key | Action |
|-----|--------|
| `↑`/`↓` | Navigate |
| `s`     | Cycle sort (State → Proto → Port → PID → Bandwidth → RTT) |
| `f`     | Cycle filter (All / TCP / UDP) |
| `n`     | Toggle DNS-name resolution in addr fields |

## What's normal

- A handful of long-lived TCP sessions to popular CDNs.
- UDP sockets for DNS / DHCP / mDNS that don't show ports being
  "established".
- PID resolution working — most rows have a process name.

## What's suspicious

- **No PID on a socket from the local host** — the socket exists in
  the kernel but no `/proc/<pid>/fd/*` resolves to it. Common when:
  - Capture user lacks permission to read other users' procfs (try
    `sudo`).
  - Process was killed but socket lingers in TIME_WAIT.
  - **Kernel-mode rootkit hiding a backdoor**. Rare, very serious.
- **Inbound connections to unusual ports** — your host shouldn't
  generally accept inbound. Check `ss -tlnp` for what's
  listening.
- **Many SYN_SENT** with the same source — outbound port scan from
  this host (sloth-side equivalent of `[7] Probe` for layer-4).
  Triggers [PORT_SCAN](alerts.md#port_scan) when a remote does it
  back to us.
- **Connection to threat-intel IP** — fires
  [`ALERT_THREAT_IP`](alerts.md#threat_ip) CRIT, and the per-alert
  pcap export (if `--pcap-dir` is set) dumps the matching packets.
- **Sustained high retransmit rate** — congested link, bad MTU, or
  flaky cable. Rarely security-relevant but worth noting.

## See also

- TCP info: [`src/platform/linux_tcpdiag.c`](../../src/platform/linux_tcpdiag.c)
  (INET_DIAG netlink).
- Bandwidth: [`src/bandwidth.c`](../../src/bandwidth.c).
- Top hosts derived from this view: [`top_hosts`](dashboard.md#top-hosts).
