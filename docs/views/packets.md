# Packets  `[4]`

Live packet capture with hex detail and BPF filter.

## Monitor mode

When a monitor-mode Wi-Fi interface is active, this view switches to the
**802.11 frame list** the radio is hearing — age, subtype (`Beacon`,
`ProbeReq`, `Auth`, `Deauth`, `Data`, `RTS`/`CTS`/`ACK`, …), source
(TA/SA) → destination (RA/DA), length, and signal — scrollable with
up/down, newest first. Frames are captured by the monitor pcap
(radiotap + 802.11), separate from the IP capture below. With no monitor
interface the view is the IP packet capture described here. The same
auto-switch applies to the dashboard's packets band.

## Source

Raw pcap on the chosen capture interface (defaults to `any` if
present, otherwise the first non-loopback iface). Filtered at the
parser level to IPv4 and IPv6 only — ARP, LLC, and unknown ethertypes
drop before they reach the ring buffer. ARP traffic is available in
its own view (`[8]`).

## What sloth captures

Ring buffer of the last `MAX_PACKETS` (= 256) packets. Each entry
carries time, src/dst/ports, IP proto, captured length, an
inline-decoded info string (e.g. `"GET example.com"`,
`"TLS 1.3 google.com"`, `"DNS A google.com"`), and the first 64 bytes
of raw frame for detail rendering and per-alert pcap export.

## View

```
 ── Packets ──────────────────────────────────────────────────────────────────
 Time      Source                Destination           Proto  Len  Info                          Hex / ASCII
 0001.123  192.168.1.5:33445     142.250.80.46:443      6    1500  TLS 1.3 google.com            16 03 03 00 ...   ......
 0001.124  142.250.80.46:443     192.168.1.5:33445      6    1500  ACK                           45 00 00 28 ...   E..(..
 0001.125  192.168.1.5:53210     1.1.1.1:53            17      78  DNS A reddit.com              ab cd 01 00 ...   ..reddit
 0001.126  1.1.1.1:53            192.168.1.5:53210     17     128  DNS R reddit.com              ab cd 81 80 ...   ..reddit
 0001.130  192.168.1.5:5353      224.0.0.251:5353      17     142  mDNS                          00 00 00 00 ...   ._airpla
```

The hex column shows as many bytes as the terminal width allows; ASCII
to the right is the same byte run, printable chars literal and
non-printable as `.`.

Press Enter on a paused packet for the hex panel:

```
 ── PACKET DETAIL ──
   Time:     0001.124680
   Source:   192.168.1.5:33445
   Dest:     142.250.80.46:443
   Protocol: 6
   Length:   1500
   Info:     TLS 1.3 google.com
 ── HEX DUMP (64 bytes) ──
   0000  45 00 05 dc d0 e1 40 00  40 06 8d 7c c0 a8 01 05   E.....@.@..|....
   0010  8e fa 50 2e 82 a5 01 bb  ab cd 12 34 5e 78 9a bc   ..P........4^x..
   ...
```

## Keybindings

| Key | Action |
|-----|--------|
| `↑`/`↓`           | Navigate (paused mode only) |
| `Enter`           | Open / close hex detail |
| `p` / `Space`     | Pause / resume auto-scroll |
| `f` / `/`         | Set BPF filter |
| `x`               | Clear filter |
| `w`               | Export visible packets to a pcap file |
| `n`               | Toggle DNS-name resolution in addr fields |

## What's normal

- Bursts of TCP/443 (browsing), some DNS, a steady trickle of mDNS /
  router advertisement.

## What's suspicious

- **Very high packet rate** to a single remote — feeds [BEACONING
  detection](alerts.md#beaconing) and `[v] Alerts`.
- **Wide port-scan signature**: many SYN packets to many local ports
  from one source IP triggers
  [PORT_SCAN](alerts.md#port_scan).
- **Unusual proto numbers** that survive the IPv4/IPv6 filter —
  e.g. proto 4 (IP-in-IP), proto 47 (GRE) showing up unexpectedly
  could indicate tunnelling.
- **Looped-back traffic** showing your own IP as both src and dst
  — often a misconfiguration but occasionally indicative of
  forged traffic.

## Tips

- Use `[/]` then a BPF filter like `port 53 or port 5353` to focus.
- `[w]` writes a timestamped `.pcap` to the cwd; usable directly in
  Wireshark.
- See also `--pcap-dir DIR` (CLI) for automatic per-alert exports.

## See also

- Capture pipeline: [`src/capture/capture.c`](../../src/capture/capture.c).
- pcap-file writer: [`src/pcap_write.c`](../../src/pcap_write.c).
- Per-alert pcap: [`src/alert_pcap.c`](../../src/alert_pcap.c).
