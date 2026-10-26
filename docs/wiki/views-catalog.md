---
name: views-catalog
description: Every sloth view indexed by keybinding, grouped into observation / synthesis / WiFi SIGINT
type: reference
---

# Views catalog

**Summary**: Full keybinding-to-view map, with one-line descriptions and links to the per-view source docs in `docs/views/`.

**Sources**: `include/sloth_views.def` (the one list the enum, the tab
bar, the help card, the draw dispatch and the view-select keys are all
generated from — #117), `docs/views/README.md` and all `docs/views/*.md`.

**Count**: `VIEW_COUNT` = **<!-- count:views -->36<!-- /count -->**. Every key below is a row of
`include/sloth_views.def`; if the two disagree, the `.def` is right.

**Last updated**: 2026-10-26 (#150 review: the clip counts wide glyphs as two cells, a cut row ends with `›`, Research's sources and the Interfaces health strip break onto rows instead of being cut); 2026-10-23 (#150: list views size their page from the cursor and clip table rows at the edge, banners above them wrap; Twins keeps Flags whole at 100 columns); 2026-10-21 (#144 slice 4: `*` BLE, the first punctuation view key); 2026-10-15 (#117 — keys and count now generated from `sloth_views.def`).

---

## Observation — straight from the wire / kernel

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `1` | Interfaces  | [interfaces.md](../views/interfaces.md) | rtnetlink + sysfs view of every iface |
| `2` | Connections | [connections.md](../views/connections.md) | TCP/UDP sockets + PID + RTT + retx (INET_DIAG) |
| `3` | WiFi        | [wifi.md](../views/wifi.md) | nl80211 stations, signal, link state |
| `4` | Packets     | [packets.md](../views/packets.md) | live pcap, BPF filter, hex detail, pcap export |
| `5` | Processes   | [processes.md](../views/processes.md) | per-process socket inventory |
| `6` | Stats       | [stats.md](../views/stats.md) | counters from `/proc/net/snmp` |
| `7` | Probe       | [probe.md](../views/probe.md) | 802.11 probe-request sniffer |
| `8` | ARP         | [arp.md](../views/arp.md) | kernel ARP table |
| `9` | mDNS        | [mdns.md](../views/mdns.md) | multicast DNS service announcements |
| `0` | NBNS        | [nbns.md](../views/nbns.md) | NetBIOS name service / LLMNR |
| `d` | DHCP        | [dhcp.md](../views/dhcp.md) | DHCP DISCOVER/OFFER/REQUEST/ACK |
| `s` | SSDP        | [ssdp.md](../views/ssdp.md) | UPnP discovery |
| `b` | Beacons     | [beacons.md](../views/beacons.md) | passive 802.11 beacon sniffer |
| `a` | Deauth      | [deauth.md](../views/deauth.md) | deauth / disassoc + flood detection |
| `h` | HTTP        | [http.md](../views/http.md) | plaintext HTTP req log |
| `t` | TLS         | [tls.md](../views/tls.md) | ClientHello, SNI, JA3 — see [[ja3-fingerprinting]] |
| `u` | QUIC        | [quic.md](../views/quic.md) | QUIC initials |
| `r` | DNS         | [dns.md](../views/dns.md) | every Q/R on UDP/53 |
| `p` | NTP         | [ntp.md](../views/ntp.md) | NTP traffic |
| `i` | ICMP        | [icmp.md](../views/icmp.md) | ICMP log |
| `m` | Channel     | [channel.md](../views/channel.md) | per-channel 802.11 activity histogram |

## Synthesis — derived from observation

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `v` | Alerts    | [alerts.md](../views/alerts.md) | rule-derived events — see [[alerts]] |
| `g` | Devices   | [devices.md](../views/devices.md) | join of ARP + DHCP + beacons + probes + stations, with a `CAMERA` row type and an `Enter` signal-trail detail ([[camera-detection]]) |
| `o` | Dashboard | [dashboard.md](../views/dashboard.md) | seven-band composite — see [[dashboard]] |
| `l` | OSI stack | [osi.md](../views/osi.md) | every observed count mapped onto its OSI layer |
| `x` | Twins     | [twins.md](../views/twins.md) | evil-twin episode table |
| `y` | KARMA     | [karma.md](../views/karma.md) | KARMA / PineAP candidate table (#30) |
| `z` | RADIUS    | [rogue-radius.md](../views/rogue-radius.md) | 802.1X EAP method / identity-leak table (#31, #38) — see [[enterprise-rogue]] |
| `c` | FragAttacks | [fragattack.md](../views/fragattack.md) | per-BSSID FragAttacks counters (#75) — see [[fragattacks]] |
| `*` | BLE | [ble.md](../views/ble.md) | BLE advertisers per sensor, HID / watchlist flags, `Enter` detail (#144 slice 4) — see [[ble]]. `*` because every letter and digit is taken |
| `f` | Research  | [research.md](../views/research.md) | the cited source behind each alert that fired (#73) — see [[research-corpus]] |
| `?` | Help      | — | keybindings, version, and the embedded-data disclosures |

## WiFi SIGINT (v1.1)

See [[wifi-sigint]] for the full SIGINT primitives.

| Key | View | Source doc | One-liner |
|-----|------|-----------|-----------|
| `k` | PNL    | [pnl.md](../views/pnl.md) | per-MAC PNL aggregation + OS fingerprint |
| `e` | EAPOL  | [eapol.md](../views/eapol.md) | PMKID + 4-way handshake capture |
| `j` | Seqnum | [seqnum.md](../views/seqnum.md) | MAC-randomisation deanonymisation — see [[mac-randomisation]] |
| `w` | Assoc  | [assoc.md](../views/assoc.md) | confirmed STA ↔ AP associations |

## List views at the 100x33 minimum

The tab bar wraps: at 100 columns it is six rows, at 200 three. A list
view therefore sizes its page from the row its table starts on, not
from the top of the screen: `view_page_budget(tail, ansi_page)` in
`src/views/view_page.h`, called after the view's status and header
lines, with `tail` the rows the view draws under the table (a legend,
a footer, a detail pane). Until #150 each view used `LINES - 5` (or 6,
8, 12, 16) as if the bar were one row, so at 100x33 the page overran
the screen: the selection could sit below the last row, and a legend
under the table - Twins' "neither half accused", RADIUS's CVE line -
was never drawn.

Table rows never wrap. A list view calls `tui_clip_rows(1)` after its
status and banner lines, just before its column headers, and every
line it prints from there is cut one column short of the screen edge;
a row that wrapped took two screen lines and pushed the rest of the
page down. The lines above the headers are prose and do wrap: Conns'
`[SCAN ALERT]` banner names attacker addresses, and clipping it hid
the fourth address and the `+N more` count at 100 columns. A wrapped
banner costs the page nothing, since the budget is measured after it.
Width is counted per glyph with `wcwidth()`, so an emoji or CJK
character in an SSID, hostname or SNI is two cells: counting one per
glyph let a cut row still reach the edge and wrap. Tables wider than
100 columns (Connections 136, Beacons 130, WiFi 114, Packets' header
143) lose their right-hand columns at the minimum and show them on a
wider terminal; each view's doc names what goes. A row cut through
anything but padding ends with `›` (U+203A) in its last cell, so a
hidden column does not read as an empty one. Twins is the exception: its Flags column
is what the legend explains, so below 114 columns it drops `Last` and
narrows SSID instead, and Flags stays whole. Text a view draws below the
last screen row is dropped rather than appended to that row; brand
letters and Packets' hex/ASCII bytes go through the same path.

Prose under a table that must be read whole is not clipped either: it
is drawn with `tui_addstr_wrapped(s, indent)`, broken onto rows of at
most `COLS - 1` cells with each continuation indented, and the view
counts those rows in its tail with `tui_wrapped_rows()`. Research's
source titles and URLs use it (a URL is up to 127 octets, and the clip
had cut the longer ones and their retrieval dates at column 99), and so
does the Interfaces health strip, whose faults at the end are the ones
the strip exists for.

Under the table, per view: Alerts 2 (blank line and the enrichment
line), Twins 6 (legend), RADIUS 2 (legend), KARMA 2 (legend), BLE 1
(legend), Beacons 1 when there is 802.11k survey activity, FragAttacks
12 (detail pane), Research the selected row's detail pane (each title
and URL counted at the rows it breaks onto), Interfaces the health
strip's rows plus the key hint, Deauth the BTM section when there is
802.11v steering (capped at a third). The rest draw nothing under it.

Pinned by `tests/test_view_fit.c`: one 100x33 `tui_draw()` test per
list view (no line reaches column 100, nothing below the screen, the
selected last row exactly `tail` rows above the bottom) and the same
checks at 200 columns, so the fit is not bought with a short page.
PNL, EAPOL, Assoc, Channel and Seqnum draw every row with no page or
selection and are not covered yet: at 100x33 their excess rows are
dropped below the screen, not drawn over the last row, but they cannot
be scrolled to. Paging them, and narrower column plans for Connections,
Beacons, WiFi and Packets, are follow-up work.

## Adding a view

See `CLAUDE.md` "How to add a new view" — 11-step checklist that keeps
`VIEW_COUNT` in sync, lays out the file, wires the key, and demands a
test + a per-view doc.

A new list view also follows the page contract above, which that
checklist does not yet name: call `view_page_budget(tail, ansi_page)`
after the column headers, with `tail` the rows drawn under the table
(name it, as `TWINS_LEGEND_ROWS` does, rather than write a bare
number); call `tui_clip_rows(1)` just before the headers, never above
a banner; and add a case to `tests/test_view_fit.c`. A fixed
`LINES - N` is the bug #150 removed.

## Related pages

- [[sloth]]
- [[architecture]]
- [[dashboard]]
- [[attack-map]]
