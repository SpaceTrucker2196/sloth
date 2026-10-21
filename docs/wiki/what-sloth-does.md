---
name: what-sloth-does
description: The complete picture of sloth as a passive monitor — the sensing surfaces it reads, the views, the alert rules, the outputs, and the hard line it never crosses
type: reference
---

# What sloth does

**Summary**: sloth is a terminal-based **passive** network monitor for
Linux, C99, single binary. It reads what is already on the wire and in
the air and surfaces it through <!-- count:views -->36<!-- /count --> views and <!-- count:rules -->90<!-- /count --> alert rules. It never
injects a frame onto a network it monitors; everything else that uses
the network is opt-in and announced (`MISSION.md` §2). This page is the one-screen map of everything it does; each row links to the
page that covers it in full.

**Sources**: `MISSION.md`, `CLAUDE.md`, `src/main.c`, `include/sloth.h`,
all `docs/views/*.md`.

**Last updated**: 2026-10-15.

---

## The one-line version

> Point sloth at a wired interface and a monitor-mode Wi-Fi interface.
> It tells you who is on the network, who is *near* the network, what
> they are saying in the clear, and which of ~61 known-bad behaviours it
> just saw — and it writes none of its own traffic to do it.

## What it reads (the sensing surfaces)

| Surface | Via | What it yields |
|---------|-----|----------------|
| Interfaces / link state | rtnetlink + `/sys` | every iface, up/down, addresses |
| Sockets | INET_DIAG | TCP/UDP connections + owning PID + RTT + retransmits |
| Wi-Fi stations | nl80211 | associated STAs, signal, link state |
| ARP / neighbour | netlink | the kernel ARP table |
| Packet stream | libpcap | the L2–L7 decode chain below |
| 802.11 management | libpcap on a monitor iface | beacons, probes, auth/assoc, deauth, action frames |
| `/proc/net` | procfs | protocol counters (Stats view) |

The packet thread decodes IPv4/IPv6 → TCP/UDP → DNS, TLS, HTTP, QUIC,
NTP, ICMP, and the 802.11 frame classes ([[how-wifi-works]] §2). It reads
every layer; it writes to none. See [[platform-vtable]] for the kernel
seam and [[architecture]] for the code tree.

## What it shows (<!-- count:views -->36<!-- /count --> views)

Grouped three ways. Full keybinding map: [[views-catalog]].

- **Observation** — straight from the wire/kernel: Interfaces, Connections,
  WiFi, Packets, Processes, Stats, Probe, ARP, mDNS, NBNS, DHCP, SSDP,
  Beacons, Deauth, HTTP, TLS, QUIC, DNS, NTP, ICMP, Channel.
- **Synthesis** — derived: Alerts, Devices, Dashboard, OSI stack, Twins,
  KARMA, Rogue RADIUS, FragAttacks, Research, Help.
- **WiFi SIGINT** — PNL, EAPOL, Seqnum, Assoc. See [[wifi-sigint]].

The **Dashboard** `[o]` tiles seven bands into one screen; see [[dashboard]].

## What it decides (<!-- count:rules -->90<!-- /count --> alert rules)

One rule per `ALERT_TYPE_*`, each with a cited basis (a CVE, CERT
advisory, MITRE technique, IEEE clause, or paper — the repo enforces the
citation, see [[research-corpus]]). Severity is LOW / WARN / CRIT, and
for the WiFi impersonation rules a **confidence %** separate from
severity. Full catalogue with triggers: [[alerts]] and
`docs/views/alerts.md`. The threat-intel matcher ships **synthetic demo
IOCs**, not a feed ([[threat-intel]]). Which attack maps to which view:
[[attack-map]] and [[where-exploits-happen]].

## What it writes (outputs, all opt-in)

| Flag | Output | Page |
|------|--------|------|
| `-o FILE` | JSONL / CEF / syslog forensic log | [[jsonl-schema]] |
| `--data-socket SPEC` | read-only live stream of the same records | [[data-socket-exposure]] |
| `--pcap-dir DIR` | per-alert packet capture | [[pcap-export]] |
| `--eapol-dir DIR` (needs `--collect-handshakes`) | captured PMKID / 4-way handshakes (hashcat 22000 + per-handshake pcap). Opt-in, off by default; swept after `--handshake-retention` days (default 7) | [[wifi-sigint]], [[pcap-export]], [[retention]] |
| `--db FILE` | bounded SQLite entity state | [[sqlite-schema]], [[retention]] |
| `--report FILE.md` / `--report-json` | posture report on exit | [[posture-report]] |
| `--snapshot-out` / `--baseline-in` | AP-inventory snapshot + diff | [[posture-report]] |

Everything sloth writes can hold captured traffic, so directories are
`0700` and files `0600`, validated not repaired. Full CLI: [[cli-reference]].

## What it never does

This is the charter, from `MISSION.md` §2, and it is load-bearing. Since
2026-10-14 it has **one absolute** and two properties that make the word
"passive" worth something:

- **No injection — ever, under any flag.** sloth never crafts and sends
  a frame onto a network it is monitoring: no deauth, no probes, no
  beacons, no ARP poisoning, no forged frames. No flag, build option or
  deployment mode turns this off.
- **Optional services may use the network.** A resolver, a scan
  trigger, the data socket, an mDNS advertisement, a local web
  interface — these transmit from the host over paths you configured,
  and none puts a frame on the monitored segment. What sloth *observes*
  it observes passively; what it *offers* it may offer like any daemon.
- **sloth never puts an interface into monitor mode.** You do that with
  `iw` first; sloth only tunes a receiver already in it (`--hop`), and
  only its own. See [[monitor-mode]].
- **Every network-using service is opt-in and announced.** None is on
  by default; `--allow-active` prints on stderr exactly what it enabled;
  `--strict` locks the active behaviours off for the run and refuses a
  routable `--data-socket`. The failure this guards against is a passive
  tool that quietly becomes active — about silence, not capability.

The one write that is neither opt-in nor announced is **promiscuous
mode**: libpcap sets it when the capture handle opens. It changes what
sloth's own NIC accepts, never what the segment carries.

The older wording — "never scans, never modifies kernel state" — was
retired because three documented opt-ins (`--hop` #22, discovery #29,
`--allow-active` #84) had already eaten it, and promiscuous mode was
never in it at all. See [[log]] 2026-10-14.

- **No mocks of real-data interfaces** in tests; the fake platform in
  `tests/fake_platform.c` is the seam.
- **No network fetch.** No threat feed, no self-update, no telemetry. A
  version check reads a locally-populated manifest ([[version-checkin]]).

The line is the product: sloth is trustworthy *because* it is passive.
An operator can run it on a network they do not own and know it added
nothing to the air.

## Related pages

- [[how-wifi-works]] — the 802.11 ground truth underneath the WiFi views.
- [[monitor-mode]] — the capability that unlocks the WiFi frame classes.
- [[where-exploits-happen]] — the attack surface sloth watches, mapped.
- [[wifi-sigint-techniques]] — the passive analyst techniques sloth supports.
- [[cli-reference]] — every flag and argument.
- [[views-catalog]] · [[alerts]] · [[attack-map]] · [[architecture]].
