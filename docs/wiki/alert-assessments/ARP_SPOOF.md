---
type: ARP_SPOOF
technique: T1557.002
rule_file: src/alerts/rules_wired.c:121 rule_arp_spoof()
count_semantics: per rule evaluation, but this rule fires only on change - one increment per alerts_update() tick (at most POLL_MS 250 ms apart) on which an IP in the sensor's own /proc/net/arp shows a MAC different from the recorded baseline; the rule then overwrites the baseline (rules_wired.c:160) so a single change yields count 1 and the incident idles 300 s to resolve; a binding that flaps re-fires on each tick it is seen to differ from the last recorded MAC, so count = number of observed flips, not ticks open
severity_assessment: too high as a blanket - CRIT is warranted when the contested IP is the sensor's default gateway or resolver; a DHCP lease moved to a new machine, a VRRP/HSRP failover, or a dual-homed host produces the identical observation and is not an attack
false_positive_risk: high - "one IP, two MACs over time" is also what lease reassignment, first-hop redundancy and a laptop moving wired-to-wireless produce by design
noise_verdict: not seen on the reference host - host is null; because the input is the sensor host's own neighbour cache, a quiet result means no binding the kernel held changed, not that no cache poisoning occurred elsewhere on the segment
prevalence: the protocol is unauthenticated by design and interception tooling is standard in every LAN suite [3], [5], [6], [7]; no fetched source quantifies real-world frequency
tuning: []
researched: 2026-10-27
---
## What the rule checks

The input is `s->arp_entries`, filled by reading **`/proc/net/arp`** on Linux (`src/platform/linux.c:154-156`), with all-zero-MAC rows skipped (`:170-171`), and since #176 the kernel's IPv6 neighbour cache appended to the same table over rtnetlink (`src/platform/linux_neigh.c`, unresolved and proxy rows skipped) - so an IPv6 neighbour whose MAC changes fires this rule too, under `arp:<ipv6>`, though the technique cited is ARP's. That file is the sensor host's own kernel neighbour cache - what this machine currently believes about IP-to-MAC bindings on its interfaces - not a decode of ARP frames on the wire (`docs/wiki/capture-scope.md:69` says the same).

Each tick the rule walks every entry (`src/alerts/rules_wired.c:123`), skips a multicast/broadcast MAC (`:128`) and an all-zero MAC (`:129-131`), and looks the IP up in a file-scope history table `g_arp_hist`: `MAX_ARP_ENTRIES` = 256 rows (`include/sloth.h:314`), least-recently-seen evicted when full (`STAB_OLDEST`, tallied `evict_arp_hist`). A first sighting of an IP, or one returning after eviction, records a baseline MAC and stays silent (`:133-141`). If the IP is known and its MAC now differs (`:142`), the rule keys on `arp:<ip>` (`:152`), renders `"<ip> now claims MAC <new> (was <old>)"` (`:153-155`), fires CRIT with `match_ip` = the IP, `match_port` 0 (`:156-157`), and overwrites the stored MAC so the same change does not re-fire (`:160`). A flip back re-fires under the same key.

There is no time window, despite `docs/views/alerts.md:165`; the baseline persists until eviction, `alerts_clear()` (`rules_wired_forget`, `:116-119`) or restart. No IP is treated as special; the rule does not know which address is the gateway. The engine resolves the incident 300 s after the last tick that re-asserted the key (`include/sloth.h:860`). The eviction caveat (code comment `:85-100`): while more than 256 distinct IPs cycle through the table, an evicted IP that reappears re-baselines, so a change across that gap is missed; `sensor_health.evict_arp_hist` (`src/sensor_health.h:104`) reports whether that window was open.

## The mechanism

ARP maps an IPv4 address to a link-layer address by asking the segment and trusting the reply; RFC 826 has no authentication and its reception algorithm updates an existing table entry with the hardware address in the latest packet, for replies and requests alike [3]. A host that answers for another address - or sends unsolicited (gratuitous) replies claiming it - can cause other hosts to send that address's traffic to it instead; MITRE frames this as exploiting ARP's statelessness to interpose on communications and read unencrypted traffic [2]. The defensive literature is what matters here: the switch-side control is Dynamic ARP Inspection, which discards ARP packets whose IP-to-MAC binding is absent from the DHCP-snooping binding table [8]; MITRE's mitigations add static entries for critical hosts and encrypting traffic so interception yields less [2]. The repo corpus notes the fix needs switch support most networks do not deploy, which is why the technique stays effective [1]. Standard interception suites (dsniff's arpspoof [5], Ettercap [6], bettercap [7]) all implement it, so the capability should be assumed present on any segment.

## Evidence that proves it

What sloth records:

- `alert` / `alert.*` JSONL under `arp:<ip>` with old and new MAC in the detail;
- `arp` state records (`mac`, `ip`, `iface`, `docs/wiki/jsonl-schema.md:694`) showing the binding before and after;
- a per-alert pcap if `--pcap-dir` is set - CRIT passes the default `pcap.min_severity` 2 (`src/tune.c:121`) and the filter is `match_ip == src or dst` with no port (`src/alert_pcap.c:102-111`), so the file holds IPv4/IPv6 traffic to and from the contested address that was still in the ring at fire time. It never holds ARP frames: the capture dispatcher decodes only ethertypes 0x0800 and 0x86DD and drops ARP on purpose (`src/capture/capture.c:1160-1163`), so the poisoning frames themselves are not evidence sloth can produce;
- `sensor_health.evict_arp_hist` for whether the baseline table was churning.

What points to a real poisoning: the contested IP is the segment's gateway or resolver; the new MAC also appears, concurrently, as the MAC behind other IPs (one interface claiming several addresses) or is a MAC never seen as a DHCP client; the old MAC is still active (its own traffic continues) rather than gone; and the binding flaps as the legitimate host's ARP competes, which the rule shows as repeated fires with alternating old/new. The `arp` records across those minutes are the timeline.

What refutes it: the new MAC shares the old one's vendor OUI and the old MAC never reappears (device replaced, or a lease moved); the IP is a virtual-router address and the new MAC is in VRRP's `00-00-5E-00-01-{VRID}` range (RFC 5798 §7.3 [4]) or the move coincided with the gratuitous ARP a router sends for each virtual address when it becomes Master (§6.4.1, §6.4.2 [4]); the two MACs are one host's wired and wireless adapters sharing an address.

## Benign causes

- **DHCP lease reassignment** - the address legitimately moves to another machine [1]; a corresponding DHCP ACK to the new MAC exists in the snoop state, which a poisoning leaves no trace of.
- **First-hop redundancy** - VRRP/HSRP/keepalived move a virtual IP between routers on purpose; VRRP uses the `00-00-5E-00-01-{VRID}` virtual MAC and the new Master gratuitously ARPs for each address it takes over [4], [1].
- **Dual-homed host** - a laptop switching wired-to-wireless with one address shows two MACs in quick succession [1].
- **Gratuitous ARP on boot** - normal; the corpus says the conflict, not the announcement, is the signal [1], and this rule only fires on a change against a recorded baseline.
- **Eviction window** - after `evict_arp_hist` churn an old IP re-baselines silently, which is a missed change, not a false one.

## Assessment

CRIT fits the named case (a poisoned gateway binding on the sensor's host) and overstates the observable as implemented, which cannot separate that from a lease move. An honest split would be CRIT when the IP is the sensor's default route or configured resolver (both readable from the host) and WARN otherwise - a code change, as there is no knob.

Two points the alert page should carry. First, the input is the sensor's own neighbour cache, so sloth sees poisoning only when the sensor itself learned the poisoned binding; a poisoning aimed at a third host, with the sensor not addressed, leaves `/proc/net/arp` untouched and fires nothing. The corpus line that ARP is broadcast "so a passive listener sees the attack itself" [1] describes a frame-level detector, not `rule_arp_spoof`. Second, `docs/views/alerts.md:165` ("within a short window") does not match the code - there is no window.

Prevalence: the technique is a standing capability of every common LAN interception suite [5], [6], [7] and works wherever DAI is absent [3], [8]; no fetched source gives a usage rate, so this entry claims none.

Reference host: not seen (null) - consistent with no binding the sensor's kernel held having changed MAC, a weaker statement than "no spoofing on the segment".

Sufficient to act on alone? No. A responder should: (1) check whether the IP is the gateway or resolver; (2) read the OUI and history of both MACs in `device`/`arp` records - is the old one still talking; (3) look for a VRRP/HSRP virtual MAC or a known failover pair, and for a DHCP ACK to the new MAC. If it is the gateway with no lease or failover explanation, find the switch port of the new MAC and isolate it; longer term enable DAI and pin the gateway statically on hosts that matter (`docs/wiki/alert-remediation.md:207-230`, [2], [8]).

## Bibliography

1. research/mitre/T1557-002.md - repo corpus document citing `ALERT_TYPE_ARP_SPOOF` (source: https://attack.mitre.org/techniques/T1557/002/, retrieved 2026-09-07) (accessed 2026-10-27)
2. MITRE ATT&CK, Adversary-in-the-Middle: ARP Cache Poisoning, T1557.002 - https://attack.mitre.org/techniques/T1557/002/ (accessed 2026-10-27)
3. RFC 826, An Ethernet Address Resolution Protocol, "Packet Reception" - https://www.rfc-editor.org/rfc/rfc826 (accessed 2026-10-27)
4. RFC 5798, Virtual Router Redundancy Protocol (VRRP) Version 3, §6.4.2 and §7.3 - https://www.rfc-editor.org/rfc/rfc5798 (accessed 2026-10-27)
5. dsniff (arpspoof) - https://www.monkey.org/~dugsong/dsniff/ (accessed 2026-10-27)
6. Ettercap README ("A suite for man in the middle attacks"; the ARP method "will poison the arp cache of the two hosts") - https://github.com/Ettercap/ettercap (accessed 2026-10-27; the project homepage https://www.ettercap-project.org/ describes the suite but does not name ARP poisoning, so the README is the citation)
7. bettercap README (ARP/DNS/NDP/DHCPv6 spoofers) - https://github.com/bettercap/bettercap (accessed 2026-10-27)
8. Cisco, Layer 2 Security Features on Catalyst L3 Fixed Configuration Switches (DHCP snooping, Dynamic ARP Inspection) - https://www.cisco.com/c/en/us/support/docs/switches/catalyst-3750-series-switches/72846-layer2-secftrs-catl3fixed.html (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD c5650a3) and by fetching every external source.

- Code: `rule_arp_spoof()` at `src/alerts/rules_wired.c:121` re-read. Input is `s->arp_entries` from `/proc/net/arp` (`src/platform/linux.c:154-156`; the IPv6 half since #176 is `linux_neigh.c`, anchors updated 2026-11-03); multicast and all-zero MACs skipped; `g_arp_hist` is `STAB_DECL(..., MAX_ARP_ENTRIES, last_seen, STAB_OLDEST, SH_EVICT_ARP_HIST, ...)`; first sighting baselines silently; a differing MAC fires CRIT under `arp:<ip>` with `match_ip` = ip, `match_port` 0, then the baseline is overwritten. No time window exists in the code. Line anchors corrected (`:128`, `:129-131`, `:133-141`, `:142`, `:152`, `:153-155`, `:156-157`, `:160`, comment `:85-100`, `linux.c:163-165`).
- Count semantics reworded: this rule does not re-fire every tick while open; it fires only on a tick where the MAC differs from the stored one, so `count` is the number of observed flips. The frontmatter said "one increment per tick while the key is open", which is the engine's general behaviour but not this rule's.
- Per-alert pcap: settled the open question - `src/capture/capture.c:1160-1163` decodes IPv4 and IPv6 only and drops ARP, so the pcap holds IP traffic to/from the contested address and never the ARP frames.
- Sources: [2] T1557.002 fetched (stateless, no authentication; intercept and collect credentials over unencrypted protocols; mitigations include static ARP entries, encryption, DHCP snooping/DAI). [3] RFC 826 "Packet Reception" fetched: the table entry is updated and the merge happens before the opcode is examined. [4] RFC 5798 fetched: §7.3 MAC format confirmed; the gratuitous ARP on becoming Master appears in §6.4.1 and §6.4.2, so both are cited. [5] dsniff page names arpspoof. [6] re-sourced to the Ettercap README, because the homepage fetched does not mention ARP. [7] bettercap README lists "ARP, DNS, NDP and DHCPv6 spoofers". [8] Cisco page fetched: DAI validates against the DHCP-snooping binding database and drops invalid ARP on untrusted ports. [1] `research/mitre/T1557-002.md` exists and lists `ALERT_TYPE_ARP_SPOOF`.

Re-verified 2026-10-27 at HEAD 0d60387 (one web-only commit after c5650a3; no source line moved).

- Code anchors re-checked and unchanged: `rule_arp_spoof()` `:121`, multicast skip `:128`, all-zero skip `:129-131`, baseline `:133-141`, compare `:142`, key `:152`, detail `:153-155`, fire `:156-157`, overwrite `:160`, comment `:85-100`, `rules_wired_forget` `:116-119`; `src/platform/linux.c:149`, `:163-165`; `src/capture/capture.c:1160-1163` (IPv4/IPv6 only, ARP dropped); `src/alert_pcap.c:102-111`; `MAX_ARP_ENTRIES` 256 at `include/sloth.h:314`.
- All seven external sources re-fetched by this pass: [2] "The ARP protocol is stateless and does not require authentication", static ARP entries, encryption, "DHCP Snooping and Dynamic ARP Inspection"; [3] RFC 826: "update the sender hardware address field of the entry with the new information in the packet" and "the triplet is merged into the table before the opcode is looked at"; [4] RFC 5798 §7.3 `00-00-5E-00-01-{VRID}`, gratuitous ARP on becoming Master in §6.4.1 and §6.4.2; [5] dsniff page: "arpspoof, dnsspoof, and macof facilitate the interception of network traffic"; [6] Ettercap README: "will poison the arp cache of the two hosts"; [7] bettercap README: "ARP, DNS, NDP and DHCPv6 spoofers"; [8] Cisco: DAI "intercepts, logs, and discards ARP packets with invalid IP-to-MAC address bindings". No text change needed.
