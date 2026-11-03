---
type: ROGUE_DHCP
technique: T1557
rule_file: src/alerts/rules_wired.c:834 rule_rogue_dhcp()
count_semantics: per rule evaluation - one increment per alerts_update() tick (at most 250 ms apart) while two or more distinct DHCP server identifiers (option 54) are present across the 128-row per-client DHCP event table; the sorted server set is the dedup key, so one incident persists while both identifiers remain on any client row
severity_assessment: too high as a blanket - CRIT fits a server nobody deployed handing out a gateway or resolver; RFC 2131 explicitly permits multiple overlapping servers for reliability, and the rule has no baseline to tell the two apart
false_positive_risk: medium - a failover pair or split scope fires permanently; a home router or phone hotspot plugged in by mistake fires too and is the ordinary case, not an adversary
noise_verdict: not seen on the reference host - host is null, consistent with a single-server segment; on any two-server segment this is one permanent CRIT, so the remedy is a known-servers allowlist, not a threshold
prevalence: a named ATT&CK sub-technique (T1557.003 DHCP Spoofing) with ready tooling in Metasploit, Yersinia and bettercap [2], [4], [5], [6]; no fetched source quantifies real-world frequency
tuning: []
researched: 2026-10-27
---
## What the rule checks

Input: `s->dhcp_events`, the DHCP snoop table of `MAX_DHCP_EVENTS` = 128 rows keyed by **client MAC** (`include/sloth.h:259-280`; `event_get(mac)` in `src/dhcp_snoop.c`). Each parsed DHCP message updates that client's row; when a message carries option 54 (Server Identifier, `OPT_SERVER_ID` 54, `src/dhcp_snoop.c:36`, parsed `:140-141`) the row's `server_ip` is replaced with it (`:171-172`). Option 54 appears on server replies (OFFER/ACK/NAK) and on a client REQUEST naming the server whose offer it took; the comment at `:186-189` notes that on a switched port the client's broadcast REQUEST is often all sloth sees of a server.

Per tick the rule gathers the distinct non-empty `server_ip` values across all rows, up to 16 (`src/alerts/rules_wired.c:784-792`). Fewer than two: return (`:794`). Otherwise it sorts them (`:797-807`) and keys on a typed set `rogue_dhcp:<n>:<hash of sorted members>` (`akey_set`, `:816-820`; `docs/wiki/alerts.md:132`), so the same pair in any order is one incident and a third server mints a new key (`tests/test_alerts.c:4243-4281`). Detail: `"<n> distinct DHCP servers on segment: <ip>, <ip>, ..."` (`:822-827`). Fires CRIT, `match_ip` = alphabetically first server, `match_port` 67 (`:831-832`; `tests/test_alerts.c:4284-4296`).

There is no baseline and no approved-server concept, despite `docs/views/alerts.md:166` ("non-baseline server"); the remediation wiki states the real behaviour - "the rule fires on any two, with no baseline" (`docs/wiki/alert-remediation.md:235-237`). Client-only messages carry no option 54 and never count (`tests/test_alerts.c:4229-4240`). The incident resolves 300 s after the condition last held (`include/sloth.h:860`), i.e. once every client row carrying the second identifier ages out or is overwritten.

## The mechanism

A DHCP client broadcasts for configuration and accepts an offer that supplies its address, default gateway (option 3) and resolver (option 6). RFC 2131 §3.1 says the client "receives one or more DHCPOFFER messages", "may choose to wait for multiple responses" and "chooses one server"; §1.6 says a client must be prepared for multiple responses because "some installations may include multiple, overlapping DHCP servers to enhance reliability and increase performance" [3]. An unauthorised server that answers first, or for addresses a client will prefer, can therefore install itself as the victim's gateway or DNS and interpose on traffic; MITRE files this under Adversary-in-the-Middle, with a dedicated sub-technique T1557.003 (DHCP Spoofing) that also calls out blocking DHCPv6 and rogue router advertisements where IPv6 is not used [2]. The repo maps the rule to the parent T1557 (`include/sloth_alerts.def:37`). Tooling is commodity: Metasploit's `auxiliary/server/dhcp` "provides a DHCP service" [4], Yersinia lists DHCP among its layer-2 attack protocols [5], and bettercap ships "ARP, DNS, NDP and DHCPv6 spoofers" [6]. The defensive control is switch DHCP snooping, which treats user-facing ports as untrusted and drops server-type replies (DHCPOFFER, DHCPACK, DHCPNAK) arriving on them [7]; MITRE's mitigations are to filter DHCP on ports 67/68 to and from unknown servers, enable DHCP snooping, and block DHCPv6 and incoming router advertisements where IPv6 is not used (M1037), plus network intrusion prevention (M1031) [2]. The corpus notes there is no network-side control in the protocol itself; the remedy is removing the unintended server [1].

## Evidence that proves it

What sloth records:

- `alert` / `alert.*` JSONL under the `rogue_dhcp:<n>:<hash>` key, with the detail listing every server IP in sorted order;
- `dhcp_event` state records per client (`docs/wiki/jsonl-schema.md`) - `mac`, `ip`, `hostname`, `msg_type`, `server_ip`, and the client's option 55 PRL / option 60 VCI (`include/sloth.h:263-279`) - which show which clients each server answered and what addresses were handed out;
- a per-alert pcap if `--pcap-dir` is set (CRIT passes default `pcap.min_severity` 2); the filter is `match_ip` (first server) and port 67 either side (`src/alert_pcap.c:102-111`), so the file holds that server's DHCP exchange from the ring.

What points to a rogue server: a second `server_ip` that is a client-range address (a host, not the router), handing out a gateway or resolver different from the legitimate one; clients with that server in their row suddenly pointed at an unexpected gateway; a server whose VCI/PRL footprint on its own clients looks like a consumer router rather than the site's DHCP appliance. The `dhcp_event` rows for the affected clients are the record.

What refutes it: the two servers are a documented failover pair or a split scope handing out the same gateway and resolver with non-overlapping address pools - RFC 2131 §4.3.1 makes the network administrator "responsible for configuring multiple DHCP servers to ensure uniform responses", address aside, so the clients' `ip`/gateway stay coherent [3]; or the second "server" is a transient hotspot that one client briefly accepted and then released.

## Benign causes

- **Failover pair / split scope** - two servers by design, firing permanently [1], `docs/wiki/alert-remediation.md:235-237`.
- **A home router or phone hotspot plugged in backwards** - the ordinary cause, a misconfiguration rather than an adversary [1], `docs/wiki/alert-remediation.md:244-246`.
- **Relay artefacts** - a client REQUEST echoes the server identifier it accepted, so a single real server reached through different relays still shows one identifier; the risk is the inverse (under-count), not a false positive.

## Assessment

CRIT fits a server nobody deployed that is handing out a gateway or resolver - the interposition case - and overstates a sanctioned two-server design. Because there is no baseline, the rule cannot distinguish them, and the right fix is an operator-supplied list of known DHCP servers that suppresses the alert when every observed server is on it; that is a feature, not a `--tune` value (there is no knob today). The remediation page already tells the operator to do the discrimination by hand (`docs/wiki/alert-remediation.md:232-253`).

Prevalence: DHCP spoofing is a first-class ATT&CK sub-technique with commodity tooling [2], [4], [5], [6]; no fetched source gives a field rate, so none is claimed. On a correctly run single-server segment the alert should be silent, which is what the reference host shows (null).

Reference host: not seen. Consistent with one DHCP server. The useful read is that on a two-server segment this would be a single standing CRIT - so if an operator sees it fire once and stay, the first question is whether the second server is theirs.

Sufficient to act on alone? No, but close: the detail already names every server. A responder should (1) identify which listed servers the network is meant to have; (2) for any extra one, read its `dhcp_event` rows to see what gateway/resolver it handed out and to which clients; (3) if it is unsanctioned and the device is theirs, disconnect or reconfigure it, else report it to whoever runs the segment, and leave a designed failover pair alone (`docs/wiki/alert-remediation.md:248-253`, [2]). Enable DHCP snooping to stop it at the switch [7].

## Bibliography

1. research/mitre/T1557.md - repo corpus document citing `ALERT_TYPE_ROGUE_DHCP` (source: https://attack.mitre.org/techniques/T1557/, retrieved 2026-08-31) (accessed 2026-10-27)
2. MITRE ATT&CK, Adversary-in-the-Middle (T1557) and DHCP Spoofing (T1557.003) - https://attack.mitre.org/techniques/T1557/003/ (accessed 2026-10-27)
3. RFC 2131, Dynamic Host Configuration Protocol, §1.6 ("multiple, overlapping DHCP servers to enhance reliability and increase performance"), §3.1 ("one or more DHCPOFFER messages"; the client "chooses one server"), §4.3.1 ("The network administrator is responsible for configuring multiple DHCP servers to ensure uniform responses") - https://www.rfc-editor.org/rfc/rfc2131 (fetched and confirmed 2026-10-27)
4. Metasploit `auxiliary/server/dhcp` module ("This module provides a DHCP service") - https://www.rapid7.com/db/modules/auxiliary/server/dhcp/ (fetched and confirmed 2026-10-27)
5. Yersinia - Kali tool page listing DHCP among STP, CDP, DTP, HSRP, 802.1q, 802.1x, ISL, VTP - https://www.kali.org/tools/yersinia/ (fetched and confirmed 2026-10-27)
6. bettercap README ("ARP, DNS, NDP and DHCPv6 spoofers for MITM attacks on IPv4 and IPv6 based networks") - https://github.com/bettercap/bettercap (fetched and confirmed 2026-10-27)
7. Cisco, Layer 2 Security Features on Catalyst Layer 3 Fixed Configuration Switches - DHCP snooping ("untrusted user-facing ports must not send DHCP server type responses, such as DHCPOFFER, DHCPACK, or DHCPNAK") - https://www.cisco.com/c/en/us/support/docs/switches/catalyst-3750-series-switches/72846-layer2-secftrs-catl3fixed.html (fetched and confirmed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD 0d60387; `src/alerts/` unchanged since c5650a3) and by fetching every external source.

- Code: `rule_rogue_dhcp()` at `src/alerts/rules_wired.c:781` re-read. Collects up to 16 distinct non-empty `server_ip` across `s->dhcp_events` (`:784-793`), returns under two (`:794`), selection-sorts (`:797-807`), keys with `akey_begin("rogue_dhcp")` + `akey_set(members, n)` (`:816-820`), detail `"%d distinct DHCP servers on segment: ..."` (`:822-827`), fires CRIT with `servers[0]` and port 67 (`:831-832`). `src/dhcp_snoop.c`: option-54 parse is `:140-141` (was cited as 138-141), the row replace `:171-172`, the switched-port comment `:186-189` (was 187-190). Test anchors corrected to the function starts (`test_rogue_dhcp_client_requests_dont_count` `:4229`, `..._detail_lists_servers_sorted` `:4243`, `..._match_port_is_server_port` `:4284`). No baseline or allowlist exists, as stated; `include/sloth_alerts.def:37` maps to T1557.
- Count semantics unchanged in substance; tick spacing restated as an upper bound (`POLL_MS` is a maximum wait, `include/sloth.h:28`).
- Sources: [3] RFC 2131 fetched - the §4.1 citation was wrong; the three claims live in §3.1 (multiple offers, client chooses), §1.6 (overlapping servers for reliability) and §4.3.1 (administrator ensures uniform responses), now quoted. [2] T1557.003 fetched: it names mitigations M1037 (filter 67/68, DHCP snooping, block DHCPv6/RA) and M1031; it names no tools, so tooling rests on [4]-[6] only. [4] Rapid7, [5] Kali, [6] bettercap README, [7] Cisco all fetched and support their sentences (quotes added). Bibliography renumbered contiguously (the draft skipped 4-5 and used an `8-cisco` label); body references updated. [1] `research/mitre/T1557.md` exists and names `ALERT_TYPE_ROGUE_DHCP`.
