---
type: ROGUE_RA
technique: T1557
rule_file: src/alerts/rules_wired.c:909 rule_rogue_ra()
count_semantics: per rule evaluation - one increment per alerts_update() tick (poll.c:296; the wait between ticks is at most POLL_MS 250 ms, include/sloth.h:28 - the loop wakes early on alert fires and --refresh-ms can shorten it, so 4 ticks/s is a floor, not a fixed cadence) while two or more distinct IPv6 sources with a non-zero router lifetime are present in the 16-row RA tracker; the comma-joined sorted router list is the key, so one incident persists while both routers keep advertising
severity_assessment: too high as a blanket - CRIT fits an unsanctioned router injecting a default route (the SLAAC-attack / Slaacers case); a first-hop redundancy pair or two legitimate uplinks produce the same two-router observation; note that mitm6 in its default form advertises router lifetime 0 and is excluded by this rule's lifetime gate, so the best-known IPv6 interposition tool is not what this rule catches
false_positive_risk: medium - redundant routers and transient host-originated RAs (Windows ICS, 6to4) trip it; the rule has no baseline
noise_verdict: not seen on the reference host - host is null, consistent with zero or one RA source; on a dual-router segment this is one permanent CRIT, so the remedy is a known-routers list or switch RA-Guard, not a threshold
prevalence: a standing IPv6 LAN problem (RFC 6104) [2]; the widely bundled IPv6 interposition tool, mitm6, works through DHCPv6 and sends its RA with router lifetime 0, outside this rule's candidate set [4], [5]; no fetched source quantifies real-world frequency
tuning: []
researched: 2026-10-27
---
## What the rule checks

Input: `s->ndp_ras`, the Router Advertisement tracker of `MAX_NDP_RAS` = 16 distinct RA-emitting sources (`include/sloth.h:559-574`), filled by `ndp_snoop_ra()` parsing ICMPv6 type 134 per RFC 4861 §4.2 (`src/ndp_snoop.c:52-124`). Each row holds the source IPv6 address, optional source link-layer address (option 1, §4.6.1), the flags byte, `router_lifetime` (RA bytes 6-7, big-endian seconds), and up to 4 prefixes from Prefix Information options (§4.6.2) (`include/sloth.h:561-574`; `docs/wiki/ipv6-ndp.md:43-53`).

Per tick the rule collects distinct `src_ip` values whose `router_lifetime` is non-zero, up to 8 (`src/alerts/rules_wired.c:844-853`). The lifetime gate is the key correctness point: RFC 4861 §4.2 says a Router Lifetime of 0 means the router is not a default router and should not appear on the default-router list, so the rule excludes it (`:848`; `docs/wiki/ipv6-ndp.md:51`) [6]. Fewer than two qualifying routers: return (`:855`). Otherwise it sorts them (`:858-868`) and keys on `rogue_ra:<comma-joined sorted IPs>` (`:870-874`; `docs/wiki/ipv6-ndp.md:74`), detail `"<n> distinct IPv6 routers on segment: <ip>, <ip>, ..."` (`:876-880`), fires CRIT with `match_ip` = first router and `match_port` 0 - NDP has no L4 port (`:883-884`; `docs/wiki/ipv6-ndp.md:76`). A third router joining mints a new key. The incident resolves 300 s after the condition last held (`include/sloth.h:860`); the 16-row tracker evicts least-recently-seen (`evict_ndp_ra`, `src/sensor_health.h:117`). The rule is the IPv6 analogue of `rule_rogue_dhcp`, same shape, same no-baseline limitation (`docs/wiki/ipv6-ndp.md:78-82`).

## The mechanism

On IPv6 a host learns its default router and on-link prefixes from Router Advertisements, which NDP does not authenticate by default (Secure Neighbor Discovery exists but is rarely deployed) (`docs/wiki/ipv6-ndp.md:9-13`, [8]). A second source advertising a router lifetime competes to be a default route, and SLAAC hosts - which modern operating systems configure automatically whenever a router appears - may adopt it [2], [9]. The best-known tool, mitm6, does not advertise itself as the default gateway; it replies to DHCPv6 to install itself as the victim's **DNS server**, then answers internal names (notably WPAD) to relay credentials [4], [5]. Its RA is built as `ICMPv6ND_RA(M=1, O=1, routerlifetime=0)` (`mitm6/mitm6.py`, [4]) - M/O set to push clients to DHCPv6, lifetime zero so as not to become a gateway - and that means **this rule does not fire on mitm6 in its default form**: the lifetime gate at `:848` drops the source for the same RFC 4861 reason it drops shutdown advertisements. What sloth keeps is the `ndp_ra` row for that source, `router_lifetime` 0 with M and O set, which is evidence an operator can read but not an alert. Because Windows enables IPv6 and prefers it over IPv4 by default, and Microsoft recommends against disabling IPv6 [10], a host that SLAACs itself the moment a rogue router appears can have IPv6 traffic silently diverted even on a network that is "IPv4-only on paper" (`docs/wiki/ipv6-ndp.md:30-37`, [9]). RFC 6104 catalogues the problem and both its malicious and accidental forms, and lists the mitigations [2]; RFC 6105 specifies RA-Guard, a layer-2 filter that blocks RAs from untrusted ports [3], with RFC 7113 documenting evasions (extension-header and fragmentation tricks) that an implementation must handle [7]. The repo maps the rule to T1557 (Adversary-in-the-Middle), the parent of the IPv6 interposition family (`include/sloth_alerts.def:38`, [1]).

## Evidence that proves it

What sloth records:

- `alert` / `alert.*` JSONL under `rogue_ra:<sorted IPs>`, the detail listing every advertising router;
- `ndp_ra` state records keyed on `src_ip` (`docs/wiki/jsonl-schema.md:722`): source address and MAC (if the SLLA option was present), `cur_hop_limit`, `flags` (M/O/H), `router_lifetime`, and the advertised `prefixes[]`;
- a per-alert pcap if `--pcap-dir` is set (CRIT passes default `pcap.min_severity` 2); `match_port` is 0, so the filter is `match_ip == src or dst` only (`src/alert_pcap.c:102-111`).

What points to a rogue router (`docs/wiki/ipv6-ndp.md:93-99`): a second `router_lifetime > 0` source whose `src_mac` OUI does not match the legitimate router's vendor; an advertised prefix that differs from the segment's real range, often by a single nibble; the M (Managed) / O (Other) flags set on a source that also carries a non-zero lifetime, steering clients to DHCPv6 for DNS; a source with M/O set and `router_lifetime` 0 is the mitm6 default and appears only in the `ndp_ra` record, never in this alert [4], [5]; or a sudden change in the real router's `cur_hop_limit` or `flags` suggesting impersonation rather than competition.

What refutes it: both sources are the site's documented first-hop redundancy pair or two sanctioned uplinks, advertising the real prefix with an expected vendor OUI; or the second source is a host running Windows Internet Connection Sharing or a 6to4 transition service that RFC 6104 names as a benign cause [2].

## Benign causes

- **Redundant routers** - a first-hop redundancy pair or two uplinks, by design (`docs/wiki/alert-remediation.md:257-279`).
- **Administrator/user misconfiguration** - RFC 6104 names router-interface misconfiguration, and user machines running Windows ICS or 6to4 that emit RAs unintentionally [2].
- **Shutdown advertisements** - a host emitting `router_lifetime = 0` during shutdown is explicitly excluded by the rule (`docs/wiki/ipv6-ndp.md:89-91`), so it is not a false positive here.
- **Eviction** - with the 16-row tracker under churn an older router can age out, which is a missed second router, not a false one.

## Assessment

CRIT fits an unsanctioned router injecting a default route or DNS; it overstates a designed redundant pair. As with `ROGUE_DHCP`, the discriminator the rule lacks is a baseline of expected routers, and the proper remedy is an operator-supplied known-routers list that suppresses the alert when every advertiser is on it - a feature, not a knob. The strongest single tell in the evidence is a mismatched prefix or SLLA OUI on a non-zero-lifetime source. The gap to state plainly: mitm6, the most-bundled IPv6 interposition tool, sends its RA with router lifetime 0 [4], [5] and so never enters this rule's candidate set; catching it needs a rule on M/O-flagged zero-lifetime advertisements or on DHCPv6 replies, neither of which exists today.

Prevalence: rogue RAs are a documented IPv6 LAN hazard, both accidental and malicious [2]; the broadly bundled tool works through DHCPv6 rather than a default-route RA [4], [5]; no fetched source gives a field rate, so none is claimed. The default-route/DNS theft needs no user action, which is what makes a true positive urgent [9].

Reference host: not seen (null) - consistent with zero or one advertising router. On a dual-router segment this would be a single standing CRIT; an operator seeing it fire and persist should first confirm whether the second router is theirs.

Sufficient to act on alone? No, but the detail names the routers. A responder should (1) identify which listed routers are sanctioned; (2) for any extra one, read its `ndp_ra` record - prefix, flags, SLLA OUI - to judge whether it is a redundancy peer, an ICS/6to4 host, or an interposer; (3) if unsanctioned and theirs, disconnect or reconfigure it, else report it, leaving designed redundant routers alone (`docs/wiki/alert-remediation.md:275-279`, [2]). Deploy RA-Guard on access ports to stop it at the switch [3], [7].

## Bibliography

1. research/mitre/T1557.md - repo corpus document citing `ALERT_TYPE_ROGUE_RA` (source: https://attack.mitre.org/techniques/T1557/, retrieved 2026-08-31) (accessed 2026-10-27)
2. RFC 6104, Rogue IPv6 Router Advertisement Problem Statement (benign causes and mitigations) - https://www.rfc-editor.org/rfc/rfc6104 (accessed 2026-10-27)
3. RFC 6105, IPv6 Router Advertisement Guard - https://www.rfc-editor.org/rfc/rfc6105 (accessed 2026-10-27)
4. mitm6 (dirkjanm) - https://github.com/dirkjanm/mitm6 (README, and the RA construction in `mitm6/mitm6.py` at `master`; accessed 2026-10-27)
5. D. Mollema (Fox-IT), "mitm6 - compromising IPv4 networks via IPv6", 2018-01-11 - https://blog.fox-it.com/2018/01/11/mitm6-compromising-ipv4-networks-via-ipv6/ (accessed 2026-10-27)
6. RFC 4861, Neighbor Discovery for IPv6, §4.2 (Router Lifetime; 0 = not a default router), §4.6.1 (SLLA), §4.6.2 (Prefix Information) - https://www.rfc-editor.org/rfc/rfc4861 (accessed 2026-10-27)
7. RFC 7113, Implementation Advice for IPv6 RA-Guard (evasion techniques) - https://www.rfc-editor.org/rfc/rfc7113 (accessed 2026-10-27)
8. RFC 3971, SEcure Neighbor Discovery (SEND) - https://www.rfc-editor.org/rfc/rfc3971 (accessed 2026-10-27)
9. MITRE ATT&CK, Adversary-in-the-Middle (T1557) and DHCP Spoofing (T1557.003, blocking DHCPv6/RAs) - https://attack.mitre.org/techniques/T1557/003/ (accessed 2026-10-27)
10. Microsoft Learn, "Configure IPv6 for advanced users" (Windows favors IPv6 over IPv4; disabling not recommended) - https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows (accessed 2026-10-27)

## Verification notes

Verified 2026-10-27 against the working tree (HEAD 0d60387) and by fetching every external source.

- Code: `rule_rogue_ra()` at `src/alerts/rules_wired.c:843` re-read. Collects distinct `src_ip` with `router_lifetime != 0` up to 8, returns below two, selection-sorts, key is `rogue_ra:` + comma-joined sorted IPs, detail lists them, fires CRIT with `match_ip` = `routers[0]`, `match_port` 0 - as stated. Line anchors corrected: collect `:844-853`, lifetime gate `:848`, return `:855`, sort `:858-868`, key `:870-874`, detail `:876-880`, fire `:883-884`; `src/ndp_snoop.c:52-124` for `ndp_snoop_ra()`; `docs/wiki/ipv6-ndp.md` anchors `:43-53` (field table), `:74`/`:76` (key, port), `:78-82` (shape), `:89-91` (shutdown RAs), `:93-99` (suspicious).
- Count semantics: `POLL_MS` is now stated as an upper bound on the wait between ticks (`include/sloth.h:28`, `src/main.c:1666`/`:1671`).
- **Substantive correction - mitm6.** The entry framed mitm6 as "the canonical attack" this rule's CRIT fits and "exactly the mitm6 shape". Reading `mitm6/mitm6.py` ([4]) shows the RA is `ICMPv6ND_RA(M=1, O=1, routerlifetime=0)`, and the Fox-IT write-up ([5]) says in words that mitm6 does not advertise itself as a gateway. The lifetime gate at `:848` therefore excludes mitm6's default RA from this rule's candidate set; it is visible only as an `ndp_ra` row with `router_lifetime` 0 and M/O set. Severity assessment, prevalence, mechanism, evidence and assessment sections rewritten so the entry no longer claims coverage the rule does not have, and the gap (no rule on zero-lifetime M/O RAs or DHCPv6 replies) is stated as a finding.
- Sources: [2] RFC 6104 fetched - names administrator misconfiguration and user devices running Windows ICS / 6to4 as benign causes, and RA-Guard and SEND among mitigations. [3] RFC 6105 title and layer-2 filtering confirmed. [4] mitm6 README confirms DHCPv6 reply setting the attacker as DNS, WPAD and ntlmrelayx use, and the `--no-ra` flag. [5] Fox-IT post confirms the DHCPv6/WPAD/relay chain and the non-gateway statement. [6] RFC 4861 §4.2 wording is "indicates that the router is not a default router and SHOULD NOT appear on the default router list" - the entry's "must not" tightened to the RFC's SHOULD NOT. [7] RFC 7113 confirms extension-header and fragmentation evasions. [8] RFC 3971 is SEND. [9] T1557.003 confirms "block DHCPv6 traffic and incoming router advertisements". [10] Microsoft page: "By default, Windows favors IPv6 global unicast addresses over IPv4 addresses" and "We don't recommend that you disable IPv6". [1] `research/mitre/T1557.md` exists and lists `ALERT_TYPE_ROGUE_RA`.
- Bibliography renumbered 1-10 (it skipped 7); every in-text reference updated.
- Citation hygiene: [1] and [6] were in the bibliography but never cited by number in the body; the T1557 mapping sentence now cites [1] and the lifetime-gate sentence cites [6].
