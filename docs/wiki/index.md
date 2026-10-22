# Wiki index

Table of contents for the sloth wiki. Pages are concept-oriented; raw
per-view documentation lives in `../views/` and is treated as immutable
source material.

**This wiki is the complete information source for sloth.** It is
mirrored to the [GitHub wiki](https://github.com/SpaceTrucker2196/sloth/wiki)
automatically — `docs/wiki/` is the source of truth, the GitHub wiki is a
render of it (see [[wiki-maintenance]]). Edit here, never there.

## Read this first — the complete reference

The eight pages that make this a from-scratch reference to sloth and to
the Wi-Fi it watches:

- [[what-sloth-does]] — the whole tool on one screen: surfaces, views, alerts, outputs, and the line it never crosses.
- [[how-wifi-works]] — 802.11 from the radio up: bands, frames, the join sequence, security generations, roaming, MAC randomisation.
- [[monitor-mode]] — the capability that unlocks the Wi-Fi frame classes, what it gathers, its limits.
- [[where-exploits-happen]] — the 802.11 attack surface mapped to the join sequence and to each detector.
- [[wifi-sigint-techniques]] — common passive Wi-Fi SIGINT techniques, defender-side.
- [[wifi-sigint-guide]] — for the non-specialist: the radio cloud around a person — routers, phones (every iOS and Android radio emission), cars, body cameras, plate readers, Bluetooth — what a listener can infer, and the limits.
- [[cli-reference]] — every flag, argument, keybinding, env var and exit code.
- [[wifi-state-of-the-art]] — living overview of Wi-Fi tech and security research (Wi-Fi 7 / 8).

## Start here

- [[sloth]] — what sloth is, what it explicitly never does.
- [[architecture]] — code-tree layout and the seams between layers.
- [[threat-model]] — assets A1–A5, adversaries ADV-1..4, trust
  boundaries TB-1..7, and the finding → boundary map every security
  issue cites by ID.
- [[views-catalog]] — keybinding-to-view map for all <!-- count:views -->36<!-- /count --> views.
- [[dashboard]] — the seven-band composite view.

## Engines

- [[alerts]] — alert engine internals and the <!-- count:rules -->90<!-- /count --> rules.
- [[beacon-detection]] — periodicity detector for C2 / implants.
- [[threat-intel]] — embedded IOC matcher (synthetic demo data, not a feed).
- [[retention]] — what `--db` actually deletes, and what nothing deletes.
- [[inventory]] — the approved-inventory trust anchor (#89): the only
  evil-twin trust input that does not arrive over the air, its JSON
  format, how it merges with `--my-ssid`/`--my-bssid`, and why `site`
  is configuration-only.
- [[ja3-fingerprinting]] — TLS ClientHello fingerprinting.
- [[camera-detection]] — passive IP-camera recognition (#106): the
  camera rules, their cited sources, and the device-record join behind
  the `CAMERA` row on `[g]` Devices — joined on IP or MAC only, never a
  setup SoftAP to a LAN IP; no default-credential matching.

## WiFi SIGINT

- [[wifi-sigint]] — overview of the v1.1 SIGINT view set.
- [[wifi-sigint-guide]] — plain-language guide to passive RF inference and its limits, with every radio emission of a current iPhone and Android phone (sourced, 117 references).
- [[non-ip-sensors]] — passive RF / non-IP sensor-family roadmap (#26).
- [[ble]] — the Bluetooth host source: `--bt-monitor` over the HCI monitor channel, the passive-scan procedure, what is refused and never written (#144).
- [[ubertooth]] — the over-the-air Bluetooth source: `--bt-capture` reading an Ubertooth's pcap file or FIFO, the allowed and forbidden tools and flags, jam mode and DISABLE_TX firmware (#144 slice 3).
- [[mac-randomisation]] — the 802.11 seqnum deanonymisation primitive.
- [[evil-twin-reproducer]] — scapy snippets for live-testing each
  evil-twin detection layer (Phases 1-4).
- [[btm-abuse]] — 802.11v BSS-Transition forcing + `BTM_ABUSE` alert
- [[action-frames]] — the MFP-era attack surface (#76): why an SA-Query
  storm is the *symptom* of a spoofed-disassoc flood rather than an
  attack in itself, and why "robust category" is an exclusion list
  (#59): the forced roam that leaves no deauth frame behind.
- [[regulatory-table]] — the compiled-in 5 GHz channel table (#101):
  FCC 47 CFR 15.407 and ETSI EN 301 893 rows, cited, dated and heuristic;
  what `DFS_MASKING` reads its DFS set from.
- [[research-corpus]] — the machine-readable side of the cite-sources
  habit (#73): one document per source, FTS5-indexed, guarded.
- [[captive-portal]] — connectivity-check interception (#69): the
  rogue portal that answers your OS's probe, and the three
  independent signals that catch it.
- [[fragattacks]] — the Vanhoef 2021 family (#75): eight of the twelve
  CVEs shipped across seven detectors, why the A-MSDU detector as
  usually described cannot work, why the gate is per-station and
  ordered, and the `[c] FragAttacks` view (slice 5) that surfaces them
- [[tool-fingerprints]] — naming the attacker's tool from passive
  beacon characteristics (#68). Ships with an **empty** signature
  table, and explains why that is the honest state.
- [[attack-hardware-fingerprints]] — #77's stack measurements (IE-order
  hash, TBTT jitter, WPS/WSC vendor strings) and their zero-reading
  rules on `[b]`; plus the capture-gated remainder, written up ready to
  refile.
- [[enterprise-rogue]] — the two halves of the WPA-Enterprise problem:
  `ROGUE_RADIUS` (#31, the AP) and `PEAP_NO_SERVER_CERT` (#65,
  CVE-2023-52160, your own fleet).
- [[ipv6-ndp]] — Router Advertisement tracker + `ROGUE_RA` alert
  (mitm6 / Slaacers detection).
- [[smb-snoop]] — SMB1 detection + `SMB1_USE` alert (EternalBlue /
  lateral-movement substrate).
- [[kerberos-snoop]] — Kerberos msg-type tracking + `KERB_PREAUTH_BURST`
  alert (AD password-spray detection).
- [[ldap-snoop]] — LDAP bind / search tracking + `LDAP_SEARCH_FLOOD`
  alert (BloodHound / ldapdomaindump detection).
- [[bgp-snoop]] — BGP session tracking + `BGP_NOTIFICATION_BURST`
  alert (peering instability / hijack-precursor detection).
- [[ssh-snoop]] — SSH banner-exchange counting + `SSH_BRUTE_FORCE`
  alert (hydra / medusa / ncrack detection).
- [[rdp-snoop]] — RDP X.224 CR counting + mstshash cookie
  extraction + `RDP_BRUTE_FORCE` alert (xfreerdp-loop / NLBrute /
  Crowbar detection).
- [[snmp-snoop]] — SNMP v1/v2c BER parsing + community-string
  tracking + `SNMP_COMMUNITY_BRUTE` alert (snmpwalk wordlist /
  metasploit snmp_login detection).
- [[mqtt-snoop]] — MQTT v3/v4/v5 CONNECT + CONNACK-fail counting
  with username extraction + `MQTT_BROKER_BRUTE` alert
  (IoT-broker brute / Mirai-class scanner detection).

## UI and infrastructure

- [[ip-palette]] — colour conventions and TUI rules.
- [[platform-vtable]] — the kernel seam (`platform_ops_t`).
- [[compiler-coverage]] — the one compiler / architecture CI builds on,
  and the alignment, byte-order and integer-width assumptions the
  parsers and platform code make.
- [[version-checkin]] — periodic release checks and the safe boundary
  between version awareness and self-update.
- [[manifest-format]] — JSON schema `--check-manifest FILE` reads.
- [[release-checklist]] — cutting a release: floors, SBOM,
  `SHA256SUMS`, the manual signed tag, and what is still pending.
- [[pcap-export]] — per-alert, manual, and per-EAPOL-handshake pcap.
- [[posture-report]] — the on-exit sign-off document (`--report`,
  `--report-json`).
- [[jsonl-schema]] — wire format for `-o FILE` and `--data-socket SPEC`.
- [[data-socket-exposure]] — who can read the data socket, the
  `unix:` trust boundary, the remote-bind guard, and the three
  supported ways to reach it from another host.
- [[slothweb]] — the browser dashboard's separate server under `web/`
  (#102): W0 (#157) is the loopback-default bind and the allowed-peer
  list refused at accept(); M0 (#158) the page, `/api/health` and the
  `/events` stream; M1 (#159) the data-socket client, `/api/live` and
  the Overview.
- [[deployment]] — `make install` + `make install-service` (#139): the
  shipped hardened unit, why it runs as `sloth` and not root, what each
  sandbox key costs, and the migration off a build-tree unit.
- [[sqlite-schema]] — the `--db` retained artifact: 38-table schema,
  retention tiers, MISSION §2 guardrails, query recipes.
- [[ring-buffers]] — bounded-history pattern shared by every per-protocol log file.

## Factory infrastructure

- [[mutation-testing]] — verifying the test suite itself; `make mutate` harness.
- [[replay-integration]] — `--replay`/`--ticks` and `make replay-check`: the CI gate that executes the shipped binary.
- [[docs-drift-judge]] — LLM-as-judge GitHub Action that audits
  per-view docs against their source files.

## Reference

- [[attack-map]] — threat class → entry-point view.
- [[cli-reference]] — the authoritative flag / keybinding / exit-code list.
- [personas/](../personas/README.md) — operator personas and their
  scenario suites; the inspection step for operator experience, the way
  `make test` is the inspection step for correctness.
  - [wifi-surveyor](../personas/wifi-surveyor.md) — RF site surveys and
    surveillance detection. Scored 2026-07-28.

## Source material

Raw source documents (treat as immutable):

- `../views/*.md` — per-view deep dives (24 files).
- `../views/README.md` — index of per-view docs.
- `../../CLAUDE.md` — project conventions and discipline rules.

## Maintenance

- [[wiki-maintenance]] — how the wiki is kept complete and synced to
  GitHub, and the standing duty on every agent that touches sloth.
- [log.md](log.md) — append-only record of wiki operations.
- All page names are lowercase with hyphens (e.g. `mac-randomisation.md`).
- Cross-link with `[[page-name]]` wherever a concept is referenced.
