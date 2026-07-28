# Wiki index

Table of contents for the sloth wiki. Pages are concept-oriented; raw
per-view documentation lives in `../views/` and is treated as immutable
source material.

## Start here

- [[sloth]] — what sloth is, what it explicitly never does.
- [[architecture]] — code-tree layout and the seams between layers.
- [[views-catalog]] — keybinding-to-view map for all 24 views.
- [[dashboard]] — the seven-band composite view.

## Engines

- [[alerts]] — alert engine internals and the six rules.
- [[beacon-detection]] — periodicity detector for C2 / implants.
- [[threat-intel]] — embedded IOC matcher.
- [[ja3-fingerprinting]] — TLS ClientHello fingerprinting.

## WiFi SIGINT

- [[wifi-sigint]] — overview of the v1.1 SIGINT view set.
- [[non-ip-sensors]] — passive RF / non-IP sensor-family roadmap (#26).
- [[mac-randomisation]] — the 802.11 seqnum deanonymisation primitive.
- [[evil-twin-reproducer]] — scapy snippets for live-testing each
  evil-twin detection layer (Phases 1-4).
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
- [[version-checkin]] — periodic release checks and the safe boundary
  between version awareness and self-update.
- [[manifest-format]] — JSON schema `--check-manifest FILE` reads.
- [[pcap-export]] — per-alert, manual, and per-EAPOL-handshake pcap.
- [[jsonl-schema]] — wire format for `-o FILE` and `--data-socket SPEC`.
- [[sqlite-schema]] — the `--db` retained artifact: 38-table schema,
  retention tiers, MISSION §2 guardrails, query recipes.
- [[ring-buffers]] — bounded-history pattern shared by every per-protocol log file.

## Factory infrastructure

- [[mutation-testing]] — verifying the test suite itself; `make mutate` harness.
- [[docs-drift-judge]] — LLM-as-judge GitHub Action that audits
  per-view docs against their source files.

## Reference

- [[attack-map]] — threat class → entry-point view.
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

- [log.md](log.md) — append-only record of wiki operations.
- All page names are lowercase with hyphens (e.g. `mac-randomisation.md`).
- Cross-link with `[[page-name]]` wherever a concept is referenced.
