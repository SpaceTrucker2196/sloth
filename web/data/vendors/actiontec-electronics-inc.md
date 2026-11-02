---
name: "Actiontec Electronics, Inc"
aliases: ["Actiontec Electronics Inc."]
country: US [2]
parent: unknown
founded: unknown
kind: network-equipment
device_classes: [ap/router]
found_in: ["CenturyLink C1000A VDSL2/ADSL2+ gateway [4]", "MI424WR MoCA/coax broadband router (revisions A-I) [5]", "T3200M VDSL2 gateway with MoCA 2.0 [3]", "WXB6X00Q 4x4 802.11ac Ethernet bridge with MoCA [3]", "PK5001A ADSL2+ and Q1000 (Qwest) VDSL2 gateways [3]"]
radios: ["Wi-Fi 4 (802.11bgn) 2.4 GHz 2x2 (C1000A) [4]", "Wi-Fi 5 (802.11ac) 5 GHz 4x4 (WXB6X00Q) [3]", "802.11g (MI424WR) [5]", "MoCA over coax (MI424WR, T3200M, WXB6X00Q) [3][5]"]
silicon: ["Broadcom BCM63168 (2-core 400 MHz, integrated 2x2 bgn) in C1000A, C2000A and T3200M [3][4]", "Broadcom BCM63169 + Quantenna QT3840/QT2518 (5 GHz 4x4 ac) + BCM50210E GbE PHY + BCM6802 MoCA 2.0 in WXB6X00Q [3]", "Broadcom BCM6368 in Q1000 [3]", "Lantiq PSB 50810 in PK5001A [3]", "Intel IXP425 (rev A-D), Cavium 5020 (rev E/F/G), Marvell 1.2 GHz (rev I) in MI424WR, with Entropic MoCA controllers; Ralink rt2500 PCI radio on rev A [5]"]
fcc_grantee: ["LNQ (US; e.g. FCC ID LNQC1000A, LNQT3200M) [3][4]", "QP7 (Taiwan entity) [3]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Actiontec Electronics is a US broadband-CPE vendor at 3301 Olcott St., Santa Clara, California [2], selling gateways, Wi-Fi products, the Optim Cloud management platform and OpenSync/prpl-based software to service providers rather than to retail [6]. The IEEE registry holds 36 prefixes (35 MA-L, one MA-M) for "Actiontec Electronics, Inc" registered from April 1998 (00:20:E0) to February 2026 [1]. A MAC in these blocks is almost always ISP-supplied infrastructure: the C1000A is a CenturyLink VDSL2/ADSL2+ gateway on a Broadcom BCM63168 with 2x2 802.11bgn, OUI 20:76:00, FCC ID LNQC1000A [4]; the MI424WR is the coax/MoCA broadband router that shipped in revisions from Intel IXP425 through Cavium 5020 to a Marvell 1.2 GHz SoC [5]; the WXB6X00Q pairs a BCM63169 with a Quantenna QT3840/QT2518 4x4 802.11ac radio and a BCM6802 MoCA 2.0 chip [3]. DeviWiki records grantee codes LNQ for the US company and QP7 for its Taiwan entity [3]. Documented silicon is Broadcom DSL SoCs throughout the 2010s with one Lantiq (PK5001A) and one Quantenna outlier [3]. No founding year, ownership, vendor security advisories or MAC-randomization behaviour were found on reachable sources (the company's home page carries only a copyright line [6]; its about pages and Wikipedia article returned 404), so those fields are unknown. An operator seeing an Actiontec OUI on a client address rather than a BSSID or gateway should suspect an extender or a MoCA bridge.
## Sources
1. Actiontec Electronics, Inc MAC address blocks - maclookup.app - https://maclookup.app/vendors/actiontec-electronics-inc (accessed 2026-10-27)
2. OUI 20:76:00 registrant record - maclookup.app - https://maclookup.app/macaddress/207600 (accessed 2026-10-27)
3. Actiontec vendor page (grantee codes LNQ/QP7, device table) - DeviWiki - https://deviwiki.com/wiki/Actiontec (accessed 2026-10-27)
4. Actiontec C1000A (CenturyLink) - DeviWiki - https://deviwiki.com/wiki/Actiontec_C1000A (accessed 2026-10-27)
5. Actiontec MI424WR - OpenWrt Table of Hardware - https://openwrt.org/toh/actiontec/mi424wr (accessed 2026-10-27)
6. Actiontec home page - https://www.actiontec.com/ (accessed 2026-10-27)
