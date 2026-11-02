---
name: Zyxel Communications Corporation
aliases: []
country: TW [1][3]
parent: "Zyxel Group Corp. [1]"
founded: 1989 [1]
kind: network-equipment
device_classes: [ap/router, switch]
found_in: ["ISP-issued DSL/fibre gateways, e.g. C1000Z, CenturyLink C3000Z, VMG3925-B10B, VMG4380-B10A, EMG3425-Q10A [4]", "Multy M1 (WSM20) Wi-Fi 6 mesh system [5]", "NBG6617 802.11ac router [6]", "USG / USG Flex / ATP / VPN / ZyWALL firewalls [7]", "5G NR CPE, fibre ONTs, wireless extenders, APs and switches, WiFi 7 NWA30BE AP [8][9]"]
radios: ["Wi-Fi 4 (802.11n) [4]", "Wi-Fi 5 (802.11ac) [4][6]", "Wi-Fi 6 (802.11ax) [5]", "Wi-Fi 7 (NWA30BE) [9]", "2.4 GHz [5][6]", "5 GHz [5][6]", "LTE/5G: 5G NR CPE and fixed wireless access [1][8][9]"]
silicon: ["MediaTek MT7621AT SoC + MT7915 Wi-Fi 6 radio in Multy M1 WSM20 [5]", "Qualcomm IPQ4018 SoC with integrated 2x2 2.4/5 GHz radios + QCA8075 switch in NBG6617 [6]", "Broadcom BCM6368 in VMG4380-B10A, BCM63168 in VMG3925-B10B, BCM63268 in C1000Z [4]", "Qualcomm Atheros platforms in EMG3425-Q10A / EMG2926-Q10A; Realtek in EMG2306-R10A; TrendChip/Ralink in AMG1302/AMG1202 DSL gateways; Sckipio in the XMG5101-S10A G.fast unit; MaxLinear MxL3705 MoCA in WAP7205 [4]"]
fcc_grantee: ["I88 (e.g. FCC IDs I88EMG3425Q10A, I88XMG3563-B10A, I88C3000Z, and I88/NBG6617) [4][6]"]
randomization: unknown
security_notes: ["CVE-2020-29583: undocumented 'zyfwp' account with hardcoded plaintext password granting admin SSH/web access on USG, USG Flex, ATP, VPN and ZyWALL firmware 4.60; CVSS 9.8, published 2020-12-22 [7]", "2025: Zyxel declined to patch two actively exploited zero-days in end-of-life CPE still on sale through Amazon [1]", "2026 advisories: CVE-2026-12489 incorrect authorization in 5G NR CPE, DSL/Ethernet CPE, fibre ONTs and extenders (2026-10-20); CVE-2023-20820 command injection via the Wi-Fi SSID field (2026-10-06); CVE-2026-14818 path traversal in ZLD firewalls (2026-08-04); CVE-2026-6837/8508 command injection and improper authentication in APs, FWA7 and security routers (2026-08-04); CVE-2026-6952 post-auth command injection in CPE, ONTs and extenders (2026-07-21) [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Zyxel was founded in 1989 by Shun-I Chu and is headquartered in Hsinchu Science Park, Taiwan; Zyxel Communications Corporation sits under Zyxel Group Corp., with Zyxel Networks spun off for the enterprise side in 2019 and Keenetic separated in 2017 [1]. It holds 72 MA-L blocks, running from 00:A0:C5 on 22 April 1998 to C8:33:74 on 17 October 2025 [2], listed to No. 6 Innovation Road II, Hsinchu [3]. A MAC in one of these blocks is infrastructure: most often an ISP-issued DSL or fibre gateway (the C1000Z/C3000Z and the VMG/EMG/XMG families are all Zyxel under FCC grantee I88 [4]), a Multy mesh node [5], a retail router [6], an AP or switch, a 5G fixed-wireless CPE or a firewall [7][9]. Documented silicon follows the product generation: Broadcom BCM63xx in the DSL gateways, Qualcomm IPQ4018 in Wi-Fi 5 routers, MediaTek MT7621AT + MT7915 in the Wi-Fi 6 Multy M1, and the current catalogue reaches Wi-Fi 7 with the NWA30BE [4][5][6][9]. The security record is the reason an operator should care which firmware a Zyxel OUI is running: CVE-2020-29583 was a hardcoded admin account across the firewall line [7], the vendor publicly declined in 2025 to patch exploited zero-days in end-of-life CPE [1], and its 2026 advisory feed covers CPE, ONTs, extenders, APs and firewalls [8]. MAC randomization does not apply to this device class and is not documented.
## Sources
1. Zyxel - Wikipedia - https://en.wikipedia.org/wiki/Zyxel (accessed 2026-10-27)
2. Zyxel Communications Corporation MAC address blocks - maclookup.app - https://maclookup.app/vendors/zyxel-communications-corporation (accessed 2026-10-27)
3. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
4. ZyXEL - DeviWiki (vendor page, grantee I88) - https://deviwiki.com/wiki/ZyXEL (accessed 2026-10-27)
5. ZyXEL WSM20 (Multy M1) - OpenWrt Table of Hardware - https://openwrt.org/toh/zyxel/wsm20 (accessed 2026-10-27)
6. ZyXEL NBG6617 - OpenWrt Table of Hardware - https://openwrt.org/toh/zyxel/nbg6617 (accessed 2026-10-27)
7. CVE-2020-29583 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29583 (accessed 2026-10-27)
8. Security Advisories - Zyxel - https://www.zyxel.com/global/en/support/security-advisories (accessed 2026-10-27)
9. About Zyxel - Zyxel - https://www.zyxel.com/global/en/about-zyxel (accessed 2026-10-27)
