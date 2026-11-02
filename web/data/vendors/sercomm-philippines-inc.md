---
name: SERCOMM PHILIPPINES INC
aliases: []
country: PH [4]
parent: "Sercomm Corporation, Taiwan (TWSE: 5388), founded 1992 [1][2]"
founded: unknown
kind: odm/ems
device_classes: [ap/router, smart-home, camera, module-in-other-brands]
found_in: ["ISP broadband gateways and Wi-Fi routers built for operators: Vodafone Station 2 (SHG1500), Vodafone H-500-s, Reliance JioFiber JCOW414, A1 Smart Home Gateway (NA502) [6][7][8]", "Retail-brand routers built by Sercomm: Netgear D6200, Linksys EA7300, Cisco RV120W, Arris RAC2V1A for Charter/Spectrum-class carriers [5]", "Sercomm's own catalogue: DOCSIS/fibre/DSL/FWA CPE, mesh repeaters, IoT sensors and cameras, small cells, enterprise APs [1][10]"]
radios: ["Wi-Fi 4 (802.11n) [5][6][7]", "Wi-Fi 5 (802.11ac) [5][6][7]", "2.4 GHz [5][6]", "5 GHz [5][6]", "Zigbee (802.15.4) and Z-Wave in the NA502 IoT gateway [7]", "LTE/5G: 4G/5G CPE, FWA and small cells in the product catalogue [1][10]"]
silicon: ["Broadcom BCM6361U SoC + BCM4352 5 GHz in Netgear D6200v1 [5]", "MediaTek MT7621A SoC + MT7615N 4x4 radios in Linksys EA7300 v1 [5]", "Qualcomm IPQ8065 SoC + QCA9983/QCA9984 in Arris RAC2V1A [5]", "Broadcom BCM63167 SoC + Quantenna QT3740BC 5 GHz in Vodafone H-500-s [6]", "MediaTek MT7621 + Zigbee and Z-Wave serial modules in Sercomm NA502 [7]", "Cavium CN5010 + Broadcom BCM4322 in Cisco RV120W [5]"]
fcc_grantee: ["P27 (parent Sercomm Corporation; the Philippine entity's own code, if any, not documented) [5]"]
randomization: unknown
security_notes: ["TCP/32764 undocumented management backdoor found December 2013 / January 2014 in Sercomm-built firmware shipped by Linksys (WAG/WRT series), Netgear (DG834, DGN2000/3500, DGND3300 and others), Cisco (RVS4000, WAP4410N, WRVS4400N), Diamond and LevelOne [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Sercomm Philippines Inc is the Philippine manufacturing entity of Sercomm Corporation, a Taiwanese ODM founded in 1992 and listed on the Taiwan Stock Exchange as 5388 [1][2]; its blocks are registered to Lots 1 & 5, Filinvest Technology Park 1, Calamba City, Laguna [4]. Sercomm's own milestone timeline lists Philippines operations as launched in 2023 alongside a new Mexico plant [2], while the Philippine entity's first MA-L (14:7D:05) dates from 23 December 2020 [3]; the two are reported here as found, not reconciled. The entity now holds 8 MA-L and 2 MA-M blocks (about 136 million addresses), with new registrations in March, May and July 2026 [3], so these OUIs will appear on recent production. Sercomm builds for service providers rather than selling under its own name: broadband gateways, mesh repeaters, DOCSIS/fibre/DSL/FWA CPE, IoT hubs, cameras and small cells [1][10], and the DeviWiki record under the parent's FCC grantee code P27 runs to 302 devices for Netgear, Linksys, Cisco, Belkin, TRENDnet and Arris [5]. A MAC in one of these blocks is therefore most likely an ISP-issued gateway or extender, or an operator-branded IoT hub, and the label on the box will say Vodafone, Jio, A1, Spectrum or similar rather than Sercomm [5][6][7][8]. Documented silicon across Sercomm-built units spans Broadcom, MediaTek, Qualcomm and Quantenna [5][6]; note that those specific units predate the Philippine blocks and were built under the parent's OUIs, so they document the vendor's chipset habits, not the exact contents of a Philippines-OUI device. The security history that matters is the 2013/2014 TCP/32764 backdoor in Sercomm-built firmware across several brands [9], the canonical example of an OUI identifying the builder rather than the brand that owns the firmware. MAC randomization does not apply to this class of device and is not documented.
## Sources
1. Company - Sercomm Corporation - https://www.sercomm.com/en/company (accessed 2026-10-27)
2. Milestones - Sercomm Corporation - https://www.sercomm.com/en/company/4 (accessed 2026-10-27)
3. SERCOMM PHILIPPINES INC MAC address blocks - maclookup.app - https://maclookup.app/vendors/sercomm-philippines-inc (accessed 2026-10-27)
4. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
5. SerComm - DeviWiki (manufacturer page, grantee P27) - https://deviwiki.com/wiki/SerComm (accessed 2026-10-27)
6. Sercomm H500-s (Vodafone H-500-s) - OpenWrt Table of Hardware - https://openwrt.org/toh/sercomm/h500-s (accessed 2026-10-27)
7. Sercomm NA502 - OpenWrt Table of Hardware - https://openwrt.org/toh/sercomm/na502 (accessed 2026-10-27)
8. Sercomm device index - OpenWrt Table of Hardware - https://openwrt.org/toh/sercomm/start (accessed 2026-10-27)
9. TCP-32764 backdoor write-up - elvanderb on GitHub - https://github.com/elvanderb/TCP-32764 (accessed 2026-10-27)
10. Sercomm Corporation home page (product categories) - https://www.sercomm.com/ (accessed 2026-10-27)
