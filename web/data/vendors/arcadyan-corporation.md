---
name: Arcadyan Corporation
aliases: []
affiliates: []
country: TW [1][2]
parent: Compal Group [1]
founded: unknown
kind: odm/ems
device_classes: [ap/router, module-in-other-brands]
found_in: ["Orange / Jazztel Livebox Next (VRV9510KWAC23) [6]", "Orange Livebox 2.1 (ARV7519RW22-A-LT) [5]", "o2 Box 6431 (VGV7510KW22) and o2 Box 4421 / Alice IAD 4421 (ARV7506PW11) [5][7]", "Vodafone EasyBox 903 (VRV752DHW22), EasyBox 904 LTE, Vodafone ARV4519PW [5]", "Vodafone R101 (WG7012E22) [8]", "EE Brightbox 1 (AR7516) and Brightbox 2 (VR9517NAC22) [5]", "Pirelli/ADB P.RG A4201G (ARV4518PW2) [5]", "ASUS, Belkin and Linksys consumer routers manufactured by Arcadyan [8]", "ISP CPE named in the CVE-2021-20090 advisory: Buffalo, Verizon, Telstra, Vodafone, Deutsche Telekom, O2, Orange, KPN, Hughesnet, Telus, Beeline, British Telecom, Skinny, Spark, Telmex, ASUS, ADB, ASMAX [3]"]
radios: ["Wi-Fi 4 (802.11 b/g/n) 2.4 GHz [6][7]", "Wi-Fi 5 (802.11ac) 5 GHz [6]", "LTE/5G (5G CPE and EasyBox 904 LTE) [1][5]", "DOCSIS, FTTx and xDSL WAN (not Wi-Fi radios) [1][6][7]"]
silicon: ["Lantiq VRX288 SoC + Lantiq VRX208 VDSL/ADSL2+ in VRV9510KWAC23 and VGV7510KW22 [6][7]", "Broadcom BCM43222 (2.4 GHz b/g/n 2x2) + Broadcom BCM4360 (5 GHz ac 3x3) in VRV9510KWAC23 [6]", "Ralink/MediaTek RT3062F (2.4 GHz b/g/n) in VGV7510KW22 [7]", "Lantiq PSB 80910 + Ralink RT3883F / RT5392L in WG7012E22 (Vodafone R101) [8]", "Broadcom BCM43xx, Quantenna QT3840BC, Qualcomm Atheros radios and Realtek RTL8367RB / Broadcom BCM53xx switches across Arcadyan-built ASUS/Belkin/Linksys products [8]"]
fcc_grantee: ["RAX (e.g. FCC ID RAXAR7516VW, RAXWA9102BAC33) [8]"]
randomization: unknown
security_notes: ["CVE-2021-20090: unauthenticated path traversal (..%2f) in the web UI of Arcadyan-made routers sold by at least 18 ISPs/brands; NVD CVSS 3.1 9.8 Critical, published 2021-04-29, added to CISA KEV 2021-11-03 [3][4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Arcadyan is a Hsinchu, Taiwan ODM in the Compal Group that builds broadband CPE - DOCSIS, FTTx and xDSL gateways, 5G CPE, Wi-Fi routers and IPTV set-top boxes - for operators, plus automotive products [1]. It holds 89 IEEE MA-L blocks at its Hsinchu address (No. 8, Sec. 2, Guangfu Rd.) [2]. A MAC in these blocks is almost always an ISP-branded home gateway or router: OpenWrt and DeviWiki document Arcadyan hardware shipped as Orange Livebox, o2 Box, Vodafone EasyBox and R101, EE Brightbox and Pirelli/ADB units [5][6][7][8], and Arcadyan also manufactures consumer routers for ASUS, Belkin and Linksys [8]. Documented silicon is Lantiq DSL SoCs with Broadcom, Ralink/MediaTek, Qualcomm Atheros or Quantenna radios [6][7][8]; the 5 GHz 802.11ac radio in the Livebox Next is a Broadcom BCM4360 [6]. On the air expect an access point rather than a client, dual-band on the newer units, and LTE/5G backhaul on the FWA models [1][5]. Arcadyan's FCC grantee code is RAX [8]. The security-relevant history is CVE-2021-20090, a path-traversal authentication bypass in Arcadyan firmware found across Buffalo, Verizon, Telstra, Vodafone, Deutsche Telekom, O2, Orange, KPN and other operator CPE, rated 9.8 and listed in CISA's Known Exploited Vulnerabilities catalogue [3][4]. The founding year could not be confirmed from a fetchable primary source in this session.
## Sources
1. Arcadyan Technology Corporation - company site - https://www.arcadyan.com/ (accessed 2026-10-27)
2. IEEE MA-L (OUI) public listing (checked against the local export web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.txt (accessed 2026-10-27)
3. TRA-2021-13: Arcadyan-based routers and modems path traversal - Tenable Research - https://www.tenable.com/security/research/tra-2021-13 (accessed 2026-10-27)
4. CVE-2021-20090 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-20090 (accessed 2026-10-27)
5. Arcadyan - OpenWrt Table of Hardware - https://openwrt.org/toh/arcadyan/start (accessed 2026-10-27)
6. Arcadyan VRV9510KWAC23 (Livebox Next) - OpenWrt Wiki - https://openwrt.org/toh/arcadyan/vrv9510kwac23 (accessed 2026-10-27)
7. Arcadyan VGV7510KW22 (o2 Box 6431) - OpenWrt Wiki - https://openwrt.org/toh/arcadyan/vgv7510kw22 (accessed 2026-10-27)
8. Arcadyan - DeviWiki - https://deviwiki.com/wiki/Arcadyan (accessed 2026-10-27)
