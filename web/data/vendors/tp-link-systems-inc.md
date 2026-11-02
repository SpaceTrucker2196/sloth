---
name: TP-Link Systems Inc.
aliases: ["TP-Link Systems Inc"]
country: US [1]
parent: "privately held; the US headquarters entity left by the 2022 to May 2024 restructuring of TP-Link, consolidated to a single California headquarters in October 2024 [1]"
founded: 1996 [1]
kind: network-equipment
device_classes: [ap/router, switch, camera, smart-home]
found_in: ["TP-Link Archer consumer routers, e.g. Archer AX23 v1 [5]", "Deco mesh Wi-Fi systems [1]", "Omada business access points, e.g. EAP245 v3 [6]", "Tapo smart-home devices and cameras, Kasa smart plugs/switches, VIGI surveillance cameras, Aginet carrier CPE [4]", "Mercusys-branded networking [1]"]
radios: ["Wi-Fi 4 (802.11n) [5][6][7]", "Wi-Fi 5 (802.11ac) [6][7]", "Wi-Fi 6 (802.11ax) [5]", "2.4 GHz [5][6]", "5 GHz [5][6]"]
silicon: ["MediaTek MT7621A SoC + MT7905DAN Wi-Fi 6 DBDC radio + MT7975DN RF front end in Archer AX23 v1 [5]", "Qualcomm Atheros QCA956X SoC (2.4 GHz integrated) + QCA9980 5 GHz in Omada EAP245 v3 [6]", "Broadcom 1.4 GHz dual-core platform in Archer C5400 v1; Qualcomm in AC2600 Archer routers; Qualcomm Atheros QCA9561 in Archer C28HP [7]"]
fcc_grantee: ["TE7 (FCC ID TE7EAP245V3; the grantee's exact legal name is not stated in the sources) [6][7]"]
randomization: unknown
security_notes: ["CVE-2023-1389: command injection in the country form of the Archer AX21 (AX1800) web management interface before firmware 1.1.4 Build 20230219, CVSS 8.8, published 2023-03-15, added to CISA KEV 2023-05-01 [8]", "Since August 2024 the US House Select Committee on US-China competition, the Commerce, Justice and Defense departments and (from December 2025) the FTC have investigated TP-Link; several US states have sued; the US Department of Defense added the company to its list of Chinese military-linked companies in June 2026 [1]", "May 2024: India's government issued a security alert about vulnerable TP-Link Archer C5400X routers [1]", "October 2026: TP-Link Systems Inc. signed a letter of intent with Key Tronic to assemble routers in the United States [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
TP-Link Systems Inc. is the Irvine, California entity left by the restructuring TP-Link began in 2022 and completed in May 2024, consolidated to a single California headquarters in October 2024; the group itself was founded in Shenzhen in 1996 by brothers Zhao Jianjun and Zhao Jiaxing and remains privately held [1]. Its OUIs are therefore new: 95 MA-L blocks, the first registered 24 September 2020 and the newest in October 2026 [2], most listed to 5 Peters Canyon Rd or 10 Mauchly, Irvine, with a few at Singapore and Hong Kong addresses [3]; older TP-Link hardware carries blocks registered to TP-LINK TECHNOLOGIES CO.,LTD. of Shenzhen instead, so which registrant appears plausibly tracks the unit's production date rather than its product line (inferred, not documented). A MAC in a Systems block is plausibly infrastructure (inferred from the product mix) (an Archer router, a Deco mesh node's BSSID, an Omada AP, a switch), but TP-Link also sells Tapo and Kasa smart-home devices, Tapo/VIGI cameras and Aginet carrier CPE under the same corporate umbrella [4], so a client-side address can be a plug, bulb or camera. Documented silicon spans MediaTek (MT7621A + MT7905DAN/MT7975DN in the Wi-Fi 6 Archer AX23 v1) [5], Qualcomm Atheros (QCA956X + QCA9980 in the Omada EAP245 v3, FCC ID TE7EAP245V3) [6] and Broadcom in the high-end Wi-Fi 5 Archer C5400 [7]; the FCC grantee code TE7 is attested by those FCC IDs [6][7], while the Wi-Fi 6E/7 and 6 GHz products are not covered by the sources reachable here. Security-relevant context an operator should hold: CVE-2023-1389 on the Archer AX21 is a command injection in the web management interface, CVSS 8.8, that has been in CISA's KEV catalog since May 2023 [8], and TP-Link has been under US federal investigation and state lawsuits since 2024, with a June 2026 DoD military-linked listing [1]; the company's own 2026 response includes a US router-assembly agreement with Key Tronic [9]. Nothing in the sources addresses MAC randomization on these products.
## Sources
1. TP-Link - Wikipedia - https://en.wikipedia.org/wiki/TP-Link (accessed 2026-10-27)
2. TP-Link Systems Inc MAC address blocks - maclookup.app - https://maclookup.app/vendors/tp-link-systems-inc (accessed 2026-10-27)
3. IEEE Registration Authority MA-L public listing (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 418; the claims were checked against the copy shipped in sloth web/data/oui.csv)
4. Corporate Profile - TP-Link Systems Inc. - https://www.tp-link.com/us/about-us/corporate-profile/ (accessed 2026-10-27)
5. TP-Link Archer AX23 v1 - OpenWrt Table of Hardware - https://openwrt.org/toh/tp-link/archer_ax23_v1 (accessed 2026-10-27)
6. TP-Link EAP245 v3 - OpenWrt Table of Hardware - https://openwrt.org/toh/tp-link/eap245_v3 (accessed 2026-10-27)
7. TP-LINK - DeviWiki (vendor page, grantee TE7) - https://deviwiki.com/wiki/TP-LINK (accessed 2026-10-27)
8. CVE-2023-1389 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-1389 (accessed 2026-10-27)
9. TP-Link US newsroom (Key Tronic letter of intent, 2026-10-19) - https://www.tp-link.com/us/press/news/ (accessed 2026-10-27)
