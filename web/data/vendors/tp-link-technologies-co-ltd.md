---
name: "TP-LINK TECHNOLOGIES CO.,LTD."
aliases: []
country: CN [1]
parent: "privately held; from 2022 to May 2024 split into China-based TP-LINK Technologies Co., Ltd. (Shenzhen) and TP-Link Systems Inc. (Irvine, California) for international operations [1]"
founded: 1996 [1]
kind: network-equipment
device_classes: [ap/router, switch, camera, smart-home, iot-sensor]
found_in: ["TP-Link Archer routers, e.g. Archer AX50 [3] and Archer C7 [4]", "Deco mesh Wi-Fi [1]", "Tapo and Kasa smart-home devices and cameras [1][2]", "Omada business networking [2]", "VIGI surveillance cameras [2]", "Aginet carrier networking [2]", "Mercusys budget networking [1]"]
radios: ["Wi-Fi 4/5 (802.11a/b/g/n/ac), Archer C7 [4]", "Wi-Fi 6 (802.11ax), Archer AX50 [3]", "Wi-Fi 7 (vendor claims to be among the earliest to market with Wi-Fi 7 certified products) [2]", "2.4 GHz [3][4]", "5 GHz [3][4]"]
silicon: ["Intel (Lantiq) GRX350 SoC + WAV654 radios in Archer AX50 [3]", "Qualcomm Atheros QCA9558 SoC/2.4 GHz + QCA9880 5 GHz in Archer C7 v1 [4]"]
fcc_grantee: ["TE7 (e.g. FCC ID TE7AX50, TE7C7) [3][4][5]"]
randomization: unknown
security_notes: ["Quad7 / CovertNetwork-1658 botnet of compromised TP-Link SOHO routers (TL-WR841N, Archer C7 and others) used for Microsoft 365 password spraying; vendor advisory cites CVE-2023-50224 (unauthenticated credential file disclosure) and CVE-2025-9377 (Parental Control command injection, RCE) [7]", "US investigations by the Commerce, Justice and Defense departments and, from December 2025, the FTC; Texas banned TP-Link products from state devices in January 2026; added to the US DoD list of Chinese military-linked companies June 2026 [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
TP-Link was founded in Shenzhen in 1996 by brothers Zhao Jianjun and Zhao Jiaxing and calls itself the number-one Wi-Fi product provider, claiming 1.7 billion users in 170+ countries [1][2]; from 2022 to May 2024 it split into a China entity (TP-LINK Technologies Co., Ltd., the IEEE registrant here) and TP-Link Systems Inc. in Irvine, California for international business, consolidated to a single California headquarters in October 2024 [1]. It holds 174 MA-L blocks [6], and a MAC in one of them is plausibly infrastructure - an Archer or Deco router/AP, Omada or Mercusys networking, or Aginet carrier equipment - or a Tapo/Kasa/VIGI smart-home device or camera, an inference from the product lines [1][2]. Documented silicon spans Intel/Lantiq (GRX350 + WAV654, Archer AX50, Wi-Fi 6 [3]) and Qualcomm Atheros (QCA9558 + QCA9880, Archer C7, Wi-Fi 5 [4]); the brand's FCC grantee code is TE7 [5], visible in IDs such as TE7AX50 [3]. The vendor states it was among the earliest to market with Wi-Fi 7 certified products [2]. Security context is substantial: TP-Link's own advisory documents the Quad7 botnet abusing older SOHO routers via CVE-2023-50224 and CVE-2025-9377 for credential spraying against Microsoft 365 [7], and in the US the company has been under Commerce, Justice and Defense investigation, joined by the FTC in December 2025, was banned from Texas state devices in January 2026 and listed as a Chinese military-linked company by the DoD in June 2026 [1]. For an operator, a TP-Link OUI on an unexpected AP, or an Archer/TL-WR model on old firmware, is worth a firmware check regardless of the policy debate. No vendor statement on MAC randomization for its client-side products (adapters, cameras) was found, so that field is unknown.
## Sources
1. TP-Link - Wikipedia - https://en.wikipedia.org/wiki/TP-Link (accessed 2026-10-27)
2. Corporate Profile - TP-Link - https://www.tp-link.com/us/about-us/corporate-profile/ (accessed 2026-10-27)
3. TP-LINK Archer AX50 - DeviWiki - https://deviwiki.com/wiki/TP-LINK_Archer_AX50 (accessed 2026-10-27)
4. TP-LINK Archer C7 - DeviWiki - https://deviwiki.com/wiki/TP-LINK_Archer_C7 (accessed 2026-10-27)
5. TP-LINK - DeviWiki (vendor page, FCC grantee TE7) - https://deviwiki.com/wiki/TP-LINK (accessed 2026-10-27)
6. TP-LINK TECHNOLOGIES CO.,LTD. MAC address blocks - maclookup.app - https://maclookup.app/vendors/tp-link-technologies-co-ltd (accessed 2026-10-27)
7. Technical News and Reports about Quad 7 (7777) Botnet aka CovertNetwork-1658 - TP-Link Support - https://www.tp-link.com/us/support/faq/4365/ (accessed 2026-10-27)
