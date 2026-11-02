---
name: D-Link International
aliases: []
country: SG [1][3]
parent: D-Link Corporation, the Taipei networking company that opened D-Link International Pte. Ltd. in Singapore in 1994 [2][4]
founded: 1994 [4]
kind: network-equipment [2]
device_classes: [ap/router [2][5], switch [2], camera [2]]
found_in: ["D-Link DIR-series Wi-Fi routers [5]", "D-Link DAP-series access points and range extenders [5]", "D-Link DWA-series USB Wi-Fi adapters [5]", "D-Link DNS-series NAS [6]"]
radios: ["Wi-Fi 4 [5]", "Wi-Fi 5 [5]", "2.4 GHz [5]", "5 GHz [5]"]
silicon: ["Realtek RTL8812AU in the DWA-182 rev C1 [5]", "Realtek RTL8814AU in the DWA-192 [5]", "MediaTek MT7610U in the DWA-171 rev B1 [5]", "Broadcom BCM43526 in the DWA-182 rev A1 [5]"]
fcc_grantee: ["KA2 (prefix of the D-Link FCC IDs DeviWiki lists, such as KA2SHG200A1) [5][7]"]
randomization: unknown
security_notes: ["US FTC complaint (2017) over router and IP-camera security, settled in 2019 with biennial third-party assessments [2]", "Authentication-bypass backdoor in DIR-100 revA firmware v1.13 (2013) [2]", "CVE-2024-3273: unauthenticated command injection in end-of-life DNS-320L, DNS-325, DNS-327L and DNS-340L NAS, no fix offered [2][6]", "Ongoing advisories for end-of-life routers left unpatched [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

D-Link International is the Singapore arm of D-Link Corporation; D-Link's own history records the opening of D-Link International Pte. Ltd. in Singapore in 1994 as part of growing beyond Europe, the USA and Greater China [4]. Its LEI record names D-LINK INTERNATIONAL PTE LTD, formerly D-LINK SINGAPORE PTE LTD, at an International Business Park address in Singapore [3]. D-Link Corporation is a Taipei networking-hardware maker founded in 1986 as Datex Systems and, since June 2020, part of the Taiwan Steel Group; it sells routers, gateways, switches, access points, repeaters, wireless adapters, mobile hotspots, NAS and IP cameras [2].

The IEEE registry lists 60 MA-L blocks under "D-Link International", nearly all at The Synergy, Singapore [1]. A MAC in them is most likely a D-Link router, access point, extender, USB adapter or camera. DeviWiki lists D-Link USB adapters on Realtek (RTL8812AU, RTL8814AU), MediaTek (MT7610U) and Broadcom (BCM43526) silicon, routers and extenders rated from N300 to AC5300, and FCC IDs under the KA2 prefix [5]; an FCC ID's first three or five characters are the grantee code [7].

Security history is heavy: the US FTC sued in 2017 over router and camera security and the case settled in 2019, a backdoor was found in DIR-100 firmware in 2013, and in 2024 D-Link declined to patch a NAS flaw because the models were end of life [2]. That flaw, CVE-2024-3273, is an unauthenticated command injection in nas_sharing.cgi [6]. D-Link's advisory portal continues to post end-of-life and end-of-service vulnerability notices [8]. Randomization is not documented.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. D-Link - Wikipedia - https://en.wikipedia.org/wiki/D-Link (accessed 2026-10-27)
3. D-LINK INTERNATIONAL PTE LTD - Bloomberg LEI record - https://lei.bloomberg.com/leis/view/254900ENTYLQJ0BTRN90 (accessed 2026-10-27)
4. History of D-Link - D-Link - https://www.dlink.com/uk/en/about/history-of-d-link (accessed 2026-10-27)
5. D-Link - DeviWiki - https://deviwiki.com/wiki/D-Link (accessed 2026-10-27)
6. CVE-2024-3273 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2024-3273 (accessed 2026-10-27)
7. FCC ID - RadioReference Wiki - https://wiki.radioreference.com/index.php/FCC_ID (accessed 2026-10-27)
8. Global Security Advisories, Responses, and Notices - D-Link - https://supportannouncement.us.dlink.com/security/ (accessed 2026-10-27)
