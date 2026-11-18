---
name: D-Link Corporation
aliases: []
affiliates: []
country: TW [1][2]
parent: Taiwan Steel Group, which holds 67% and which D-Link joined in June 2020 [1]
founded: 1986 [1][3]
kind: network-equipment [1]
device_classes: [ap/router [1][4], switch [1][3], camera [1]]
found_in: ["D-Link routers, gateways, switches, access points and repeaters, NAS and IP cameras [1]", "D-Link DWA-series USB Wi-Fi adapters [4]", "D-Link Covr AC1300 Wi-Fi range extender (FCC ID KA2AP1655A1) [4]"]
radios: ["Wi-Fi 4/5 [4]", "5 GHz [3]"]
silicon: ["Ralink RT3070 in the DWA-125 rev A1 [4]", "Realtek RTL8812AU in the DWA-182 rev B [4]", "MediaTek MT7610U in the DWA-171 rev B1 [4]", "Realtek RTL8814AU in the DWA-192 rev A1 [4]"]
fcc_grantee: ["KA2 (prefix of the D-Link FCC IDs DeviWiki lists, such as KA2AP1655A1) [4]"]
randomization: unknown
security_notes: ["US FTC lawsuit (January 2017) over router and camera security, settled July 2019 with biennial third-party assessments [1]", "Authentication-bypass backdoor in DIR-100 revA firmware v1.13 (2013) [1]", "CVE-2024-3273: command injection in end-of-life DNS-320L, DNS-325, DNS-327L and DNS-340L NAS, no fix offered [5][1]", "Continuing advisories for end-of-life products, e.g. SAP10521 for all DIR-X4860 revisions (October 2026) [6]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

D-Link Corporation is the Taipei networking-hardware company founded in 1986 as Datex Systems and renamed D-Link in 1992; it joined the Taiwan Steel Group in June 2020, which holds 67% [1][3]. D-Link's own history records that in 1994 it became Taiwan's first networking company to list on the Taiwan Stock Exchange, and that in 2001 it was among the first to release 802.11a 5 GHz wireless LAN products [3]. The IEEE registry lists 27 MA-L blocks to "D-Link Corporation" at Taipei and Hsinchu addresses, separate from the many blocks under its subsidiaries such as D-Link International [2]. It sells routers, DSL and cable gateways, switches, access points, repeaters, NAS and IP cameras [1], so a MAC in one of these blocks is most likely a home or small-office router, extender, camera or USB Wi-Fi adapter.

DeviWiki lists D-Link FCC IDs under the KA2 prefix and documents the silicon in its USB adapters: Ralink RT3070 in the DWA-125 rev A1, Realtek RTL8812AU in the DWA-182 rev B, MediaTek MT7610U in the DWA-171 rev B1 and Realtek RTL8814AU in the AC1900 DWA-192 [4]. Router silicon is not listed by the sources in hand.

D-Link's security history is long: the FTC sued it in January 2017 over router and camera security and settled in July 2019, a backdoor shipped in DIR-100 revA firmware in 2013, and in April 2024 it declined to fix a flaw in four end-of-life NAS models [1], tracked as CVE-2024-3273 [5]. Its advisory page continues to post vulnerabilities in products past end of support [6]. Address randomization is not documented by the sources consulted, and the FCC grantee search was not reachable from this session, so the grantee code rests on DeviWiki.

## Sources
1. D-Link - Wikipedia - https://en.wikipedia.org/wiki/D-Link (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. History of D-Link - D-Link - https://www.dlink.com/uk/en/about/history-of-d-link (accessed 2026-10-27)
4. D-Link - DeviWiki - https://deviwiki.com/wiki/D-Link (accessed 2026-10-27)
5. CVE-2024-3273 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2024-3273 (accessed 2026-10-27)
6. Global Security Advisories, Responses, and Notices - D-Link - https://supportannouncement.us.dlink.com/security/ (accessed 2026-10-27)
