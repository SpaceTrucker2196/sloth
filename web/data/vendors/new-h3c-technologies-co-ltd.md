---
name: "New H3C Technologies Co., Ltd"
aliases: ["Hangzhou H3C Technologies Co., Limited"]
country: CN [1]
parent: Unisplendour (UNIS), which bought 51% in 2015 and agreed in 2024 to buy a further 30% from Hewlett Packard Enterprise [3]
founded: unknown
kind: network-equipment [2]
device_classes: [switch [2], ap/router [2][5]]
found_in: ["H3C WA6628 enterprise Wi-Fi 6 access point [5]", "H3C Magic R100, R200 and NX18 Plus home routers [6]", "H3C switches, routers, wireless and UniServer servers [2]"]
radios: ["Wi-Fi 6 [5]", "2.4 GHz [5]", "5 GHz [5]"]
silicon: ["Qualcomm IPQ8078 SoC with Qualcomm QCN5154 (5 GHz, 8x8) and QCN5124 (2.4 GHz, 4x4) radios in the H3C WA6628 [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["H3C Magic R100, R200 and NX18 Plus home routers: dozens of stack overflows in /goform/aspForm and other web handlers (2022), and on the R100 an open UDP service on port 9034 that executes commands (CVE-2022-34598) [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

New H3C Technologies is the networking and computing company behind the H3C brand; its site carries the name in its copyright line and lists switches, routers and wireless under InterConnect and the UniServer servers under Intelligent Computing [2]. H3C began as a 2003 joint venture of Huawei and 3Com, 3Com bought out Huawei's 49% stake in 2007, and Hewlett-Packard completed its acquisition of 3Com in 2010 [4]. Unisplendour (UNIS) bought 51% of H3C in May 2015, and Hewlett Packard Enterprise announced in May 2024 that UNIS would buy a further 30% [3].

The IEEE registry lists 134 MA-L blocks to "New H3C Technologies Co., Ltd" at 466 Changhe Road, Binjiang District, Hangzhou, and 27 to "Hangzhou H3C Technologies Co., Limited", some at the same 466 Changhe Road address and older ones in Beijing and at Liuhe Road, Hangzhou [1]; treating the latter as the same company under its earlier name is inferred from the shared address. A MAC in these blocks is most likely enterprise network equipment, a switch, router or access point, or one of H3C's Magic home routers [2][6]. The WA6628 access point, for example, runs a Qualcomm IPQ8078 with QCN5154 and QCN5124 radios for 802.11ax at 8x8 on 5 GHz and 4x4 on 2.4 GHz [5].

NVD records dozens of 2022 stack overflows in the web handlers of the Magic R100, R200 and NX18 Plus home routers and an open command-execution UDP service on the R100 [6]. Founding year of the current entity, FCC grantee codes and randomization are unknown; the FCC ID databases refused the session's requests.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About Us - New H3C Technologies - https://www.h3c.com/en/About_Us/ (accessed 2026-10-27)
3. Unisplendour - Wikipedia - https://en.wikipedia.org/wiki/Unisplendour (accessed 2026-10-27)
4. H3C (served as the 3Com article) - Wikipedia - https://en.wikipedia.org/wiki/H3C (accessed 2026-10-27)
5. H3C WA6628 - DeviWiki - https://deviwiki.com/wiki/H3C_WA6628 (accessed 2026-10-27)
6. H3C Magic CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=H3C%20Magic (accessed 2026-10-27)
