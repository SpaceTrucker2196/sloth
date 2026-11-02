---
name: Alpha Networks Inc.
aliases: []
affiliates: []
country: TW [1][2]
parent: unknown
founded: 2003 [2]
kind: odm/ems [3][4]
device_classes: [ap/router [3][4], switch [3], camera [3][4], module-in-other-brands [4]]
found_in: ["D-Link routers and access points such as DIR-860L, DIR-890L and DAP-2660 [4]", "Western Digital My Net N600, N750 and N900 routers [4]", "TRENDnet TEW-750DAP and TEW-752DRU [4]", "Enterasys WS-AP3705i access point [4]", "Samsung CY-SWR1100 and Sony VGP-WAR100 [4]"]
radios: ["Wi-Fi 4 [4]", "Wi-Fi 5 [4]", "2.4 GHz [4]", "5 GHz [4]"]
silicon: ["Broadcom BCM4709A0 with BCM43602 in D-Link DIR-890L [4]", "Broadcom BCM47081A0 with BCM4352 in D-Link DIR-860L rev A1 [4]", "MediaTek MT7621AT with MT7612E in D-Link DIR-860L rev B1 [4]", "Qualcomm Atheros QCA9558 with QCA9557 and QCA9882 in D-Link DAP-2660 [4]", "Qualcomm IPQ4018 in D-Link DAP-2610 [4]", "Atheros AR9344 in Western Digital My Net N750 [4]", "MediaTek MT7620A in TRENDnet TEW-750DAP [4]"]
fcc_grantee: ["RRK [4]"]
randomization: unknown
security_notes: ["CVE-2013-6026 web interface authentication bypass via a hardcoded User-Agent in D-Link, Planex and Alpha Networks routers [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Alpha Networks is a Taiwanese networking design and manufacturing company split off from D-Link around 2003 [4]; its milestones record the August 2003 split with NT$2 billion of capital, the December 2004 stock listing, Wistron taking a 5.63 percent stake in 2007 and Qisda brought in as a strategic investor by private placement in 2018 [2]. The IEEE registry lists 9 MA-L blocks under Alpha Networks Inc. at a Hsinchu Science Park address [1]. Its site describes it as a DMS networking maker with data-centre, campus, carrier-access and industrial Ethernet lines, mobile and fixed broadband and wireless networking, and video doorbell, surveillance and radar products [3].

A MAC in an Alpha block is usually a device sold under another brand. DeviWiki, which calls Alpha the former manufacturing arm of D-Link and tags over 300 devices as its manufacture, gives its FCC grantee code as RRK while the D-Link units it lists carry D-Link's own KA2 FCC IDs, such as KA2AP2660A1 for the DAP-2660 [4]. The documented products span D-Link DIR and DAP routers and access points, Western Digital My Net routers, TRENDnet, Enterasys, Samsung and Sony devices, on Broadcom, MediaTek, Ralink, Realtek, Atheros and Qualcomm silicon with 802.11n and 802.11ac radios [4]. NVD lists CVE-2013-6026, a hardcoded User-Agent authentication bypass shared by D-Link, Planex and Alpha Networks router firmware [5].

The parent field is left unknown because no fetched source states a controlling owner, randomisation is unknown, the FCC databases refused the session, and nothing is filled in from memory.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Alpha Networks milestones - https://www.alphanetworks.com/about/38fcfa2bfeac3e0d (accessed 2026-10-27)
3. Alpha Networks home page - https://www.alphanetworks.com/ (accessed 2026-10-27)
4. Alpha Networks - DeviWiki - https://deviwiki.com/wiki/Alpha_Networks (accessed 2026-10-27)
5. NVD CVE API keyword search Alpha Networks - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Alpha%20Networks&keywordExactMatch&resultsPerPage=30 (accessed 2026-10-27)
