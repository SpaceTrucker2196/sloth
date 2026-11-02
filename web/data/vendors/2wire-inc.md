---
name: 2Wire Inc
aliases: []
affiliates: []
country: US [1][2]
parent: Pace plc, which agreed to buy 2Wire in 2010; Arris is named as successor [1]
founded: 1998 [1]
kind: network-equipment [1]
device_classes: [ap/router [1][3]]
found_in: ["2Wire HomePortal residential gateways distributed by AT&T, Embarq, Windstream and Qwest [1]", "2Wire 2700HG-B, 2701HG-B, 3600HGV, 3800HGV-B and 3801HGV DSL gateways [3]", "2Wire MediaPortal TV, DVR and broadband platform [1]"]
radios: ["802.11b/g (2701HG-B) [4]"]
silicon: ["2Wire Ares SoC with an Atheros AR2413A Wi-Fi chip in the 2701HG-B [4]", "Atheros AR2413A in the 3600HGV, 3800HGV-B and 3801HGV [3]", "Texas Instruments ACX100 in the HomePortal 1000HW and 1000SW [3]"]
fcc_grantee: ["PGR, the prefix of FCC IDs such as PGR2W2701 and PGR2W3800 [3][4]"]
randomization: unknown
security_notes: ["CVE-2007-4389: CSRF in /xslt on 2Wire 1701HG, 1800HW and 2071 gateways lets a remote attacker create DNS mappings and poison DNS [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

2Wire was a San Jose, California maker of broadband residential gateways active from 1998 to 2010, when Pace plc agreed to buy it for 475 million US dollars; Arris is named as its successor [1]. Its HomePortal gateways covered ADSL2+ to fiber and were distributed by providers including AT&T, Embarq, Windstream and Qwest, and its MediaPortal combined TV, DVR and broadband [1]. The IEEE registry lists 34 MA-L blocks to "2Wire Inc" at Automation Parkway, San Jose [2].

A MAC in these blocks is most likely an ISP-supplied DSL gateway, and the 3800HGV-B and 3801HGV are also analog phone gateways [1][3]. The 2701HG-B (FCC ID PGR2W2701) runs a 2Wire Ares SoC with an Atheros AR2413A 802.11b/g radio, and the 3600HGV, 3800HGV-B and 3801HGV use the same Atheros AR2413A [3][4]. 2Wire gateway FCC IDs start with PGR [3][4].

CVE-2007-4389 is a cross-site request forgery flaw in the /xslt handler of the 1701HG, 1800HW and 2071 gateways that lets a remote attacker create DNS mappings and poison DNS [5]. Randomization behaviour is not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources
1. 2Wire - Wikipedia - https://en.wikipedia.org/wiki/2Wire (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. 2Wire - WikiDevi - https://wikidevi.wi-cat.ru/2Wire (accessed 2026-10-27)
4. 2Wire 2701HG-B - WikiDevi - https://wikidevi.wi-cat.ru/2Wire_2701HG-B (accessed 2026-10-27)
5. CVE-2007-4389 - CIRCL Vulnerability-Lookup - https://cve.circl.lu/vuln/cve-2007-4389 (accessed 2026-10-27)
