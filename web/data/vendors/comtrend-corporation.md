---
name: Comtrend Corporation
aliases: []
country: TW [1][2]
parent: unknown
founded: 1990 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][4], switch [2]]
found_in: ["Comtrend PG-9072 AC1200 G.hn powerline adapter [3]", "Comtrend PG-9172 G.hn powerline adapter [3]", "Comtrend routers such as the VR-3033 and AR-5387un [4]"]
radios: ["Wi-Fi 4 [3]", "Wi-Fi 5 [3]", "2.4 GHz [3]", "5 GHz [3]"]
silicon: ["Celeno CL1860 WiSoC with MediaTek MT7620A (2.4 GHz) and Celeno CL2200 / MediaTek MT7612EN (5 GHz) in PG-9072 [3]", "Marvell 88LX3142 G.hn baseband in PG-9072, PG-9172 and PG-9073 [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-10173 command injection in VR-3033 ping and traceroute diagnostics and CVE-2024-5785 command injection in WLD71-T1 [4]", "CVE-2018-20388 credentials exposed over SNMP in CM-6200un and CM-6300n [4]", "CVE-2010-0470, CVE-2018-8062 cross-site scripting and CVE-2024-5786 CSRF in router web interfaces [4]", "CVE-2019-25483 restricted shell escape in AR-5310 [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Comtrend Corporation is a Taiwanese broadband equipment maker founded in 1990 and listed under stock code 8089; it describes itself as serving telecom operators, ISPs, enterprises and system integrators with GPON, XGS-PON, G.hn, Wi-Fi, Ethernet switching and PoE products [2]. The IEEE registry lists 9 MA-L blocks under the name at a New Taipei City address [1].

A MAC in a Comtrend block is most likely an operator-supplied gateway or a G.hn powerline adapter, though that reading is inferred from the product range rather than stated by a source. DeviWiki documents the PG-9072 AC1200 G.hn adapter with a Marvell 88LX3142 G.hn baseband, a Celeno CL1860 WiSoC, a MediaTek MT7620A for 802.11n on 2.4 GHz and a Celeno CL2200 (a rebranded MediaTek MT7612EN) for 802.11ac on 5 GHz, and the PG-9172 and PG-9073 G.hn adapters on the same Marvell baseband [3]. NVD lists command injection in the VR-3033 ping and traceroute pages and in the WLD71-T1, SNMP credential exposure, cross-site scripting, CSRF and a restricted-shell escape across several Comtrend router models [4].

Parent company, FCC grantee codes and randomisation behaviour are unknown: the English Wikipedia has no article, the FCC databases refused the session that wrote this entry, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Comtrend corporate profile - https://www.comtrend.com/corporate-profile.html (accessed 2026-10-27)
3. Comtrend - DeviWiki - https://deviwiki.com/wiki/Comtrend (accessed 2026-10-27)
4. NVD CVE API keyword search Comtrend - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Comtrend&resultsPerPage=30 (accessed 2026-10-27)
