---
name: Siemens AG
aliases: ["SIEMENS AG", "Siemens AG,"]
affiliates: []
country: DE [1]
parent: independent [4]
founded: 1847 [4]
kind: other [4]
device_classes: [industrial [5]]
found_in: ["SIMATIC S7-1200 PLCs, with integrated Profinet and Ethernet interfaces, and S7-1500 PLCs, with Profinet interfaces as standard [5]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2022-38465: the built-in global private key of SIMATIC S7-1200, S7-1500 and related CPU families is insufficiently protected, so one CPU can yield the key for its whole family [6]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Siemens is a German technology company founded in Berlin on 1 October 1847 by Werner von Siemens and Johann Georg Halske and headquartered in Munich and Berlin; its operations include Digital Industries, Smart Infrastructure, Siemens Mobility, Siemens Financial Services and the majority-owned Siemens Healthineers, and it spun off Gigaset in 2008 and Siemens Energy in 2020 [4]. The IEEE registry lists MA-L blocks to "Siemens AG" at Amberg, Regensburg, Erlangen, St. Georgen and Munich, to "SIEMENS AG" at Karlsruhe and Fuerth and to "Siemens AG," at Karlsruhe, plus an MA-M block at Karlsruhe and an MA-S block at Erlangen [1][2][3]. Many other Siemens units register under their own names and are not covered here [1].

A MAC in these blocks is most likely industrial automation equipment: SIMATIC is Siemens' PLC and automation family, whose S7-1200 controllers carry integrated Profinet and Ethernet interfaces and whose S7-1500 CPUs carry Profinet interfaces as standard [5]. Which products sit in which block is not documented by the sources consulted, so found_in is inferred and radios and silicon are empty. NVD records CVE-2022-38465, an insufficiently protected global private key across SIMATIC S7-1200, S7-1500 and related CPUs that lets an attacker who extracts it from one CPU attack legacy PG/PC and HMI communication of the family [6]. FCC grantee codes are not listed because the FCC ID databases refused access from the session that wrote this entry, and randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
3. IEEE Registration Authority, MA-S assignments (oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
4. Siemens - Wikipedia - https://en.wikipedia.org/wiki/Siemens (accessed 2026-10-27)
5. Simatic - Wikipedia - https://en.wikipedia.org/wiki/Simatic (accessed 2026-10-27)
6. NVD, CVE-2022-38465 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-38465 (accessed 2026-10-27)
