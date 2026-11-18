---
name: Rockwell Automation
aliases: []
affiliates: []
country: US [1][2]
parent: independent [2]
founded: 1903 [2]
kind: other [2]
device_classes: [industrial [2][3]]
found_in: ["Allen-Bradley programmable logic controllers, including ControlLogix [3]", "CompactLogix, ControlLogix, GuardLogix and SoftLogix controllers [4]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2021-22681: an unauthenticated attacker can bypass the key verification between Studio 5000 Logix Designer or RSLogix 5000 and Logix controllers; listed in CISA's Known Exploited Vulnerabilities catalogue on 2026-03-05 [4]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Rockwell Automation is a US industrial automation company headquartered in Milwaukee, Wisconsin, which began in 1903 as the Compression Rheostat Launch Company, is the legal successor of Rockwell International after the 2001 Rockwell Collins spin-off, trades on the NYSE as ROK, and sells under the Allen-Bradley, FactoryTalk and LifecycleIQ names [2]. The IEEE registry lists 14 MA-L blocks to "Rockwell Automation" at 1 Allen-Bradley Drive, Mayfield Heights, Ohio [1].

A MAC in these blocks is most likely Allen-Bradley factory automation equipment, a line Rockwell International bought in 1985 that makes programmable logic controllers, among them the ControlLogix family introduced in 1997, and drives [3]. Which products sit in which block is not documented by the sources consulted, so found_in is inferred and radios and silicon are empty. NVD records CVE-2021-22681, a bypass of the key that Studio 5000 Logix Designer and RSLogix 5000 use to verify CompactLogix, ControlLogix, GuardLogix and other Logix controllers, and marks it as added to CISA's Known Exploited Vulnerabilities catalogue on 2026-03-05 [4]. FCC grantee codes are not listed because the FCC ID databases refused access from the session that wrote this entry, and randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Rockwell Automation - Wikipedia - https://en.wikipedia.org/wiki/Rockwell_Automation (accessed 2026-10-27)
3. Allen-Bradley - Wikipedia - https://en.wikipedia.org/wiki/Allen-Bradley (accessed 2026-10-27)
4. NVD, CVE-2021-22681 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-22681 (accessed 2026-10-27)
