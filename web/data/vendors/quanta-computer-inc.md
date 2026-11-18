---
name: Quanta Computer Inc.
aliases: []
affiliates: []
country: TW [1]
parent: independent, listed on the Taiwan Stock Exchange [1][2]
founded: 1988 [1][2]
kind: odm/ems
device_classes: [laptop [1][2]]
found_in: []
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2024-13040 authorization bypass, and CVE-2025-15235 to CVE-2025-15240 missing authorization, path traversal, SQL injection and arbitrary file upload, in Quanta's QOCA aim AI Medical Cloud Platform (server software, not a device on the air) [4]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

Quanta Computer is a Taiwanese contract manufacturer of electronic hardware founded in 1988 by Barry Lam, headquartered in Taoyuan City and listed on the Taiwan Stock Exchange [1]. Its own site calls it the leader in worldwide notebook manufacturing and lists cloud computing, smart home, smart automobile and AIoT product lines [2]. As an ODM it has built notebooks, servers and other hardware for Apple, Dell, Facebook and One Laptop per Child, among others [1].

The registry holds 20 MA-L blocks under the spelling Quanta Computer Inc., all at Taiwanese addresses [3]. A MAC in one of them is most likely a Quanta-built notebook or other Quanta-made hardware, but which brand's product carries a Quanta block is not documented in the sources consulted, so found_in is left empty rather than guessed from the ODM customer list [1][2]. The other Quanta registrants (Quanta Storage, Quanta Network Systems, Quanta Microsystems) are separate registry names and are not folded in here [3].

No wireless silicon, radios or FCC grantee codes are documented: the FCC ID databases (fccid.io, fcc.report, the FCC grantee search) refused the session that wrote this entry, and nothing is filled in from memory. The NVD records naming Quanta Computer concern its QOCA aim AI Medical Cloud Platform, server software rather than a device on the air: an authorization bypass (CVE-2024-13040) and missing authorization, path traversal, SQL injection and arbitrary file upload flaws (CVE-2025-15235 to CVE-2025-15240) [4]. Randomization is the host operating system's behaviour and is unknown here.

## Sources
1. Quanta Computer - Wikipedia - https://en.wikipedia.org/wiki/Quanta_Computer (accessed 2026-10-27)
2. Quanta Computer company profile - https://www.quantatw.com/Quanta/english/about/company.aspx (accessed 2026-10-27)
3. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
4. NVD CVE API, keyword Quanta Computer - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Quanta%20Computer&resultsPerPage=20 (accessed 2026-10-27)
