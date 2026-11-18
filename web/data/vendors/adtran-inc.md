---
name: Adtran Inc
aliases: []
affiliates: []
country: US [1][2]
parent: ADTRAN Holding, listed on Nasdaq (ADTN) and Frankfurt [1]
founded: 1985 [1]
kind: network-equipment [1][3]
device_classes: [ap/router [3][6][7], switch [3][5]]
found_in: ["Fiber access optical line terminals, including the SDX 6400 series [1][3]", "834-5 SmartOS gateway [6]", "SR400ac routers [4]", "NetVanta 3120 business routers [5]", "411 ONT optical network terminals [7]", "Bluesocket enterprise Wi-Fi [1]", "ADVA optical transport and Oscilloquartz timing equipment after the ADVA combination [1]"]
radios: ["Wi-Fi 7 (named as a product area) [3]", "Wi-Fi in the 834-5 gateway, which advertises a BSSID [6]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["SR400ac: ping command injection allowing remote code execution (CVE-2023-38120) [4]", "NetVanta 3120: Telnet enabled by default with default root-level credentials (CVE-2024-28093) [5]", "834-5 SmartOS gateway: SSH on by default with a hidden hard-coded support account (CVE-2024-39345) [6]", "411 ONT: weak default passwords and command injection to root (CVE-2025-22938, CVE-2025-22939) [7][8]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Adtran is an American fiber networking and telecommunications company founded in 1985 and headquartered in Huntsville, Alabama, whose parent ADTRAN Holding trades on Nasdaq as ADTN and in Frankfurt [1]. The IEEE registry lists 15 MA-L blocks to "Adtran Inc", most at its Huntsville address and three at Cambridge, UK addresses [2]. It combined with Germany's ADVA Optical Networking, bringing optical transport and Oscilloquartz timing, and earlier bought Bluesocket for enterprise Wi-Fi and SmartRG for connected-home software [1].

A MAC in an Adtran block is most likely carrier access equipment or customer premises gear supplied by a broadband operator: an optical line terminal, an optical network terminal, a SmartOS gateway, or a NetVanta business router [1][3][5][6][7]. Adtran's site lists optical line terminals, aggregation switches and routers, managed Wi-Fi and Wi-Fi 7 [3]. NVD records serious flaws in that customer premises gear: command injection in SR400ac routers, default credentials on NetVanta 3120 Telnet, a hidden hard-coded support account on the 834-5 SmartOS gateway, and weak default passwords plus command injection in the 411 ONT [4][5][6][7][8].

Radio details are sparse: the sources consulted name Wi-Fi 7 as a product area and show that the 834-5 gateway broadcasts a BSSID, but give no band or chipset data [3][6]. Silicon and FCC grantee codes are not listed: the FCC ID databases refused requests from this session and no teardown was found, and nothing is filled in from memory. Randomization behaviour is not documented.

## Sources
1. Adtran - Wikipedia - https://en.wikipedia.org/wiki/Adtran (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Adtran products and services - https://www.adtran.com/en/products-and-services (accessed 2026-10-27)
4. NVD CVE-2023-38120 - https://nvd.nist.gov/vuln/detail/CVE-2023-38120 (accessed 2026-10-27)
5. NVD CVE-2024-28093 - https://nvd.nist.gov/vuln/detail/CVE-2024-28093 (accessed 2026-10-27)
6. NVD CVE-2024-39345 - https://nvd.nist.gov/vuln/detail/CVE-2024-39345 (accessed 2026-10-27)
7. NVD CVE-2025-22938 - https://nvd.nist.gov/vuln/detail/CVE-2025-22938 (accessed 2026-10-27)
8. NVD CVE-2025-22939 - https://nvd.nist.gov/vuln/detail/CVE-2025-22939 (accessed 2026-10-27)
