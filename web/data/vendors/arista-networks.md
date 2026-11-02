---
name: Arista Networks
aliases: ["Arista Network, Inc.", "Arista Networks, Inc."]
affiliates: []
country: US [1][2]
parent: public company, NYSE-listed (ANET) [1]
founded: 2008 [1]
kind: network-equipment [1]
device_classes: [switch [1], ap/router [1][4]]
found_in: ["Data-center, AI, campus and routing Ethernet switches such as the 7800R, 7060X, 720XP and 7130 series running EOS [1]", "Cognitive Wi-Fi access points (Wi-Fi 6, 6E and 7) [1]", "Mojo Networks (acquired 2018) and Awake Security (acquired 2020) [1]"]
radios: ["Wi-Fi 6/6E/7 [1]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["EOS with OSPFv3: crafted packets from an unauthenticated attacker on the same OSPFv3 broadcast domain restart the Ospf3 agent (CVE-2026-73438) [3]", "Arista Wi-Fi access points: memory corruption in the wired-uplink endpoints reachable by an unauthenticated attacker (CVE-2026-102167) [4]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Arista Networks is a Santa Clara, California maker of data-center, AI and campus Ethernet switches, founded in 2008 by Andy Bechtolsheim, Kenneth Duda and David Cheriton from roots in Arastra, and listed on the NYSE as ANET since 2014 [1]. The IEEE registry lists 47 MA-L blocks to "Arista Networks", five to "Arista Network, Inc." and one to "Arista Networks, Inc.", all at Santa Clara or Mountain View addresses [2]. The registry's "Arista Corp" in Fremont and the Taiwanese "Arista Systems Corporation" are not counted here because nothing consulted ties them to Arista Networks [2].

A MAC in an Arista block is most likely a data-center or campus switch running Arista's EOS network operating system, or one of its Cognitive Wi-Fi access points, which span Wi-Fi 6, 6E and 7 [1]. Arista bought Mojo Networks in 2018 and Awake Security in 2020 [1]. NVD lists an EOS OSPFv3 denial-of-service flaw open to an unauthenticated attacker on the same broadcast domain, and a memory corruption flaw in its Wi-Fi access points' wired-uplink endpoints [3][4].

Silicon and FCC grantee codes are not listed: the FCC ID databases and Arista's own product pages refused requests from this session, and nothing is filled in from memory. Wikipedia flags its Arista article as possibly containing machine-generated text, so its product claims are used here only for broad product lines [1]. Randomization behaviour is not documented.

## Sources
1. Arista Networks - Wikipedia - https://en.wikipedia.org/wiki/Arista_Networks (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. NVD CVE-2026-73438 - https://nvd.nist.gov/vuln/detail/CVE-2026-73438 (accessed 2026-10-27)
4. NVD CVE-2026-102167 - https://nvd.nist.gov/vuln/detail/CVE-2026-102167 (accessed 2026-10-27)
