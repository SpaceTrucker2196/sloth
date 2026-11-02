---
name: D&M Holdings Inc.
aliases: []
country: JP [1][2]
parent: Sound United LLC since 2017, itself acquired by Samsung-owned Harman International in 2025 [3][4]
founded: 2002 [3]
kind: brand [3]
device_classes: [speaker [2][4][5]]
found_in: ["Denon HEOS wireless multi-room speakers (HEOS 1, 3, 5, 7, HEOS Go Pack) [4][5]", "Denon HEOS Bar wireless soundbar [2]", "Denon A/V receivers, e.g. the AVR-3313CI [6]", "Marantz, Boston Acoustics and Polk Audio products [3]"]
radios: ["Wi-Fi 4 (IEEE 802.11a/b/g/n, HEOS 1) [5]", "2.4 GHz [5]", "5 GHz [5]", "Bluetooth (added in HEOS Series 2) [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2014-8508: cross-site scripting in s_network.asp of the Denon AVR-3313CI receiver via unspecified parameters related to Friendlyname [6]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

D&M Holdings is the Japanese audio company formed in 2002 by the merger of Denon and Marantz; its brands have included Denon, Marantz, Boston Acoustics, Polk Audio and D&M Professional, and Sound United LLC acquired it in February 2017 [3]. Sound United was in turn acquired by Samsung-owned Harman International on 23 September 2025 [4]. The IEEE registry lists three MA-L blocks to "D&M Holdings Inc." at Nisshin-cho, Kawasaki, Kanagawa [1], the same address its EU declaration of conformity gives for the Denon HEOS Bar wireless soundbar [2].

A MAC in a D&M block is most likely a networked Denon or Marantz audio product: an A/V receiver or a HEOS wireless multi-room speaker, a line Denon began in 2014 with the HEOS 3, 5 and 7 and extended with Bluetooth in the 2016 Series 2 [4]. The HEOS 1 manual gives its wireless LAN as IEEE 802.11a/b/g/n on 2.4 GHz and 5 GHz [5]. NVD records a cross-site scripting flaw in the network settings page of the Denon AVR-3313CI receiver, CVE-2014-8508 [6].

The chips inside these products are not documented by the sources consulted, so silicon is empty, and FCC grantee codes are not listed because the FCC ID databases refused automated access from this session. Randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Denon HEOS Bar EU Declaration of Conformity DM-CE16025-R4 - https://manuals.denon.com/CEdeclaration/pdf/HEOS%20Bar_CE_DoC_R4.pdf (accessed 2026-10-27)
3. D&M Holdings - Wikipedia - https://en.wikipedia.org/wiki/D%26M_Holdings (accessed 2026-10-27)
4. Denon - Wikipedia - https://en.wikipedia.org/wiki/Denon (accessed 2026-10-27)
5. Denon HEOS 1 owner's manual, specifications - https://manuals.denon.com/HEOS1/ALL/EN/DRDZSYvvrhvacp.php (accessed 2026-10-27)
6. NVD - CVE-2014-8508 - https://nvd.nist.gov/vuln/detail/CVE-2014-8508 (accessed 2026-10-27)
