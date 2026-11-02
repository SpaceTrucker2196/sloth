---
name: Hewlett Packard
aliases: []
country: US [1][2]
parent: split in 2015 into HP Inc. and Hewlett Packard Enterprise [2]
founded: 1939 [2]
kind: brand [2]
device_classes: [laptop [2], printer [2]]
found_in: ["HP personal computers and printers, now HP Inc. [2]", "HP ProLiant servers and HP Networking (formerly ProCurve) products, now Hewlett Packard Enterprise [2]", "HP Compaq business desktops and laptops, after the 2002 Compaq merger [2]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2021-39238: potential buffer overflow in certain HP Enterprise LaserJet, LaserJet Managed, Enterprise PageWide and PageWide Managed products [3]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Hewlett-Packard was an American information technology company founded
in 1939 by Bill Hewlett and David Packard in a Palo Alto garage; it
merged with Compaq in 2002 and on November 1, 2015 split into Hewlett
Packard Enterprise, which took the enterprise products and services,
and HP Inc., which took PCs and printers [2]. The IEEE registry holds
150 MA-L blocks under the plain name Hewlett Packard, at Cupertino,
Boulder and Houston addresses, many at 11445 Compaq Center Drive,
Houston [1]. Blocks registered under HP Inc. and Hewlett Packard
Enterprise are separate registry names and are not claimed here [1].

A MAC in a Hewlett Packard block is most likely an HP-era or
Compaq-era PC, laptop, printer, ProLiant server or HP Networking
(formerly ProCurve) product, now supported by one of the two successor
companies [2]. Printers are one documented security exposure: NVD
lists CVE-2021-39238, a potential buffer overflow in certain HP
Enterprise LaserJet, LaserJet Managed, Enterprise PageWide and
PageWide Managed products [3].

Radios, silicon and FCC grantee codes are not listed: the FCC ID
databases refused the session that verified this entry, and nothing is
filled in from memory. MAC randomization depends on the host operating
system and is not documented by the sources consulted.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Hewlett-Packard - Wikipedia - https://en.wikipedia.org/wiki/Hewlett-Packard (accessed 2026-10-27)
3. CVE-2021-39238 - NVD API record - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-39238 (accessed 2026-10-27)
