---
name: HP Inc.
aliases: []
affiliates: []
country: US [1][2]
parent: independent, a public company (NYSE: HPQ) and the legal successor of Hewlett-Packard after the 2015 split [2]
founded: 1939 [2]
kind: brand [2]
device_classes: [laptop [2], printer [2]]
found_in: ["HP DeskJet, OfficeJet, LaserJet and Envy printers [2]", "HP Pro, Elite, OmniBook and Omen PCs [2]", "HP DeskJet 2800 series printers (Wi-Fi Direct) [3]"]
radios: ["Wi-Fi with Wi-Fi Direct (DeskJet 2800 series) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2026-13753: DeskJet 2800 series firmware TBP1CN2612AR and earlier, missing authorization in the embedded web server lets an unauthenticated LAN host read the Wi-Fi Direct SSID and plaintext passphrase, serial numbers and admin settings; unpatched at disclosure on 2026-07-06 [3]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

HP Inc. is the personal-computer and printing half of Hewlett-Packard after the company split in two in 2015, and is its legal successor; Hewlett-Packard itself was founded by Bill Hewlett and David Packard in 1939, and HP Inc. is headquartered in Palo Alto, California [2]. The IEEE registry lists 43 MA-L blocks under HP Inc., registered at Spring, Texas [1]. A MAC in an HP Inc. block is most likely a printer (DeskJet, OfficeJet, LaserJet, Envy) or a PC (Pro, Elite, OmniBook, Omen, HP Z workstations) [2]; Hewlett Packard Enterprise, the server and networking sibling, is a separate company [2].

Printers that raise their own Wi-Fi Direct network are worth a look: CERT/CC disclosed on 2026-07-06 that DeskJet 2800 series printers on firmware TBP1CN2612AR or earlier return the Wi-Fi Direct SSID and plaintext passphrase, serial numbers and administrative settings to unauthenticated requests from the local network, and that HP could not be reached, so no patch existed at publication [3]. CERT/CC advises placing such printers on an isolated segment, disabling Wi-Fi Direct where unneeded, and limiting or disabling SNMP [3].

Silicon and the FCC grantee code are not listed because the FCC ID databases (fccid.io, fcc.report, device.report, apps.fcc.gov) refused this session's requests and no teardown was consulted. HP PCs take their MAC behaviour from the operating system, and no source in hand documents it, so randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. HP Inc. - Wikipedia - https://en.wikipedia.org/wiki/HP_Inc. (accessed 2026-10-27)
3. VU#828543 HP Deskjet 2800 Printer Series Webservers contain Missing Authorization Vulnerability - CERT/CC - https://kb.cert.org/vuls/id/828543 (accessed 2026-10-27)
