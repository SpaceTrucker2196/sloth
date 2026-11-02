---
name: Ubiquiti Inc
aliases: []
country: US [1][3]
parent: publicly traded on the NYSE as UI, no parent named [3]
founded: 2003 [3]
kind: network-equipment [3]
device_classes: [ap/router [3][4], switch [4]]
found_in: ["UniFi access points, switches and cloud gateways [3][4]", "airMAX and airFiber outdoor wireless links [3]", "EdgeMax routers running EdgeOS [3][6]", "AmpliFi [3]", "UniFi U7 Pro Wi-Fi 7 access point [5]"]
radios: ["Wi-Fi 7 (802.11be) in the U7 Pro [5]", "2.4 GHz [5]", "5 GHz [5]", "6 GHz [5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["EdgeOS routers left on default administrator passwords were infected with Moobot and taken over by GRU unit 26165 (APT28); FBI disrupted the botnet in early 2024 (Operation Dying Ember) [6][3]", "CVE-2026-22557, unauthenticated path traversal in the UniFi Network Application, CVSS 10.0, fixed in 10.1.89 (March 2026) [7]", "2013 U-Boot flaw let configuration including passwords be read over TFTP [3]", "2021 alleged data breach, later charged by federal prosecutors as an inside job by a former employee to extort the company [3]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Ubiquiti Inc, formerly Ubiquiti Networks, is a US maker of wireless and wired networking equipment founded by Robert Pera in San Jose, California, in 2003 and now headquartered in New York City; it trades on the NYSE as UI [3]. Wikipedia's infobox gives 2003 while one of its category tags says 2005, so the year is taken from the infobox [3]. The IEEE registry lists 48 MA-L blocks and one IAB block under this exact name at a New York address [1][2].

A MAC in a Ubiquiti block is most likely infrastructure rather than a client: a UniFi access point, switch or cloud gateway, an airMAX or airFiber outdoor link, an EdgeMax router, or an AmpliFi unit [3]. Ubiquiti's own site groups its line as cloud gateways, switching, Wi-Fi, physical security and door access [4]. On the air, a current access point such as the U7 Pro is Wi-Fi 7 with 2x2 radios on 2.4, 5 and 6 GHz, up to 5.8 Gbit/s at 320 MHz on 6 GHz [5].

Security history worth knowing: criminals installed Moobot on EdgeOS routers still using default administrator passwords, GRU unit 26165 (APT28) took the botnet over, and the FBI disrupted it in an operation announced in February 2024 [6][3]. CVE-2026-22557, disclosed in March 2026, is an unauthenticated path traversal in the UniFi Network Application rated CVSS 10.0, fixed in 10.1.89, 10.2.97 and UniFi Express firmware 4.0.13 [7]. Earlier, a 2013 bootloader flaw exposed plaintext configuration over TFTP, and a 2021 alleged breach was later charged as an insider extortion attempt [3].

Silicon and FCC grantee codes are not listed: the U7 Pro specification page names no chipset [5], and fccid.io, fcc.report and the FCC's own grantee search refused requests from the session that wrote this entry, so nothing is filled in from memory. Randomization is unknown; access points and routers are infrastructure and no source here documents their behaviour.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. IEEE Registration Authority, IAB assignments (iab.csv) - https://standards-oui.ieee.org/iab/iab.csv (accessed 2026-10-27)
3. Ubiquiti - Wikipedia - https://en.wikipedia.org/wiki/Ubiquiti (accessed 2026-10-27)
4. Ubiquiti - ui.com - https://ui.com/ (accessed 2026-10-27)
5. U7 Pro technical specification - Ubiquiti - https://techspecs.ui.com/unifi/wifi/u7-pro (accessed 2026-10-27)
6. FBI disrupts Moobot botnet used by Russian military hackers - BleepingComputer - https://www.bleepingcomputer.com/news/security/fbi-disrupts-moobot-botnet-used-by-russian-military-hackers/ (accessed 2026-10-27)
7. Advisory: Ubiquiti UniFi Network Application Remote Path Traversal Vulnerability (CVE-2026-22557) - Censys - https://censys.com/advisory/cve-2026-22557/ (accessed 2026-10-27)
