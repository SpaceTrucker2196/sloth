---
name: Sercomm Corporation.
aliases: []
affiliates: []
country: TW [1]
parent: none named; listed on the Taiwan Stock Exchange (TWSE 5388) [2]
founded: 1992 [2]
kind: odm/ems [2][3]
device_classes: [ap/router [3], camera [3], iot-sensor [3], switch [3]]
found_in: ["Linksys, Netgear, Cisco and Diamond routers carrying the SerComm TCP 32764 backdoor, among them the Netgear DGN1000 (2013-2014) [4]"]
radios: ["LTE/5G (4G/5G fixed wireless CPE) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Undocumented TCP 32764 service in SerComm-made router firmware letting commands run without administrator authentication; the 2014 Netgear DGN1000 firmware 1.1.0.55 kept it, re-enabled by a crafted raw-Ethernet packet (EtherType 0x8888) [4]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sercomm was founded in 1992 and is listed on the Taiwan Stock Exchange as 5388; it describes itself as a partner to frontline telecom operators, service providers, system integrators and technology companies [2]. Its product lines span small cells and 4G/5G fixed wireless CPE, DOCSIS and FTTx gateways, home routers and mesh Wi-Fi repeaters, IoT monitoring and safety and security devices, enterprise access points, switches and SMB cameras [3]. The IEEE registry lists 19 MA-L and 13 MA-M blocks to "Sercomm Corporation." at a Miaoli, Taiwan address [1][5], plus separate blocks for its Japan, France and Philippines entities, which are not folded into this entry [1][5].

A MAC in a Sercomm block is most likely an operator-supplied gateway, router, repeater or IoT device rather than a Sercomm-branded product, since its customers are operators and service providers [2][3].

In 2014 Eloi Vanderbeken found that the TCP 32764 backdoor, earlier reported in Linksys, Netgear, Cisco and Diamond routers made by SerComm, was still present in Netgear DGN1000 firmware 1.1.0.55 after the patch and could be re-enabled from the local network by a crafted raw-Ethernet packet [4]. No teardown naming silicon and no randomization documentation was found, and the FCC ID databases could not be consulted, so no grantee code is listed [2][3].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Sercomm: About Sercomm - https://www.sercomm.com/en/company (accessed 2026-10-27)
3. Sercomm - Pioneering Broadband Solutions - https://www.sercomm.com/ (accessed 2026-10-27)
4. Router TCP 32764 Backdoor Vulnerability Secretly added to Patched Routers - The Hacker News - https://thehackernews.com/2014/04/router-manufacturers-secretly-added-tcp.html (accessed 2026-10-27)
5. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
