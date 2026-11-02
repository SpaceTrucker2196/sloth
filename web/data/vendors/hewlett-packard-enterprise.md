---
name: Hewlett Packard Enterprise
aliases: ["Hewlett Packard Enterprise "]
country: US [1][2]
parent: independent; created in the November 2015 split of Hewlett-Packard [1]
founded: 2015 [1]
kind: network-equipment [1]
device_classes: [ap/router [3], switch [4]]
found_in: ["Aruba Networks enterprise access points such as the AP-555 [3]", "HPE OfficeConnect 1920 and 1420 switches [4]", "HPE ProLiant, Synergy and Superdome servers [1]"]
radios: ["Wi-Fi 6 802.11ax, 8x8 at 5 GHz and 4x4 at 2.4 GHz (AP-555) [3]", "BLE 4.x/5.x (Bluetooth 5.0 in the AP-555) [3]", "Thread/Zigbee (802.15.4) (Zigbee in the AP-555) [3]"]
silicon: ["Qualcomm IPQ8074A with two QCN5154 and one QCN5124 radio in the Aruba AP-555 [3]"]
fcc_grantee: ["Q9D, the prefix of the AP-555's FCC ID Q9DAPIN0555 [3]"]
randomization: unknown
security_notes: ["HPESBNW04722 (November 2024): CVE-2024-42509 and CVE-2024-47460, unauthenticated command injection via PAPI on UDP 8211 in Instant AOS-8 and AOS-10 access points, CVSS 9.8 and 9.0 [5]", "2017: Reuters reported HPE let a Russian defence agency examine a cyber-defence system used by the Pentagon [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Hewlett Packard Enterprise was founded on 1 November 2015 in Palo Alto in the split of Hewlett-Packard and has been headquartered in Spring, Texas since 2020; it sells ProLiant, Synergy and Superdome servers, 3PAR, Alletra and Nimble storage, Cray high-performance computing and GreenLake cloud services [1]. Its networking comes from Aruba Networks, acquired by the Hewlett-Packard Company in March 2015 before the split, Silver Peak, and Juniper Networks, whose acquisition completed on 2 July 2025 [1]. The IEEE registry lists 118 MA-L blocks to "Hewlett Packard Enterprise" at Santa Clara and San Jose addresses and 54 more under the same name with a trailing space, mostly at Roseville, California [2].

Which product line a given block serves is not stated by the registry, so the device mapping here is inferred: a MAC in these blocks is most likely an Aruba access point, an HPE OfficeConnect or Aruba switch, or a server port; WikiDevi lists HPE OfficeConnect 1420 and 1920 switches [3][4]. The Aruba AP-555 (FCC ID Q9DAPIN0555) runs a Qualcomm IPQ8074A with QCN5154 and QCN5124 802.11ax radios and also carries Bluetooth 5.0 and Zigbee [3].

HPE advisory HPESBNW04722 of 5 November 2024 fixed CVE-2024-42509 and CVE-2024-47460, unauthenticated command injection through crafted packets to the PAPI management protocol on UDP 8211 in Instant AOS-8 and AOS-10 access points [5]. Randomization behaviour is not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources

1. Hewlett Packard Enterprise - Wikipedia - https://en.wikipedia.org/wiki/Hewlett_Packard_Enterprise (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Aruba Networks AP-555 (APIN0555) - WikiDevi - https://wikidevi.wi-cat.ru/Aruba_Networks_AP-555_(APIN0555) (accessed 2026-10-27)
4. Hewlett Packard Enterprise - WikiDevi - https://wikidevi.wi-cat.ru/Hewlett_Packard_Enterprise (accessed 2026-10-27)
5. HPE Aruba Networking Access Points Multiple Vulnerabilities (HPESBNW04722) - https://csaf.arubanetworking.hpe.com/2024/hpe_aruba_networking_-_hpesbnw04722.txt (accessed 2026-10-27)
