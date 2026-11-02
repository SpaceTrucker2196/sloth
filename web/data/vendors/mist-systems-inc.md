---
name: "Mist Systems, Inc."
aliases: []
affiliates: []
country: US [1][2]
parent: "Juniper Networks (acquired 2019), itself part of Hewlett Packard Enterprise since 2 July 2025 [3]"
founded: 2014 [2]
kind: network-equipment [4]
device_classes: [ap/router [4]]
found_in: ["Juniper Mist access points AP21, AP24, AP34, AP43, AP45, AP64 [4]", "Juniper Mist Wi-Fi 7 access points AP36, AP37, AP47, AP66 [4]"]
radios: ["Wi-Fi 5 [4]", "Wi-Fi 6 [4]", "Wi-Fi 6E [4]", "Wi-Fi 7 [4]", "2.4 GHz [4]", "5 GHz [4]", "6 GHz [4]", "BLE (virtual BLE and omni BLE) [4][5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Mist Systems is a Cupertino, California, WLAN company founded in 2014 that Juniper Networks agreed to buy for 405 million US dollars [2]; Wikipedia dates the acquisition of the wireless LAN startup to April 2019, and Juniper in turn became part of Hewlett Packard Enterprise when HPE's acquisition closed on 2 July 2025 [3]. The IEEE registry lists 17 MA-L blocks under Mist Systems, Inc. at a Cupertino address [1].

A MAC in a Mist block is most plausibly an enterprise access point managed from the Mist cloud, though that link between the blocks and the hardware is inferred rather than stated by a source in hand. Juniper's access-point range, sold as Juniper Mist with the Mist cloud and Marvis AI, runs from the 802.11ac Wave 2 AP21 through Wi-Fi 6 and 6E models such as the AP45 and AP64 to Wi-Fi 7 models such as the AP47, on 2.4 and 5 GHz and, from the 6E models on, 6 GHz, most with a dedicated third or fourth radio and either a virtual BLE antenna array or omni BLE [4]. The Mist site, now carrying the HPE banner, lists Virtual Bluetooth LE among its technologies [5]. An NVD keyword search for Mist Systems returned no Mist-related CVEs [6].

Chipsets, FCC grantee codes and randomisation are unknown: the FCC databases and HPE's product pages refused the session that wrote this entry, no teardown was found, and nothing is filled in from memory.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Juniper Networks buys Mist Systems for USD 405 mln - Telecompaper - https://www.telecompaper.com/nieuws/juniper-networks-buys-mist-systems-for-usd-405-mln--1283170 (accessed 2026-10-27)
3. Juniper Networks - Wikipedia - https://en.wikipedia.org/wiki/Juniper_Networks (accessed 2026-10-27)
4. Juniper access points - https://www.juniper.net/us/en/products/access-points.html (accessed 2026-10-27)
5. Mist home page - https://www.mist.com/ (accessed 2026-10-27)
6. NVD CVE API keyword search Mist Systems - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Mist%20Systems&resultsPerPage=30 (accessed 2026-10-27)
