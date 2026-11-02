---
name: Calix Inc.
aliases: ["Calix Networks"]
country: US [1][2]
parent: unknown
founded: 1999 [2]
kind: network-equipment [2][3]
device_classes: [ap/router [3][4][5], smart-home [5]]
found_in: ["Calix GigaSpire residential Wi-Fi systems such as the GS2020E and GS2026E [3][5][7]", "Calix GigaCenter 844G-1 and GigaHub 814G-1 ONT gateways [4][6]", "GigaPoint optical network terminals and AXOS E-Series access systems at the operator side [3]"]
radios: ["Wi-Fi 4/5/6 [4][5][6]", "2.4 GHz [4][5]", "5 GHz [5][6]", "BT Classic and BLE (Bluetooth 4.1) [5]", "Thread/Zigbee (802.15.4) [5]"]
silicon: ["Broadcom BCM68380 with BCM43217 and Quantenna QT3840BC in GigaCenter 844G-1 [4]", "Qualcomm IPQ8074 with QCN5054 and QCN5024, Qualcomm CSR8811 Bluetooth, Silicon Labs EFR32MG and Sigma Designs ZM5101 Z-Wave in GigaSpire GS2026E [5]", "5V Technologies 5VT2516 with Realtek RTL8812BRH and RTL8192ER in GigaHub 814G-1 [6]", "Qualcomm IPQ8074 with QCN5054 and QCN5024 in GigaSpire GS2020E [7]"]
fcc_grantee: ["2ABLK, the prefix of the 844G-1, 814G-1, GS2020E and GS2026E FCC IDs [4][5][6][7]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Calix, formerly Calix Networks Inc., was founded in 1999, is headquartered in San Jose, California, and provides cloud, software platforms, systems and services to internet service providers, with about 1,500 service-provider customers by February 2026 [2]. The IEEE registry lists 21 MA-L blocks to "Calix Inc." at 2777 Orchard Pkwy, San Jose, and an IAB block to "Calix Networks" at a Petaluma address [1][8]. Its customers are national providers, telephone and electric co-ops, cable operators, municipalities and WISPs, and its hardware includes GigaSpire home Wi-Fi systems (Wi-Fi 7 among them), GigaPoint ONTs and ONUs, and the AXOS E-Series access systems [3].

Calix files GigaSpire under subscriber solutions and GigaPoint ONTs and ONUs as subscriber access devices [3], so a MAC in a Calix block is likely the gateway or ONT a provider installed in a subscriber's home, under the provider's brand; that last step is an inference, not a sourced statement. WikiDevi documents the GigaCenter 844G-1 as a Broadcom BCM68380 with a BCM43217 2x2 2.4 GHz radio and a Quantenna QT3840BC 4x4 802.11ac radio [4], the GigaHub 814G-1 as a 5V Technologies 5VT2516 with Realtek RTL8812BRH and RTL8192ER [6], and the GigaSpire GS2020E and GS2026E as Qualcomm IPQ8074 with two QCN5054 (5 GHz, 8x8 802.11ax) and a QCN5024 (2.4 GHz, 4x4) [5][7]. The GS2026E also carries a Qualcomm CSR8811 Bluetooth 4.1 chip, a Silicon Labs EFR32MG for Zigbee or Thread and a Sigma Designs ZM5101 for Z-Wave, so it can also act as a smart-home hub [5]. All four FCC IDs start with 2ABLK [4][5][6][7].

Parent, randomization and security advisories are not documented by the sources consulted: Wikipedia mentions no security incident [2], and NVD's search pages did not render for the session that wrote this entry.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Calix Inc. - Wikipedia - https://en.wikipedia.org/wiki/Calix_Inc. (accessed 2026-10-27)
3. Calix home page - https://www.calix.com/ (accessed 2026-10-27)
4. Calix GigaCenter 844G-1 - WikiDevi - https://wikidevi.wi-cat.ru/Calix_GigaCenter_844G-1 (accessed 2026-10-27)
5. Calix GigaSpire GS2026E - WikiDevi - https://wikidevi.wi-cat.ru/Calix_GigaSpire_GS2026E (accessed 2026-10-27)
6. Calix GigaHub 814G-1 - WikiDevi - https://wikidevi.wi-cat.ru/Calix_GigaHub_814G-1 (accessed 2026-10-27)
7. Calix GigaSpire GS2020E - WikiDevi - https://wikidevi.wi-cat.ru/Calix_GigaSpire_GS2020E (accessed 2026-10-27)
8. IEEE Registration Authority, IAB assignments (iab.csv) - https://standards-oui.ieee.org/iab/iab.csv (accessed 2026-10-27)
