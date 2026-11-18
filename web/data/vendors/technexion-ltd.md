---
name: TechNexion Ltd.
aliases: []
affiliates: []
country: TW [1][2]
parent: unknown
founded: 2001 [2]
kind: module-maker
device_classes: [industrial, camera, module-in-other-brands, iot-sensor]
found_in: ["TechNexion AXON, EDM and PICO system-on-modules built on NXP i.MX 6/7/8M/9 processors for embedded designs [3][4]", "TechNexion panel PCs, embedded vision (MIPI CSI-2), USB vision and automotive SerDes cameras [2][3]"]
radios: ["Wi-Fi 4 (802.11a/b/g/n) on PIXI-IW416 module [5]", "Wi-Fi 5 (802.11ac) on PIXI-9377, STIX-9377 and CLIX-9377 modules [5]", "2.4 GHz [5]", "5 GHz [5]", "BT Classic / BLE (version not stated) on all listed combo modules [5]"]
silicon: ["NXP IW416 802.11a/b/g/n + Bluetooth combo in PIXI-IW416 [5]", "Qualcomm QCA9377 802.11ac + Bluetooth in PIXI-9377-S/-P, STIX-9377-M2-B/-M2-AE/-MPCIE, CLIX-9377 [5]", "NXP i.MX 6, 7, 8M and 9 application processors in AXON/EDM/PICO SOMs [4]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
TechNexion is a Taiwanese embedded-computing company founded in 2001 and headquartered in New Taipei City; it makes system-on-modules, embedded mainboards, fan-less computers and panel PCs for multimedia, communications, security, automation and process-control customers, runs its own PCBA facility in Taiwan and promises up to 15 years product longevity [2]. Its single IEEE block 00:1F:7B (MA-L, 14 January 2008) is registered to a Chung Ho, Taipei address and is its only block [1][6]. Its SOM families (AXON 58x37 mm with four 80-pin Hirose connectors, EDM 260-pin edge connector, PICO 37x40 mm) are all NXP i.MX 6/7/8M/9 based [3][4], and its connectivity line is a set of Wi-Fi/Bluetooth modules: PIXI-IW416 (NXP IW416, 802.11a/b/g/n + BT, SDIO/UART) and a family of Qualcomm QCA9377 802.11ac + Bluetooth modules in SDIO, PCIe/USB, M.2 Key-B, M.2 Key-A+E and Mini-PCIe forms, each stated as FCC/CE/IC/RCM/TELEC certified [5]. A MAC in 00:1F:7B is therefore most likely an embedded industrial device, camera system or panel PC built on TechNexion hardware, an inference from the product line rather than a documented mapping; where it is one of the radio modules, expect a dual-band Wi-Fi 4/5 client with Bluetooth. The product pages do not state Bluetooth versions or FCC ID numbers, and the FCC ID databases were unreachable in this session (HTTP 403), so the grantee code is left empty. No TechNexion security advisories were found, and nothing in the sources documents MAC randomization, so it is recorded as unknown.
## Sources
1. MAC prefix 00:1F:7B - maclookup.app - https://maclookup.app/macaddress/001F7B (accessed 2026-10-27)
2. About TechNexion - https://www.technexion.com/about/ (accessed 2026-10-27)
3. Products - TechNexion - https://www.technexion.com/products/ (accessed 2026-10-27)
4. System on Modules - TechNexion - https://www.technexion.com/products/system-on-modules/ (accessed 2026-10-27)
5. Connectivity (Wi-Fi and Bluetooth modules) - TechNexion - https://www.technexion.com/products/connectivity/ (accessed 2026-10-27)
6. TechNexion Ltd. MAC address blocks - maclookup.app - https://maclookup.app/vendors/technexion-ltd (accessed 2026-10-27)
