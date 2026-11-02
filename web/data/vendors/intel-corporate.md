---
name: Intel Corporate
aliases: []
country: US [1]
parent: independent [1]
founded: 1968 [1]
kind: chip-vendor
device_classes: [laptop, module-in-other-brands]
found_in: ["PC laptops and desktops via M.2 2230 / M.2 1216 modules and CNVio/CNVi companion parts [5][8]", "Linux systems using the iwlwifi driver (Wi-Fi 7 BE200/BE201/BE202, 6E AX210/AX211/AX411, 6 AX200/AX201, Wireless-AC 9xxx/8xxx/7xxx) [4]"]
radios: ["Wi-Fi 4 (Centrino Wireless-N / Advanced-N / Ultimate-N) [4][6]", "Wi-Fi 5 (Wireless-AC 7260, 8260/8265, 9260/9560, 3165/3168) [4]", "Wi-Fi 6 (AX200, AX201) [4]", "Wi-Fi 6E (AX210, AX211, AX411) [4]", "Wi-Fi 7 (BE200, BE201, BE202) [4][5]", "2.4 GHz [5]", "5 GHz [5]", "6 GHz [5]", "BT Classic [5]", "BLE 5.x (Bluetooth 5.4 on BE200) [5]"]
silicon: ["Intel Wi-Fi 7 BE200 / BE201 / BE202 [4][5]", "Intel Wi-Fi 6E AX210 / AX211 / AX411 [4]", "Intel Wi-Fi 6 AX200 / AX201 [4][8]", "Intel Wireless-AC 9560 / 9462 / 9461 / 9260 [4][8]", "Intel Wireless-AC 8265 / 8260, 3168 / 3165 [4][8]", "Intel Wireless 7265 / 7260 / 3160 [4][8]", "Intel PRO/Wireless 2100B / 2200BG / 3945ABG, WiFi Link 4965AGN, Ultimate-N 6300 (Centrino era, 2003-2013) [6]"]
fcc_grantee: []
randomization: mixed [9][10][11]
security_notes: ["Intel PROSet/Wireless WiFi software advisories INTEL-SA-01224 (2025-02), 01270 (2025-05), 01292 (2025-08), 01398 (2025-11), 01422 and 01468 (2026-08) [7]", "Intel Wireless Bluetooth / Killer Bluetooth advisories INTEL-SA-00606 (2025-02) and INTEL-SA-00628 (2022-08) [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: documented}
researched: 2026-10-27
---
## Summary
Intel is an independent US semiconductor company incorporated 18 July 1968, headquartered in Santa Clara and listed on Nasdaq (INTC); the US government took a 9.9% stake in August 2025 and the company has been restructuring through 2025-2026 [1]. "Intel Corporate" is the registrant name on 667 IEEE blocks (MA-L and MA-S), the first from November 2004 and the latest updated July 2026; the sample block 00:12:F0 is registered to an Intel site in Kulim, Malaysia [2][3]. A MAC in an Intel Corporate block is almost always a laptop or desktop Wi-Fi/Bluetooth card: Intel's client adapters ship as M.2 2230 and M.2 1216 modules and, for the 9xxx/AX201/AX211 class, as CNVio companions to Intel chipsets, inside other brands' PCs [5][8]. The lineage the Linux iwlwifi driver supports runs from Centrino-era 802.11abgn parts through Wireless-AC 7260/8260/9260, Wi-Fi 6 AX200/AX201, Wi-Fi 6E AX210/AX211/AX411 to Wi-Fi 7 BE200/BE201/BE202 [4]; the BE200 (launched Q3 2023) is 2x2 on 2.4, 5 and 6 GHz with 320 MHz channels, up to 5.8 Gbps, and Bluetooth 5.4 [5]. Intel's wireless brand began with Centrino in 2003 (PRO/Wireless 2100B/2200BG, later 3945ABG and 4965AGN) and the Centrino name was retired in 2013 [6]. What the operator sees on the air depends on the host OS, not on Intel: Windows exposes random hardware addresses as a setting the user turns on, for all networks or per network, and its support page does not state the default [9]; NetworkManager on Linux randomizes the address during scanning by default but keeps the permanent (1.4) or current (1.6+) address for connections [10]; Android, where it uses Intel silicon, randomizes per network by default since Android 10 [11]. So an Intel OUI usually means a Windows or Linux PC that is not hiding its hardware address. Intel publishes a steady stream of PROSet/Wireless Wi-Fi software advisories (six between February 2025 and August 2026) and Bluetooth driver advisories (INTEL-SA-00606, -00628) [7]; patch levels matter more than the radio generation. The FCC grantee code was not confirmed because the FCC ID mirrors returned 403; it is left empty rather than recalled.
## Sources
1. Wikipedia - Intel - https://en.wikipedia.org/wiki/Intel (accessed 2026-10-27)
2. maclookup.app - Intel Corporate vendor page - https://maclookup.app/vendors/intel-corporate (accessed 2026-10-27)
3. maclookup.app - OUI 00:12:F0 registration - https://maclookup.app/macaddress/0012F0 (accessed 2026-10-27)
4. Linux Wireless documentation - iwlwifi supported devices - https://wireless.docs.kernel.org/en/latest/en/users/drivers/iwlwifi.html (accessed 2026-10-27)
5. Intel - Wi-Fi 7 BE200 specifications - https://www.intel.com/content/www/us/en/products/sku/230078/intel-wifi-7-be200/specifications.html (accessed 2026-10-27)
6. Wikipedia - Centrino - https://en.wikipedia.org/wiki/Centrino (accessed 2026-10-27)
7. Intel Product Security Center - advisories list - https://www.intel.com/content/www/us/en/security-center/default.html (accessed 2026-10-27)
8. DeviWiki - Intel - https://deviwiki.com/wiki/Intel (accessed 2026-10-27)
9. Microsoft Support - How to use random hardware addresses in Windows - https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc (accessed 2026-10-27)
10. Thomas Haller - MAC address spoofing in NetworkManager 1.4.0 - https://blogs.gnome.org/thaller/2016/08/26/mac-address-spoofing-in-networkmanager-1-4-0/ (accessed 2026-10-27)
11. Android Open Source Project - MAC randomization behavior - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
