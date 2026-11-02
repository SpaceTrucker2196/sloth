---
name: "Quectel Wireless Solutions Co.,Ltd."
aliases: []
affiliates: []
country: CN [2]
parent: unknown
founded: 2010 [1]
kind: module-maker
device_classes: [module-in-other-brands, iot-sensor, industrial, laptop]
found_in: ["PINE64 PinePhone (Quectel EG25-G LTE modem) [6][12]", "Lenovo ThinkPad X1 Carbon Gen 12/13 and X1 2-in-1 Gen 9 WWAN options (EM160R-GL LTE Cat 16, RM520N-GL 5G sub-6) [8]", "Nielsen Portable People Meter gateway (EG21-G LTE module) [12]", "Industrial routers, industrial PDAs, rugged tablet PCs, digital signage and video transmission (vendor-stated EC25 applications) [4]", "G-Technologies GPS tracker (KG200Z LoRa and LC86L GNSS modules) [3]"]
radios: ["LTE Cat 4 (EC25) with UMTS/HSPA+ and GSM/GPRS/EDGE fallback [4]; LTE Cat 16 (EM160R-GL) and 5G sub-6 GHz (RM520N-GL) WWAN modules [8]", "Wi-Fi 4 2.4 GHz (802.11b/g/n 1x1) on FC41D [5]", "2.4 GHz [5]", "BLE 5.2 on FC41D [5]", "LoRa: KG200Z module [3]", "GNSS receivers (LC86L, QLM29Hx, QLM290P) [3]"]
silicon: ["Qualcomm MDM9206 in BG96 LTE-M/NB-IoT module [7]", "Qualcomm baseband (Qualcomm-signed baseband firmware and TrustZone kernel) in EG25-G [6]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE records are indexed for EG25-G, AG550QCN, RG502Q-EA and UC20 firmware (CIRCL vulnerability-lookup product index; the individual CVE IDs and descriptions could not be verified this session) [9]", "Quectel publishes a vulnerability-disclosure site (security.quectel.com) with a PSIRT policy [10]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Quectel Wireless Solutions is a Shanghai-headquartered IoT module maker founded in 2010 [1][2], selling cellular, GNSS, Wi-Fi/Bluetooth and LoRa modules, antennas, smart modules, single-board computers and edge-computing boxes, with R&D or regional offices in China, Canada, Brazil, Serbia and Malaysia [2][3]. Its OUIs (75 blocks, both MA-L and MA-S) [11] are therefore soldered into other brands' products, not into Quectel-branded devices: documented hosts range from the PinePhone (EG25-G) [6][12] and Lenovo ThinkPad X1 WWAN options (EM160R-GL, RM520N-GL) [8] to Nielsen's Portable People Meter gateway (EG21-G) [12], industrial routers, PDAs, signage and rugged tablets [4], and a LoRa/GNSS GPS tracker [3]. A Quectel MAC on a LAN is a Wi-Fi/Bluetooth module such as the low-cost FC41D, which is 2.4 GHz 802.11b/g/n 1x1 with Bluetooth 5.2 [5]; the dual-band and Thread, Wi-Fi HaLow and Amazon Sidewalk module claims that earlier drafts of this entry took from fccid.io grantee XMR were removed because every fccid.io page returned HTTP 403 on verification, so no FCC grantee code is recorded. Cellular modules (EC25 LTE Cat 4 with 3G/2G fallback [4]; EM160R-GL LTE Cat 16 and RM520N-GL 5G [8]) show up as LTE/5G rather than on Wi-Fi. Chip-level documentation reached in this session names Qualcomm MDM9206 under the BG96 [7] and Qualcomm-signed baseband firmware in the EG25-G [6]; Quectel's own product pages do not name the silicon [4][5]. No MAC-randomization statement exists for a bare module. The CIRCL vulnerability index lists CVE-bearing firmware for the EG25-G, AG550QCN, RG502Q-EA and UC20 modules [9], and the vendor runs a PSIRT [10]; US national-security scrutiny of Quectel is reported elsewhere but no primary source for it was reachable here, so it is not asserted.
## Sources
1. About Quectel (company page) - Quectel - https://www.quectel.com/company/ (accessed 2026-10-27)
2. Contact Quectel (headquarters and offices) - Quectel - https://www.quectel.com/contact (accessed 2026-10-27)
3. Quectel home page (product categories, KG200Z, LC86L, QLM29Hx, QLM290P) - Quectel - https://www.quectel.com/ (accessed 2026-10-27)
4. LTE EC25 Series - Quectel - https://www.quectel.com/product/lte-ec25-series (accessed 2026-10-27)
5. Wi-Fi & Bluetooth FC41D - Quectel - https://www.quectel.com/product/wi-fi-bluetooth-fc41d/ (accessed 2026-10-27)
6. PinePhone - Wikipedia - https://en.wikipedia.org/wiki/PinePhone (accessed 2026-10-27)
7. List of Qualcomm Snapdragon modems - Wikipedia - https://en.wikipedia.org/wiki/List_of_Qualcomm_Snapdragon_modems (accessed 2026-10-27)
8. ThinkPad X1 series - Wikipedia - https://en.wikipedia.org/wiki/ThinkPad_X1_series (accessed 2026-10-27)
9. CVE search quectel (eg25-g_firmware, ag550qcn_firmware, rg502q-ea_firmware, uc20_firmware) - CIRCL vulnerability-lookup API (the product index was reachable; the individual CVE IDs were not shown by it) - https://cve.circl.lu/api/browse/quectel (accessed 2026-10-27)
10. Quectel Product Security / PSIRT - https://security.quectel.com/ (accessed 2026-10-27)
11. Quectel Wireless Solutions Co.,Ltd. MAC address blocks - maclookup.app - https://maclookup.app/vendors/quectel-wireless-solutions-co-ltd (accessed 2026-10-27)
12. Wikipedia search results for "Quectel" (Portable People Meter, PinePhone, ThinkPad entries) - https://en.wikipedia.org/w/index.php?search=Quectel&title=Special:Search (accessed 2026-10-27)
