---
name: Ezurio, LLC
aliases: []
affiliates: []
country: US [1][2]
parent: "Audax Private Equity (acquired July 2022) [2]"
founded: 2004 [2]
kind: module-maker
device_classes: [medical, industrial, iot-sensor, module-in-other-brands]
found_in: ["Medical, industrial and commercial OEM products embedding Ezurio (ex-Laird Connectivity) RF modules [2]", "Ezurio Nitrogen8M/8M Plus/8M Mini/91/93/95 SMARC SOMs (NXP i.MX) with optional Sona Wi-Fi 6/6E, Summit SOM 8M Plus with 60 Series Wi-Fi 5, Carbon AM62/AM67 OSM (TI), Tungsten510/700 SMARC (MediaTek Genio) with optional Sona MT320 [5]"]
radios: ["Wi-Fi 4 (Sterling-LWB/LWB+, 50 Series, 45 Series) [4]", "Wi-Fi 5 (Sterling-LWB5+, 60-2230C) [4][6]", "Wi-Fi 6 (Sona MT320, Sona TI351, Sona NX611, Veda IF912, Veda SL917) [4]", "Wi-Fi 6E (Sona IF513, Sona IF573, Veda IF913) [4][7]", "Wi-Fi 7 (Sona IF703, Sona IF713) [4]", "2.4 GHz [6]", "5 GHz [6]", "6 GHz (Sona IF573, up to 7.125 GHz) [7]", "BT Classic / BLE 5.x (Bluetooth 5.2 on Sterling-LWB5+; Bluetooth 5.4 on Sona MT320, Sona NX611 and Veda IF912/IF913/SL917) [4][6]", "BLE 6.0 (Sona IF513, IF573, IF703, IF713) [4][7]", "Thread/Zigbee (802.15.4) on Sona IF713 [4]", "Cellular and LoRaWAN (listed as module categories; generations not stated) [2][3]", "UWB (listed as a module category) [2][3]"]
silicon: ["Infineon/Cypress CYW4373E in Sterling-LWB5+ [6]", "Infineon CYW4343W in Sterling-LWB, CYW43439 in Sterling-LWB+ [4]", "Infineon CYW55513 in Sona IF513, CYW55573 in Sona IF573 [4][7]", "Infineon AIROC ACW7410 in Sona IF703, ACW7411 in Sona IF713 [4]", "Infineon CYW55912 in Veda IF912, CYW55913 in Veda IF913 [4]", "MediaTek MT921 in Sona MT320 [4]", "TI CC3351 in Sona TI351 [4]", "NXP IW611 in Sona NX611, NXP 88W8997 in 60-2230C [4]", "Silicon Labs SiWx917 in Veda SL917 [4]", "Qualcomm Atheros AR6004 in 50 Series, AR6003 in 45 Series [4]", "NXP i.MX 8M/91/93/95, TI AM62/AM67, MediaTek Genio 510/700 in Nitrogen/Carbon/Tungsten SOMs [5]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
Ezurio is the March 2024 rebrand of Laird Connectivity merged with Boundary Devices: the business began in the UK in 2004 as a Bluetooth/Wi-Fi specialist, was bought by Laird Technologies in 2008, went private with Laird plc under Advent in 2018, was sold to Audax Private Equity in July 2022 and bought SOM maker Boundary Devices in December 2022; it is headquartered in Akron, Ohio [2][3]. It holds seven MA-L blocks (00:25:CA from 2010, then C0:EE:40, 18:C2:93, EC:C0:7A, D8:03:1A, B0:FB:15 and E8:CB:F5), all re-registered under the Ezurio name at a Cedarburg, Wisconsin address and last updated in November 2025 [1][8]. A MAC in any of them is an Ezurio module soldered into another brand's product, overwhelmingly medical, industrial or commercial IoT equipment and the SMARC/OSM SOMs it sells to OEMs [2][5]. The current module line is almost entirely Infineon AIROC silicon, from the 2.4 GHz-only Sterling-LWB (CYW4343W) through the Sterling-LWB5+ (CYW4373E, Wi-Fi 5, Bluetooth 5.2) to the Sona IF573 (CYW55573, Wi-Fi 6E 2x2 across 2.4/5/6 GHz, Bluetooth 6.0) and the Wi-Fi 7 Sona IF703/IF713, with MediaTek, TI, NXP and Silicon Labs parts filling out the Wi-Fi 6 tier [4][6][7]. On the air these are long-lived clients with factory MACs; expect WPA2/WPA3 personal or enterprise and often industrial temperature-rated hardware in hospitals and plants [6][7]. Every product page lists FCC certification but gives no FCC ID, and the FCC ID databases returned HTTP 403 in this session, so the grantee code is not recorded; no vendor security advisories were found, and the company advertises a backported Linux driver stack with bi-annual CVE releases [6].
## Sources
1. MAC prefix 00:25:CA - maclookup.app - https://maclookup.app/macaddress/0025CA (accessed 2026-10-27)
2. Ezurio - Wikipedia - https://en.wikipedia.org/wiki/Ezurio (accessed 2026-10-27)
3. About Us - Ezurio - https://www.ezurio.com/about-us (accessed 2026-10-27)
4. Wi-Fi + Bluetooth modules - Ezurio - https://www.ezurio.com/wireless-modules/wifi-modules-bluetooth (accessed 2026-10-27)
5. System on Module - Ezurio - https://www.ezurio.com/system-on-module (accessed 2026-10-27)
6. Sterling-LWB5+ Wi-Fi 5 + Bluetooth 5.2 module - Ezurio - https://www.ezurio.com/wireless-modules/wifi-modules-bluetooth/sterling-lwb5-plus-wifi-5-bluetooth-5-module (accessed 2026-10-27)
7. Sona IF573 Wi-Fi 6E + Bluetooth module - Ezurio - https://www.ezurio.com/wireless-modules/wifi-modules-bluetooth/sona-if573-wi-fi-6e-bluetooth-5-4-module (accessed 2026-10-27)
8. Ezurio, LLC MAC address blocks - maclookup.app - https://maclookup.app/vendors/ezurio-llc (accessed 2026-10-27)
