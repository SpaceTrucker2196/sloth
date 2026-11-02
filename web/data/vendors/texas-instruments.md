---
name: Texas Instruments
aliases: []
country: US [1]
parent: "none (publicly traded, Nasdaq: TXN) [1]"
founded: 1951 [1]
kind: chip-vendor
device_classes: [iot-sensor, smart-home, industrial, medical, module-in-other-brands, ap/router]
found_in: ["Cisco Aironet 1540/1800i/1810/1815/4800 and Meraki MR30H/MR33/MR74/MR42E/MR53E access points (CC2640/CC2650 BLE radios) [9]", "Original Amazon Echo (TI DM3725 application processor) [10]", "Grid infrastructure, building automation, retail automation, personal electronics and medical devices (CC2652R7 target markets) [6]"]
radios: ["Wi-Fi 4 (802.11a/b/g/n dual-band, CC3235MOD and WL1837MOD) [7][8]", "Wi-Fi 6 (802.11ax: 2.4 GHz on CC3301, dual-band 2.4/5 GHz on CC3551E) [4][5]", "2.4 GHz [5][6][7]", "5 GHz [7][8]", "BT Classic (WL1837MOD dual-mode Bluetooth 5.1) [8]", "BLE 5.x (BLE 5.4 on CC3301; BLE on CC2652R7, CC2340R5, CC2755R10) [4][5][6]", "Thread/Zigbee (802.15.4, Zigbee 3.0, Thread, Matter, 6LoWPAN on CC2652R7) [6]", "Sub-1 GHz (offered in the wireless portfolio; CC1354P10 multiband MCU) [4]"]
silicon: ["SimpleLink CC3301 Wi-Fi 6 + BLE 5.4 companion IC [5]", "SimpleLink CC2652R7 multiprotocol 2.4 GHz wireless MCU [6]", "SimpleLink CC3235MODSF dual-band Wi-Fi CERTIFIED module [7]", "WiLink 8 WL1837MOD 2x2 Wi-Fi + Bluetooth module [8]", "CC2340R5 and CC2755R10 Bluetooth/Zigbee/Thread wireless MCUs, CC3551E Wi-Fi 6 + BLE, CC1354P10 multiband [4]", "CC2640 / CC2650 BLE chips inside Cisco and Meraki APs [9]", "DM3725 Cortex-A8 in original Amazon Echo [10]"]
fcc_grantee: []
randomization: unknown
security_notes: ["BleedingBit: CVE-2018-16986 memory corruption when CC2640/CC2650 process malformed BLE frames, enabling code execution on nearby Cisco Aironet and Meraki APs (disclosed 2018-11-01) [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Texas Instruments is a publicly traded US semiconductor company founded in 1951 (from Geophysical Service Inc., 1930), headquartered in Dallas and listed on Nasdaq as TXN [1]; its 401 IEEE MA-L blocks, among them 00:12:37, 00:12:4B and the 1998-vintage 08:00:28, are registered to 12500 TI Boulevard, Dallas [2][3]. TI sells wireless MCUs and modules for Wi-Fi, Bluetooth, Sub-1 GHz, Zigbee, Thread and Matter [4], so a MAC in a TI block is most likely an embedded radio in someone else's product rather than a TI-branded device (an inference from the product line). On 2.4 GHz expect either a SimpleLink Wi-Fi part, such as the CC3301 Wi-Fi 6 + BLE 5.4 companion IC for Linux/RTOS hosts [5] or the dual-band 802.11a/b/g/n CC3235MOD module with a FIPS 140-2 validated IC [7], or a multiprotocol MCU such as the CC2652R7 running BLE, Zigbee 3.0, Thread, Matter or 6LoWPAN for grid, building-automation, retail, personal-electronics and medical products [6]; industrial designs use the WiLink 8 WL1837MOD 2x2 Wi-Fi + Bluetooth 5.1 module rated to +85 C [8]. TI BLE silicon also sits inside enterprise access points: Cisco's 2018 advisory names CC2640/CC2650 in Aironet and Meraki APs for CVE-2018-16986 (BleedingBit), where a malformed BLE frame from a nearby attacker could cause code execution [9], and the first Amazon Echo used a TI DM3725 application processor [10]. No documentation of MAC randomization by TI stacks was found, so that field is left unknown. TI module datasheets state FCC, IC/ISED, ETSI/CE, MIC and SRRC certification but the CC3235MODSF datasheet text does not print the FCC ID, so the grantee code is left empty [7][11].
## Sources
1. Wikipedia - Texas Instruments - https://en.wikipedia.org/wiki/Texas_Instruments (accessed 2026-10-27)
2. maclookup.app - Texas Instruments vendor page - https://maclookup.app/vendors/texas-instruments (accessed 2026-10-27)
3. maclookup.app - OUI 08:00:28 registration - https://maclookup.app/macaddress/080028 (accessed 2026-10-27)
4. Texas Instruments - Wireless connectivity overview - https://www.ti.com/wireless-connectivity/overview.html (accessed 2026-10-27)
5. Texas Instruments - CC3301 product page - https://www.ti.com/product/CC3301 (accessed 2026-10-27)
6. Texas Instruments - CC2652R7 product page - https://www.ti.com/product/CC2652R7 (accessed 2026-10-27)
7. Texas Instruments - CC3235MODSF product page - https://www.ti.com/product/CC3235MODSF (accessed 2026-10-27)
8. Texas Instruments - WL1837MOD product page - https://www.ti.com/product/WL1837MOD (accessed 2026-10-27)
9. Cisco Security Advisory cisco-sa-20181101-ap (BleedingBit, CVE-2018-16986) - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181101-ap (accessed 2026-10-27)
10. Wikipedia - Amazon Echo - https://en.wikipedia.org/wiki/Amazon_Echo (accessed 2026-10-27)
11. Texas Instruments - CC3235MODx datasheet SWRS243C - https://www.ti.com/lit/ds/symlink/cc3235modsf.pdf (accessed 2026-10-27)
