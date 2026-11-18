---
name: Tuya Smart Inc.
aliases: []
affiliates: []
country: CN [1]
parent: "Tuya Inc. (Cayman-incorporated; NYSE: TUYA, HKEX: 2391) [1][3]"
founded: 2014 [1][3]
kind: module-maker
device_classes: [smart-home, iot-sensor, camera, module-in-other-brands]
found_in: ["White-label smart plugs, bulbs, switches and sensors from many brands built on Tuya WB/CB/WBR modules (the OpenBeken replacement-firmware targets) [4][5]", "KERUI HD 3MP camera and KERUI K259 camera (Tuya platform, CVE-2024-48214 / CVE-2025-63296) [6]", "LSC Indoor PTZ camera (CVE-2025-25680) [6]", "WOLFBOX Level 2 EV charger (CVE-2025-5748 / -5750) [6]", "Tuya Smart Camera U6N (CVE-2024-32268) [6]", "Platform partners Schneider Electric, Lenovo and Philips [1]"]
radios: ["Wi-Fi on the Beken, Realtek and Lightning module chips (802.11 generation and band not stated in the sources) [4][5]", "BLE marked as supported for the BK7231T/N, LN882H, RTL8710B and RTL8720C chip families [5]"]
silicon: ["Beken BK7231T in WB3S / WB2S / WB2L modules [4]", "Beken BK7231N in CB3S / CB2S / CB2L / CBU and T34 modules [4][5]", "Realtek RTL8710B in WR3E / WR2 modules [4]", "Realtek RTL8720C / RTL8710C in WBR3 and W701 modules [4]", "Realtek RTL8720D in BW16 / WBR3D modules [4]", "Lightning LN882H in WL2H-U module [5]", "Bouffalo Lab BL602 in BW2L module [4]", "XR809 in XR3 module [4]", "TR6260 in HLK-M20 module [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Dark Cubed, 2021: Tuya-connected devices subject to China's Data Security Law; concerns over data transmission practices [1]", "Repeated QR-code Wi-Fi-provisioning command injection in Tuya-platform cameras (CVE-2024-48214 KERUI, CVE-2025-25680 LSC) [6]", "CVE-2025-56557 unprivileged control of Matter devices via the Matter protocol in Smart Life app 5.6.1; CVE-2025-56400 OAuth CSRF in Tuya SDK 6.5.0 [6]", "CVE-2024-3764 (disputed) denial of service via the MQTT packet handler in Tuya SDK up to 5.0.x, and CVE-2026-3465 (disputed) denial of service via a JSON data-point handler in the Tuya App and SDK [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Tuya is a Hangzhou, China IoT platform and connectivity-module vendor founded on 16 June 2014 by Xueji (Jerry) Wan, incorporated in the Cayman Islands and dual-listed on the NYSE (TUYA, March 2021 IPO raising $915M) and HKEX (2391, July 2022) [1][3]. It shipped its first Wi-Fi module in April 2015 and today claims 2,092,000+ registered developers, about 5,800 customers and 3,000+ product categories, so the brand on the box is almost never Tuya itself [3]. The IEEE registrant "Tuya Smart Inc." is the US entity at 160 Greentree Drive, Dover, Delaware, as the 10:5A:17 MA-L record shows [2]. A MAC in these blocks is plausibly a white-label smart plug, bulb, switch, sensor or camera containing a Tuya module, an inference from the product line: the module families documented by the replacement-firmware projects are Beken BK7231T (WB3S/WB2S/WB2L), BK7231N (CB3S/CB2S/CBU/T34), Realtek RTL8710B (WR3E), RTL8720C (WBR3), RTL8720D (BW16) and Lightning LN882H (WL2H-U), with BLE marked as supported for the Beken, Lightning and Realtek families [4][5]; the sources do not state the 802.11 generation or band. No Zigbee or Thread module is documented in the sources reached here, so none is listed. The Tuya SDK carries an MQTT packet handler (CVE-2024-3764) [6], and the 2021 Dark Cubed report plus the recurring QR-code provisioning command-injection CVEs in Tuya-platform cameras are the security notes an operator should weigh [1][6]. FCC grantee codes and MAC randomization are not documented in the sources reached, so both are left empty or unknown rather than recalled.
## Sources
1. Tuya Inc. - Wikipedia - https://en.wikipedia.org/wiki/Tuya_Inc. (accessed 2026-10-27)
2. maclookup.app 10:5A:17 registrant record - https://maclookup.app/macaddress/105A17 (accessed 2026-10-27)
3. Tuya, About Us - https://www.tuya.com/about (accessed 2026-10-27)
4. OpenBK7231T_App (OpenBeken) README, module-to-chip table - https://github.com/openshwprojects/OpenBK7231T_App (accessed 2026-10-27)
5. LibreTiny docs, Supported families and boards - https://docs.libretiny.eu/docs/status/supported/ (accessed 2026-10-27)
6. NVD CVE API, keyword "tuya" (11 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=tuya&resultsPerPage=20 (accessed 2026-10-27)
