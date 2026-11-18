---
name: Espressif Inc.
aliases: []
affiliates: ["Espressif Systems (Singapore) Pte. Ltd [2]"]
country: CN [1]
parent: independent (listed on the Shanghai Stock Exchange STAR Market since July 2019) [1]
founded: 2008 [1]
kind: chip-vendor
device_classes: [iot-sensor, smart-home, module-in-other-brands]
found_in: ["Shelly Plus 1 smart relay (ESP32-U4WDH) [10]", "2861 ESP8266/ESP32-based smart-home devices catalogued by the Tasmota template repository, including Waveshare, Qubo, Shelly and Olimex products [11]", "coffee machines, light bulbs, smart-city and automation products, DIY hobbyist boards [1]"]
radios: ["Wi-Fi 4 (802.11 b/g/n) 2.4 GHz on ESP32-class modules (e.g. in Shelly Plus 1) [10]", "Wi-Fi 6 (802.11ax) 2.4 GHz on ESP32-C6 [4]", "Wi-Fi 6 dual-band 2.4 GHz + 5 GHz on ESP32-C5 [5]", "BLE 4.x/5.x: Bluetooth 4.2 on ESP32 (Shelly Plus 1) [10]; BLE 5 on ESP32-C6, ESP32-C5, ESP32-H2 [4][5][6]", "Thread/Zigbee (802.15.4) on ESP32-C6, ESP32-C5, ESP32-H2 [4][5][6]"]
silicon: ["ESP8266EX (Tensilica 160 MHz) [12]", "ESP32 (dual-core Xtensa 240 MHz, Wi-Fi + Bluetooth) [12]", "ESP32-S2 / ESP32-S3 (Xtensa) [12]", "ESP32-C2 / C3 / C5 / C6 / C61 / H2 / P4 / S31 (RISC-V) [12]", "ESP32-U4WDH in Shelly Plus 1 [10]", "Modules ESP32-WROOM-32D, ESP32-S3-WROOM-1U, ESP32-C3-MINI-1U, ESP8684-WROOM-02C [3]"]
fcc_grantee: ["2AC7Z (FCC-certified modules include ESP32-WROOM-32D, ESP32-S3-WROOM-1U, ESP32-C3-MINI-1U, ESP8684-WROOM-02C) [3]"]
randomization: fixed [7]
security_notes: ["Hardware security advisories AR2020-001 (fault injection on Flash Encryption and Secure Boot V1, CVE-2020-15048 / CVE-2020-13629), AR2022-003 (AES core of ESP32 v3.0), AR2023-005 (EMFI on secure boot / flash encryption), AR2023-007 (CPA and fault injection on ESP32-C3/C6), AR2026-005 (voltage fault injection on ESP32-S3) require physical access to the chip; AR2024-007 (ECDSA timing on ESP32-H2), AR2026-001 (XTS-AES CPA on ESP32-C5) and AR2026-006 (ECDSA secure boot on ESP32-H2/C5/C61/P4/S31) are cryptographic-implementation issues [8]", "Undocumented Bluetooth HCI debug commands in the original ESP32 (not in C/S/H series); Espressif states they cannot be triggered over Bluetooth, radio or the Internet [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Espressif Systems was founded on 28 April 2008 in Shanghai, listed on the STAR Market on 22 July 2019, and had shipped over one billion IoT chips by September 2023, making it the fifth-largest Wi-Fi microcontroller vendor [1]. In the IEEE registry copy shipped with sloth (ieee-data 20260625) it holds 319 MA-L blocks as "Espressif Inc.", 220 of them at a Road Town, Tortola (VG) address and 99 at a Shanghai one, and one as "Espressif Systems (Singapore) Pte. Ltd" at a Singapore address [2]. Because Espressif sells chips and modules rather than finished goods, a MAC in its blocks is almost always an IoT or smart-home device sold under another brand - the Tasmota template repository alone lists 2861 ESP8266/ESP32 devices [11], and Shelly documents an ESP32-U4WDH with 2.4 GHz 802.11 b/g/n and Bluetooth 4.2 in its Plus 1 relay [10]. The base MAC is burned into eFuse at the factory and is used as-is; Wi-Fi station uses the base MAC, SoftAP base+1, Bluetooth base+2 and Ethernet base+3, so one device can present several adjacent addresses [7]. That the address is fixed is inferred from this derivation: the page documents where the MAC comes from, not that no firmware randomises it, and an application can set a custom base MAC before its network interfaces start [7]. Older parts (ESP8266, ESP32, S2, S3) are Tensilica/Xtensa; the C-, H- and P-series and the S31 are RISC-V [12]. Expect 2.4 GHz Wi-Fi 4 from most fielded devices [10]; ESP32-C6 adds 2.4 GHz Wi-Fi 6, BLE 5 and 802.15.4 Thread/Zigbee [4], ESP32-C5 adds 5 GHz [5], and ESP32-H2 has BLE 5 and 802.15.4 but no Wi-Fi [6]. Modules are FCC-certified under grantee 2AC7Z [3]. Published security advisories are mostly hardware fault-injection and side-channel issues needing physical access, plus a few ECDSA and XTS-AES implementation issues [8]; the widely reported ESP32 Bluetooth "backdoor" is a set of local-only HCI debug commands, per Espressif not reachable over the air [9].
## Sources
1. Espressif Systems - Wikipedia - https://en.wikipedia.org/wiki/Espressif_Systems (accessed 2026-10-27)
2. IEEE Registration Authority MA-L registry (read from the copy shipped in sloth web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Certificates - Espressif Systems - https://www.espressif.com/en/support/documents/certificates (accessed 2026-10-27)
4. ESP32-C6 - Espressif Systems - https://www.espressif.com/en/products/socs/esp32-c6 (accessed 2026-10-27)
5. ESP32-C5 - Espressif Systems - https://www.espressif.com/en/products/socs/esp32-c5 (accessed 2026-10-27)
6. ESP32-H2 - Espressif Systems - https://www.espressif.com/en/products/socs/esp32-h2 (accessed 2026-10-27)
7. Miscellaneous System APIs: MAC Address - ESP-IDF Programming Guide - https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/misc_system_api.html (accessed 2026-10-27)
8. Security Advisories - Espressif Systems - https://www.espressif.com/en/support/documents/advisories (accessed 2026-10-27)
9. Espressif's Response to Undocumented Commands in ESP32 Bluetooth - https://www.espressif.com/en/news/Response_ESP32_Bluetooth (accessed 2026-10-27)
10. Shelly Plus 1 - Shelly Knowledge Base - https://kb.shelly.cloud/knowledge-base/shelly-plus-1 (accessed 2026-10-27)
11. Tasmota Supported Devices Repository - https://templates.blakadder.com/ (accessed 2026-10-27)
12. SoCs - Espressif Systems - https://www.espressif.com/en/products/socs (accessed 2026-10-27)
