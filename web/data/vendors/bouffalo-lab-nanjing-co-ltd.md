---
name: "Bouffalo Lab (Nanjing) Co., Ltd."
aliases: []
affiliates: []
country: CN [1][2]
parent: unknown
founded: 2016 [2]
kind: chip-vendor [2]
device_classes: [smart-home [2], iot-sensor [3]]
found_in: ["Pine64 PineCone BL602 evaluation board [4]"]
radios: ["Wi-Fi 4 [3][4]", "2.4 GHz [3][4]", "BLE 4.x/5.x [3][4]", "Thread/Zigbee (802.15.4) [2]", "Wi-Fi 6 [2]"]
silicon: ["BL602 RISC-V Wi-Fi 4 and Bluetooth LE 5.0 SoC in the Pine64 PineCone [3][4]", "BL702 and BL706 Zigbee 3.0 plus BLE 5.0 chips [2]", "BL606P dual-core Wi-Fi, Bluetooth, BLE and Zigbee chip [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Bouffalo Lab (Nanjing) is a chip design company established in Nanjing
in 2016, located in the Jiangbei New District, developing low-power IoT
and edge computing SoCs and promoting Matter for the smart home [2].
The IEEE registry lists 23 MA-L blocks to it at Nanjing addresses [1].
Its BL602 and BL604 pair a 32-bit RISC-V core with 802.11b/g/n Wi-Fi 4
on 2.4 GHz and Bluetooth 5.0 LE for low-power IoT, pitched at the
ESP8266's price point [3]; the BL702 and BL706 combine Zigbee 3.0 with
BLE 5.0, the BL606P adds Wi-Fi, Bluetooth and Zigbee on one dual-core
chip, and the company's timeline announces a Wi-Fi 6 low-power chip
[2].

A MAC in a Bouffalo block can be an IoT device or board built around one of these chips; Pine64's PineCone is a BL602
evaluation board with 802.11b/g/n, STA, SoftAP and sniffer modes and
Bluetooth LE 5.0 [4]. A search for advisories naming Bouffalo Lab or
the BL602 found none, so security_notes is empty rather than clean. Parent company, randomization and FCC grantee codes are unknown:
the FCC ID databases refused the session that wrote this entry, and
nothing is filled in from memory.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Bouffalo Lab company site - https://en.bouffalolab.com/ (accessed 2026-10-27)
3. BL602/BL604 RISC-V WiFi and Bluetooth 5.0 LE SoC will sell at ESP8266 price point - CNX Software - https://www.cnx-software.com/2020/10/24/bl602-bl604-risc-v-wifi-bluetooth-5-0-le-soc-will-sell-at-esp8266-price-point/ (accessed 2026-10-27)
4. PineCone - PINE64 wiki - https://wiki.pine64.org/wiki/PineCone (accessed 2026-10-27)
