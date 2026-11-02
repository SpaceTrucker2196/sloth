---
name: "Murata Manufacturing Co., Ltd."
aliases: ["Murata Manufacturing CO., Ltd."]
country: JP [1]
parent: independent [1]
founded: 1944 [1]
kind: module-maker
device_classes: [module-in-other-brands, phone, iot-sensor, tv]
found_in: ["Apple iPhone 4S, iPhone 8 / 8 Plus / X [8]", "Apple TV 4K [8]", "Samsung Galaxy S3, S4, S8, S10 [8]", "Apple iPhone 6s (Murata 240 front-end module) [9]", "NXP i.MX Linux hosts via Embedded Artists Type 1YN M.2 module [6]"]
radios: ["Wi-Fi 4 (802.11a/b/g/n) [4][5]", "Wi-Fi 5 (802.11ac 2x2 MIMO) [4]", "Wi-Fi 6 (802.11ax, Type 2EL) [7]", "2.4 GHz [4]", "5 GHz [4]", "BT Classic (BR/EDR 4.1-5.4) [4][5][7]", "BLE 4.x/5.x (5.1 on 1YN, 5.2 on 1XK, 5.4 on 2EL) [5][6][7]", "Thread/Zigbee (802.15.4, Type 2EL) [7]"]
silicon: ["NXP IW416 in Type 1XK (LBEE5CJ1XK) [5]", "Infineon CYW43439 in Type 1YN (LBEE5KL1YN) [6]", "NXP IW612 in Type 2EL [7]", "Cypress/Infineon CYW54907, CYW43907, CYW4356, CYW43340, CYW43455, CYW4343W, CYW43438, CYW43012 across Types 1PS/1GC/1CX/1BW/1MW/1DX/1LD/1MD/YD/1HD/1FX/1CD/1LV [8]", "Murata 240 front-end module in iPhone 6s [9]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Murata Manufacturing is an independent Japanese components maker founded in October 1944, headquartered in Nagaokakyo, Kyoto, listed on the Tokyo Stock Exchange (6981), with about 72,500 employees in 2025 [1]. Alongside its core ceramic capacitors it sells communication modules including Bluetooth and short-range wireless modules, and it bought RF Monolithics (2012), Peregrine Semiconductor (2014) and Resonant (2022) for RF technology [1]. It holds 79 IEEE blocks (MA-L and MA-S), the oldest 00:60:57 from 1998, registered to a Yokohama address [2][3]; one MA-S block carries the spelling "Murata Manufacturing CO., Ltd.", which this entry lists as an alias. A MAC in a Murata block is almost never a "Murata device": it is a Murata Wi-Fi/Bluetooth module soldered into someone else's product, so the brand on the box is the thing to find. Murata's module lineup covers 802.11a/b/g/n/ac 2x2 and Bluetooth 4.1-5.1 BR/EDR/LE on 2.4 and 5 GHz, grouped by chipset vendor (Infineon, NXP, TI, Qualcomm) [4]; documented examples are Type 1XK on NXP IW416 (802.11a/b/g/n, BT 5.2, marked to-be-discontinued) [5], Type 1YN on Infineon CYW43439 (802.11b/g/n, BT 5.1, for NXP i.MX Linux/FreeRTOS and WICED hosts) [6], and Type 2EL on NXP IW612 (Wi-Fi 6 dual-band, BT 5.4, 802.15.4 for Thread/Zigbee) [7]. DeviWiki lists the Cypress-based families (CYW43455, CYW4343W, CYW43438, CYW43012 and others) and places Murata modules in Apple iPhones 4S/8/X, Apple TV 4K and Samsung Galaxy S3-S10 [8]; iFixit identifies a Murata front-end module in the iPhone 6s [9]. Phones carrying Murata modules will show the phone OS's randomization behaviour rather than a Murata block, so a Murata OUI seen on the air is more likely an embedded or IoT host that uses its burned-in address. Murata states its modules are FCC/IC "reference" certified but the product pages reached do not print the FCC ID, and the FCC ID mirrors returned 403, so the grantee code is left empty rather than recalled. No vendor security advisories were found in the sources reached.
## Sources
1. Wikipedia - Murata Manufacturing - https://en.wikipedia.org/wiki/Murata_Manufacturing (accessed 2026-10-27)
2. maclookup.app - Murata Manufacturing vendor page - https://maclookup.app/vendors/murata-manufacturing-co-ltd (accessed 2026-10-27)
3. maclookup.app - OUI 00:60:57 registration - https://maclookup.app/macaddress/006057 (accessed 2026-10-27)
4. Murata - Wi-Fi/Bluetooth connectivity modules overview - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth (accessed 2026-10-27)
5. Murata - Type 1XK - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type1xk (accessed 2026-10-27)
6. Murata - Type 1YN - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type1yn (accessed 2026-10-27)
7. Murata - Type 2EL - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type2el (accessed 2026-10-27)
8. DeviWiki - Murata - https://deviwiki.com/wiki/Murata (accessed 2026-10-27)
9. iFixit - iPhone 6s Teardown, step 20 - https://www.ifixit.com/Teardown/iPhone+6s+Teardown/48170 (accessed 2026-10-27)
