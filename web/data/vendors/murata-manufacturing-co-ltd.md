---
name: "Murata Manufacturing Co., Ltd."
aliases: ["Murata Manufacturing CO., Ltd."]
country: JP [1]
parent: independent [1]
founded: 1944 [1]
kind: module-maker [7]
device_classes: [module-in-other-brands [7], iot-sensor [6], smart-home [4], phone [8]]
found_in: ["Apple iPhone X Wi-Fi/Bluetooth module, labelled Apple/Murata USI 339S00397 [8]", "Apple iPhone 6s (a Murata circuit) [1]"]
radios: ["Wi-Fi 4/5/6 [3][4][5][6][7]", "2.4 GHz [3][6]", "5 GHz [3][6]", "BT Classic [3][4][6]", "BLE 4.x/5.x [3][4][5][6]", "Thread/Zigbee (802.15.4) [6]"]
silicon: ["Infineon CYW43455 in Type 1MW (LBEE5HY1MW) [3]", "Infineon CYW4373E in Type 2AE (LBEE5PK2AE) [4]", "Infineon CYW43012 in Type 1LV (LBEE59B1LV) [5]", "NXP IW612 in Type 2EL (LBES5PL2EL) [6]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Murata Manufacturing is a Japanese electronic-component maker founded
in October 1944 by Akira Murata, headquartered in Nagaokakyo, Kyoto,
and listed on the Tokyo Stock Exchange; alongside its ceramic
capacitors it sells communication modules, including Bluetooth and
short-range wireless modules [1]. It holds 75 MA-L blocks registered to
its Nagaokakyo address and two MA-S blocks registered from Yokohama and
Yasu, the second of them under the spelling "Murata Manufacturing CO.,
Ltd." [2][9]. A MAC in a Murata block is almost always a Murata
Wi-Fi/Bluetooth module soldered into another brand's product, so the
OUI names the module maker, not the device: Murata's lineup is built
on Infineon, NXP, TI and Qualcomm chipsets and spans 802.11a/b/g/n/ac
up to 2x2 MIMO and Bluetooth 4.1 to 5.1 [7], with Wi-Fi 6 and 802.15.4
in the NXP IW612-based Type 2EL [6].

The documented silicon is Infineon CYW43455 in the Type 1MW (802.11ac
plus Bluetooth 5.0, now not recommended for new designs, replaced by
the Type 2AE and 2BC) [3], CYW4373E in the Type 2AE (802.11ac 1x1 plus
Bluetooth 5.2) [4], CYW43012 in the Type 1LV (802.11a/b/g/n plus
Bluetooth 5.0) [5] and NXP IW612 in the Type 2EL (802.11ax 1x1 on 2.4
and 5 GHz plus Bluetooth 5.4 plus 802.15.4) [6]. Murata's stated
markets are industrial IoT, smart home, sensor networks, audio/video
and gateways [3][4][5][6], and iFixit's iPhone X teardown labels that
phone's Wi-Fi/Bluetooth module "Apple/Murata USI 339S00397", so an
Apple phone can carry a Murata block too, though the label leaves the
module's maker ambiguous between Murata and USI [8]. Whether a device
randomises its address is the host operating system's doing, not the
module's, so randomization is unknown here. FCC grantee codes are not
listed: the FCC ID databases were not reachable from the session that
wrote this entry, and nothing is filled in from memory.

## Sources

1. Murata Manufacturing - Wikipedia - https://en.wikipedia.org/wiki/Murata_Manufacturing (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Murata Type 1MW (LBEE5HY1MW) Wi-Fi/Bluetooth module - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type1mw (accessed 2026-10-27)
4. Murata Type 2AE (LBEE5PK2AE) Wi-Fi/Bluetooth module - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type2ae (accessed 2026-10-27)
5. Murata Type 1LV (LBEE59B1LV) Wi-Fi/Bluetooth module - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type1lv (accessed 2026-10-27)
6. Murata Type 2EL (LBES5PL2EL) Wi-Fi 6/Bluetooth/802.15.4 module - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth/overview/lineup/type2el (accessed 2026-10-27)
7. Murata Wi-Fi/Bluetooth modules overview - https://www.murata.com/en-us/products/connectivitymodule/wi-fi-bluetooth (accessed 2026-10-27)
8. iPhone X Teardown - iFixit - https://www.ifixit.com/Teardown/iPhone+X+Teardown/98975 (accessed 2026-10-27)
9. IEEE Registration Authority, MA-S assignments (oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
