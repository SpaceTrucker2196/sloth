---
name: Raspberry Pi Trading Ltd
aliases: [Raspberry Pi (Trading) Ltd]
affiliates: ["Raspberry Pi Foundation [1]"]
country: GB [1]
parent: Raspberry Pi Holdings plc, in which the Raspberry Pi Foundation remains a major shareholder [1]
founded: 2012 [1]
kind: brand
device_classes: []
found_in: ["Raspberry Pi 5 [3]", "Raspberry Pi 4 Model B [4]", "Raspberry Pi Pico W and Pico 2 W [5]"]
radios: ["Wi-Fi 5 (802.11ac) [3][4]", "Wi-Fi 4 (802.11n) on Pico W [5]", "2.4 GHz [4][5]", "5 GHz [3][4]", "Bluetooth 5.0 and BLE [3][4]", "Bluetooth 5.2 on Pico W and Pico 2 W [5]"]
silicon: ["Infineon CYW43439 in Raspberry Pi Pico W and Pico 2 W [5]", "Broadcom BCM2712 application processor in Raspberry Pi 5 [3]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Raspberry Pi (Trading) Ltd was set up in late 2012 as a wholly owned subsidiary of the Raspberry Pi Foundation, was renamed Raspberry Pi Ltd in 2021 and now sits under Raspberry Pi Holdings plc, headquartered in Cambridge, England, and listed on the London Stock Exchange since 2024 [1]. It designs and markets single-board computers, semiconductors and accessories under the Raspberry Pi brand, and the Foundation remains a major shareholder [1].

The registry holds the blocks under three names: four MA-L as Raspberry Pi Trading Ltd, three MA-L plus one MA-M and one MA-S as Raspberry Pi (Trading) Ltd, all at Cambridge addresses, and the older MA-L B8:27:EB as Raspberry Pi Foundation [2][6][7]. A MAC in any of them is almost certainly a Raspberry Pi board or a product built on one; the bootloader documentation notes that on the Raspberry Pi 4 and 5 the MAC address is no longer generated from the serial number, and that on BCM2712 devices the Ethernet, Wi-Fi and Bluetooth MAC addresses are set in OTP memory [8].

The Raspberry Pi 5 has dual-band 802.11ac Wi-Fi and Bluetooth 5.0 with BLE around a Broadcom BCM2712 processor [3]; the Raspberry Pi 4 Model B has 2.4 and 5 GHz 802.11ac and Bluetooth 5.0 with BLE [4]. The wireless Pico boards use the Infineon CYW43439, documented in the boards' key features as single-band 2.4 GHz 802.11n with Bluetooth 5.2, although the same page's models section says dual-band 802.11ac [5]. The wireless chip of the larger boards is not named on the pages consulted, the FCC ID databases refused the session that wrote this entry, and nothing is filled in from memory. Randomization depends on the operating system the board runs and is unknown here.

## Sources
1. Raspberry Pi Holdings - Wikipedia - https://en.wikipedia.org/wiki/Raspberry_Pi_Holdings (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Raspberry Pi 5 product page - https://www.raspberrypi.com/products/raspberry-pi-5/ (accessed 2026-10-27)
4. Raspberry Pi 4 Model B product page - https://www.raspberrypi.com/products/raspberry-pi-4-model-b/ (accessed 2026-10-27)
5. Pico-series microcontrollers documentation - https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html (accessed 2026-10-27)
6. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
7. IEEE Registration Authority, MA-S assignments (oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
8. Raspberry Pi computers documentation - https://www.raspberrypi.com/documentation/computers/raspberry-pi.html (accessed 2026-10-27)
