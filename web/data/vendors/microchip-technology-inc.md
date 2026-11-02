---
name: Microchip Technology Inc.
aliases: ["Microchip Technologies Inc"]
country: US [1][2]
parent: independent, public on Nasdaq as MCHP [1]
founded: 1989 [1]
kind: chip-vendor [1]
device_classes: [module-in-other-brands [3]]
found_in: ["Adafruit ATWINC1500 WiFi Breakout (product 2999) [3]"]
radios: ["Wi-Fi 4 [3]", "BLE (version not stated) on ATSAMB11 [4]"]
silicon: ["ATWINC1500 in the ATWINC1500-MR210PB module on the Adafruit breakout [3]", "ATSAMB11 Bluetooth Low Energy chip with the BluSDK Smart stack [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-19195 (SweynTooth): BluSDK Smart through 6.2 on ATSAMB11 does not check incoming link-layer data size, so an attacker in radio range can crash the device [4][5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Microchip Technology is an American semiconductor company headquartered in Chandler, Arizona, founded in February 1989 out of the microelectronics division General Instrument had spun off, and listed on Nasdaq as MCHP; it
makes 8-, 16- and 32-bit PIC and AVR microcontrollers, serial EEPROMs
and analog ICs [1]. It bought Atmel in January 2016 and ZeroG Wireless
in January 2010, the latter to provide Wi-Fi for its PIC
microcontrollers [1]. The IEEE registry lists 16 MA-L blocks to
"Microchip Technology Inc." and four MA-L blocks plus one MA-S block to
"Microchip Technologies Inc", all at 2355 W Chandler Blvd, Chandler
[2][6].

A MAC in a Microchip block can be a Microchip Wi-Fi module inside another product: Adafruit
sells a breakout carrying the ATWINC1500-MR210PB, an FCC-certified
802.11b/g/n module that Adafruit describes as Atmel's [3]. Microchip's
ATSAMB11 Bluetooth Low Energy chip runs the BluSDK Smart stack, which
through version 6.2 does not check the size of incoming link-layer
data, so a crafted packet from within radio range crashes the device
(CVE-2019-19195) [4]; the SweynTooth disclosure lists Microchip among
the affected vendors [5].

Randomization is unknown, and FCC grantee codes are not listed: the
FCC ID databases and Microchip's own product pages refused the session
that wrote this entry, and nothing is filled in from memory.

## Sources

1. Microchip Technology - Wikipedia - https://en.wikipedia.org/wiki/Microchip_Technology (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Adafruit ATWINC1500 WiFi Breakout - Adafruit - https://www.adafruit.com/product/2999 (accessed 2026-10-27)
4. CVE-2019-19195 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2019-19195 (accessed 2026-10-27)
5. SweynTooth Bluetooth Low Energy attacks - GitHub - https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks (accessed 2026-10-27)
6. IEEE Registration Authority, MA-S assignments (oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
