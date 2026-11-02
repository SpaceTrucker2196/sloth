---
name: NXP Semiconductor (Tianjin) LTD.
aliases: []
country: CN [1]
parent: NXP Semiconductors N.V., Eindhoven, which lists Tianjin among its test and assembly sites [2]
founded: unknown
kind: chip-vendor [2]
device_classes: [unknown]
found_in: []
radios: ["Wi-Fi 6 [3]", "2.4 GHz [3]", "5 GHz [3]", "BLE 4.x/5.x [3][4]", "Thread/Zigbee (802.15.4) [3]"]
silicon: ["IW612 Wi-Fi 6, Bluetooth LE and 802.15.4 tri-radio chip for IoT and industrial designs [3]", "KW41Z Bluetooth Low Energy device [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-17519 (SweynTooth): the NXP SDK BLE stack through 2.2.1 for KW41Z does not limit Link Layer payload length, so a nearby attacker can overflow a buffer [4][5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

NXP Semiconductor (Tianjin) holds 23 MA-L blocks in the IEEE registry,
all registered to an address in the Xiqing Economic Development Area,
Tianjin, China [1]. NXP Semiconductors is a Dutch semiconductor company
spun off from Philips in 2006, headquartered at the High Tech Campus in
Eindhoven and listed on Nasdaq as NXPI; its test and assembly sites
include Tianjin, and in December 2019 it completed the purchase of
Marvell's wireless connectivity assets [2]. No source consulted names a device that carries these specific blocks, so found_in is empty [1].

NXP's current IoT connectivity chip IW612 combines 1x1 dual-band Wi-Fi
6 on 2.4 and 5 GHz, Bluetooth LE certified to 5.4 and 802.15.4 for
Thread and Zigbee, aimed at smart home, industrial and gateway designs
[3]. The SweynTooth disclosure lists NXP among the affected Bluetooth
LE vendors, naming the KW41Z [5]; CVE-2019-17519 records that the BLE
stack in the NXP SDK through 2.2.1 for KW41Z does not limit Link Layer
payload length, allowing a nearby attacker to overflow a buffer [4].

The founding year of the Tianjin entity is not documented in the
sources consulted, randomization is unknown, and FCC grantee codes are
not listed because the FCC ID databases refused the session that wrote
this entry.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. NXP Semiconductors - Wikipedia - https://en.wikipedia.org/wiki/NXP_Semiconductors (accessed 2026-10-27)
3. IW612 product page - NXP - https://www.nxp.com/products/IW612 (accessed 2026-10-27)
4. CVE-2019-17519 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2019-17519 (accessed 2026-10-27)
5. SweynTooth Bluetooth Low Energy attacks - GitHub - https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks (accessed 2026-10-27)
