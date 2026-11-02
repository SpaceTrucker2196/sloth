---
name: u-blox AG
aliases: []
country: CH [1]
parent: "Advent International (acquisition completed 2025-11-26) [1]"
founded: 1997 [1]
kind: module-maker
device_classes: [iot-sensor, industrial, automotive-telematics, pos, medical, module-in-other-brands]
found_in: ["Application areas named by u-blox for NINA-W10: telematics, low-power sensors, connected factories, connected buildings (appliances and surveillance), point-of-sale, health devices [2]"]
radios: ["Wi-Fi 4 (802.11b/g/n) 2.4 GHz, NINA-W10 [2]", "2.4 GHz [2]", "BT Classic (BR/EDR) 4.2, NINA-W10 [2]", "BLE 4.x (Bluetooth 4.2 LE), NINA-W10 [2]", "LTE/5G (GSM/UMTS/CDMA2000/LTE cellular modules) [1]", "GNSS receivers (GPS, GLONASS, Galileo, BeiDou, QZSS) [1]"]
silicon: ["Espressif ESP32 in NINA-W10 series (NINA-W101/W102/W106) [2]"]
fcc_grantee: ["XPY (FCC ID XPYNINAW10 / XPYNINAW106 on NINA-W10 series) [2]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
u-blox AG is a Thalwil, Switzerland wireless-semiconductor and module company founded in 1997 as an ETH Zurich spin-off; it sells GNSS receivers, cellular (GSM/UMTS/CDMA2000/LTE) modules and Bluetooth/Wi-Fi short-range modules for location-based services and M2M/IoT, and since 26 November 2025 it is owned by private-equity firm Advent International [1]. Its short-range business was assembled by acquisition: connectBlue (2014), Lesswire (2015), Rigado's Bluetooth module business (2019) and others [1], which is consistent with its oldest MAC block (00:12:F3, 2004) still carrying a Malmö, Sweden registrant address [4]. A MAC in one of its 11 MA-L blocks [3] is therefore a u-blox module soldered into someone else's product, not a u-blox-branded device; u-blox's own datasheet names telematics, low-power sensors, connected factories and buildings, point-of-sale and health devices as the targets [2], so expect an embedded or industrial endpoint rather than a phone or laptop. The documented silicon for the Wi-Fi line is Espressif's ESP32 (NINA-W10: 802.11b/g/n at 2.4 GHz only, Bluetooth 4.2 BR/EDR and LE) [2]; the Nordic- and NXP-based module families could not be confirmed from a reachable primary page in this session (u-blox product pages failed with header overflow and guessed datasheet URLs returned 404), so they are not listed. The module ships with FCC modular approval under grantee code XPY (FCC ID XPYNINAW10), and the datasheet notes that an integrator may instead obtain its own grantee status via "change in ID" [2], so the same module can also appear under an end-product brand's FCC ID. No public statement on MAC randomization and no vendor security advisories were found; both are recorded as unknown/empty.
## Sources
1. u-blox - Wikipedia - https://en.wikipedia.org/wiki/U-blox (accessed 2026-10-27)
2. NINA-W10 series Data sheet, UBX-17065507 R17 (5-May-2025) - u-blox - https://content.u-blox.com/sites/default/files/NINA-W10_DataSheet_UBX-17065507.pdf (accessed 2026-10-27)
3. u-blox AG MAC address blocks - maclookup.app - https://maclookup.app/vendors/u-blox-ag (accessed 2026-10-27)
4. MAC prefix 00:12:F3 - maclookup.app - https://maclookup.app/macaddress/0012F3 (accessed 2026-10-27)
