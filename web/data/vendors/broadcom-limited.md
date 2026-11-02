---
name: Broadcom Limited
aliases: [Broadcom, Broadcom Inc.]
country: US [1]
parent: independent [1]
founded: 1961 [1]
kind: chip-vendor
device_classes: [module-in-other-brands [1]]
found_in: ["Apple devices (radio-frequency, Wi-Fi and Bluetooth components) [1]"]
radios: ["Wi-Fi 7 [3]", "Wi-Fi and Bluetooth [1]"]
silicon: ["BCM6765 dual 2x2 320 MHz Wi-Fi 7 with quad-core ARM SoC [3]", "BCM43xx Wi-Fi chips named in CVE-2017-9417 [4]", "BCM2712 application processor in Raspberry Pi 5 [6]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2017-9417 (Broadpwn) remote code execution on BCM43xx Wi-Fi chips [4]", "CVE-2019-15126 Broadcom Wi-Fi clients mis-encrypt a limited set of frames after crafted timed traffic, disclosing them over the air [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Broadcom traces to HP Associates, set up in 1961 as a Hewlett-Packard semiconductor division and separated in the 1999 Agilent spinoff; Avago Technologies Limited took the Broadcom name when it acquired Broadcom Corporation in January 2016, traded as Broadcom Limited until November 2017, moved its legal address from Singapore to Delaware, and is now Broadcom Inc., headquartered in Palo Alto, California [1]. It lists broadband and Wi-Fi SoCs among its products, has supplied Apple with radio-frequency, Wi-Fi and Bluetooth components, and sold its IoT Wi-Fi, Bluetooth and Zigbee portfolio to Cypress in 2016 [1].

The registry holds 21 MA-L blocks as Broadcom Limited, nine older MA-L blocks as Broadcom at Irvine, San Jose, Sunnyvale and Petaluma addresses, and one MA-M as Broadcom Inc. at a Regensburg address [2][7]. A MAC in one of them is most likely a Broadcom network chip inside another brand's device, a router or a reference design; the OUI names the chip vendor, not the device [1]. Broadcom's current infrastructure parts include the BCM6765, a dual 2x2 320 MHz Wi-Fi 7 chip with a quad-core ARM SoC [3], and the Raspberry Pi 5 is built around Broadcom's BCM2712 processor, though a Raspberry Pi board's MAC comes from Raspberry Pi's own blocks, not Broadcom's [6].

NVD records CVE-2017-9417, known as Broadpwn, remote code execution on BCM43xx Wi-Fi chips [4], and CVE-2019-15126, in which crafted timed traffic makes Broadcom Wi-Fi clients send a limited set of frames with improper layer 2 encryption [5]. FCC grantee codes are not listed because the FCC ID databases refused the session that wrote this entry; nothing is filled in from memory. Randomization is the host operating system's behaviour and is unknown here.

## Sources

1. Broadcom - Wikipedia - https://en.wikipedia.org/wiki/Broadcom (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Broadcom BCM6765 product page - https://www.broadcom.com/products/wireless/wireless-lan-infrastructure/bcm6765 (accessed 2026-10-27)
4. NVD CVE-2017-9417 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9417 (accessed 2026-10-27)
5. NVD CVE-2019-15126 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-15126 (accessed 2026-10-27)
6. Raspberry Pi 5 product page - https://www.raspberrypi.com/products/raspberry-pi-5/ (accessed 2026-10-27)
7. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
