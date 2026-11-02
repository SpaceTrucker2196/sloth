---
name: MediaTek Inc
aliases: []
country: TW [1][2]
parent: independent, listed on the Taiwan Stock Exchange (2454) since 2001 [1]
founded: 1997 [1]
kind: chip-vendor [1]
device_classes: [phone [1], tv [1], laptop [3], ap/router [4], module-in-other-brands [3]]
found_in: ["Sony LCD TVs, the first to ship the MT5595 Android TV SoC [1]", "MT7921-family Wi-Fi/Bluetooth cards, also sold as AMD RZ608 and RZ616 [3]", "Lenovo ThinkPad L14 Gen 2 and L15 Gen 2 (MT7921 driver package) [3]"]
radios: ["Wi-Fi 6 (MT7921AN) [1]", "Wi-Fi 6E (MT7922AN) [1]", "Wi-Fi 7 (MT7925AN) [1]", "BLE 4.x/5.x [1][3]", "LTE/5G (Helio M70/M80/M90 modems) [1]"]
silicon: ["MT7921AN Wi-Fi 6, MT7922AN Wi-Fi 6E and MT7925AN Wi-Fi 7 PCIe wireless controllers [1]", "MT5595 digital TV SoC in Sony LCD TVs [1]", "MT7603, MT7615, MT7622, MT7663, MT7915, MT7916, MT7981, MT7986 Wi-Fi AP chipsets [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Product Security Bulletins published since August 2021 [5]", "CVE-2025-20631/20632: wlan AP driver out-of-bounds writes, High, in MT7615, MT7622, MT7663, MT7915, MT7916, MT7981, MT7986, SDK 7.6.7.2 and earlier [4][6]", "CVE-2025-20633: wlan AP driver out-of-bounds write, High, in MT7603, MT7615, MT7622, MT7915, SDK 7.4.0.1 and earlier [4]", "CVE-2025-20634: modem out-of-bounds write, High, across about 30 chipsets running modem NR16, NR17 and NR17R [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

MediaTek is a Taiwanese fabless chip designer headquartered in Hsinchu, spun off from United Microelectronics Corporation and incorporated on 28 May 1997, and listed on the Taiwan Stock Exchange since 2001 [1]. Its acquisitions include the 802.11 designer Inprocomm in 2005 and Ralink Technology in 2011, which brought Wi-Fi expertise, and MStar Semiconductor, merged in 2014 [1]. The IEEE registry lists four MA-L blocks to "MediaTek Inc" at its Hsinchu Science Park address [2].

No source consulted says what carries these four blocks, and MediaTek is a chip designer rather than a device brand [1], so a MAC in them is best read as a MediaTek board of unknown kind; its silicon sits in phones (Dimensity SoCs), TVs (the MT5595 Android TV SoC first shipped in Sony LCD TVs) and PCs (the MT7921AN Wi-Fi 6, MT7922AN Wi-Fi 6E and MT7925AN Wi-Fi 7 PCIe wireless controllers) [1]. A driver catalogue gives Bluetooth 5.2 for the MT7921 family, the AMD RZ608 and RZ616 names for the same cards, and a Lenovo package for the ThinkPad L14 Gen 2 and L15 Gen 2 [3].

MediaTek publishes Product Security Bulletins, the earliest listed dated August 2021 [5]. The February 2025 bulletin rated three wlan AP driver flaws High for the MT7603, MT7615, MT7622, MT7663, MT7915, MT7916, MT7981 and MT7986 router chipsets, and a modem out-of-bounds write High across about 30 chipsets running modem NR16, NR17 and NR17R [4]; NVD describes CVE-2025-20631 as an out-of-bounds write in the wlan AP driver from an incorrect bounds check [6]. Randomization is the host operating system's choice and is unknown here; FCC grantee codes are not listed because the FCC ID databases refused automated access from this session.

## Sources

1. MediaTek - Wikipedia - https://en.wikipedia.org/wiki/MediaTek (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. MediaTek MT7921/MT7921K Wireless LAN/BT Driver (AMD RZ608/RZ616) - OEMDrivers - https://oemdrivers.com/network-mediatek-mt7921-wireless-lan-driver (accessed 2026-10-27)
4. MediaTek Product Security Bulletin, February 2025 - https://www.mediatek.com/product-security-bulletin/February-2025 (accessed 2026-10-27)
5. MediaTek Product Security Bulletins - https://www.mediatek.com/product-security-bulletin (accessed 2026-10-27)
6. NVD - CVE-2025-20631 - https://nvd.nist.gov/vuln/detail/CVE-2025-20631 (accessed 2026-10-27)
