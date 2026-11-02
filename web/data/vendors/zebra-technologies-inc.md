---
name: Zebra Technologies Inc
aliases: ["Zebra Technologies Inc.", "Zebra Technologies Corp."]
country: US [1][2]
parent: independent; publicly traded on Nasdaq as ZBRA since 1991 [1]
founded: 1969 [1]
kind: brand
device_classes: [industrial [1][3], printer [1], ap/router [4]]
found_in: ["Motorola Solutions AP 7532 802.11ac access point, OUI 84:24:8D [4]", "Zebra TC52x, TC57x and TC52ax Android mobile computers [3]"]
radios: ["Wi-Fi 5 (TC52x/TC57x, AP 7532) [3][4]", "Wi-Fi 6 (TC52ax) [3]", "2.4 GHz [4]", "5 GHz [4]", "BLE 5.x (Bluetooth 5.0/5.1 with BLE) [3]", "LTE/5G (LTE on TC57x) [3]"]
silicon: ["Qualcomm Snapdragon 660 in TC52x/TC57x/TC52ax [3]", "Broadcom BCM43460 radios and BCM53016 CPU in Motorola Solutions AP 7532 [4]"]
fcc_grantee: ["UZ7 (FCC ID UZ7AP7532, AP 7532) [4]"]
randomization: mixed: Android 10 and later use a per-network randomized MAC by default [5], and Zebra Android devices expose a MACRandomization setting in Zebra OEMConfig that administrators can turn off [6]
security_notes: ["CVE-2023-4957: authentication bypass in the web interface of a Zebra ZT410 ZPL printer from the same network when protected mode is disabled [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: inferred}
researched: 2026-10-27
---
## Summary

Zebra Technologies Corporation was founded in 1969 as Data Specialties Incorporated, took the Zebra name in 1986, is headquartered in Lincolnshire, Illinois, and has traded on Nasdaq as ZBRA since 1991 [1]. It makes barcode and RFID printers, rugged mobile computers and tablets, scanners and real-time locating systems, and in 2014 bought Motorola Solutions' enterprise division, including the Symbol Technologies and Psion lines [1]. The IEEE registry lists its MA-L blocks under three spellings, "Zebra Technologies Inc" at Lincolnshire, "Zebra Technologies Inc." at Holtsville, New York, and "Zebra Technologies Corp." in Vernon Hills and Germantown [2].

A MAC in a Zebra block is most likely a warehouse or retail handheld, a label printer or an enterprise access point from the former Motorola line [1][4]. WikiDevi records the Motorola Solutions AP 7532, a dual-band 3x3 802.11ac access point with FCC ID UZ7AP7532 built on Broadcom BCM43460 radios and a BCM53016 CPU, carrying OUI 84:24:8D from a Zebra block [4]. Zebra's TC52x and TC57x handhelds run a Qualcomm Snapdragon 660 with 802.11a/b/g/n/ac 2x2 MU-MIMO and Bluetooth 5.0, the TC52ax adds Wi-Fi 6, and the TC57x adds LTE [3].

Android 10 and later use a randomized per-network MAC by default [5], and Zebra's Android devices can have it disabled fleet-wide through a MACRandomization setting in Zebra OEMConfig, so a managed Zebra fleet may show its real Zebra address or a random one [6]. NVD lists CVE-2023-4957, an authentication bypass on a ZT410 printer's web page [7].

## Sources

1. Zebra Technologies - Wikipedia - https://en.wikipedia.org/wiki/Zebra_Technologies (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. TC52x/TC57x spec sheet - Zebra - https://www.zebra.com/us/en/products/spec-sheets/mobile-computers/handheld/tc52x-tc57x.html (accessed 2026-10-27)
4. Motorola Solutions AP 7532 - WikiDevi - https://wikidevi.wi-cat.ru/Motorola_Solutions_AP_7532 (accessed 2026-10-27)
5. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
6. How to disable MAC randomization on Android - Esper - https://www.esper.io/blog/how-to-disable-mac-randomization-on-android (accessed 2026-10-27)
7. CVE-2023-4957 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2023-4957 (accessed 2026-10-27)
