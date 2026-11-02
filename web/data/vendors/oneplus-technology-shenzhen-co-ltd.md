---
name: "OnePlus Technology (Shenzhen) Co., Ltd"
aliases: ["OnePlus Tech (Shenzhen) Ltd"]
country: CN [1][2]
parent: Oppo [1]
founded: 2013 [1][3]
kind: brand
device_classes: [phone [1], tablet [1], wearable [1], tv [1]]
found_in: ["OnePlus 6 smartphone (Snapdragon 845, WCN3990 Wi-Fi) [4]", "OnePlus Nord smartphone (WCN3998 Wi-Fi/Bluetooth) [5]", "OnePlus Buds, Watch and Pad products [1]"]
radios: ["Wi-Fi 5 [4]", "BLE 4.x/5.x [5]"]
silicon: ["Qualcomm Snapdragon 845, WCN3990 2x2 802.11ac Wi-Fi, SDR845 RF transceiver and NXP NFC controller in OnePlus 6 [4]", "Qualcomm Atheros WCN3998 Wi-Fi 6-ready/Bluetooth 5 chipset in OnePlus Nord [5]"]
fcc_grantee: []
randomization: Android-based OxygenOS; Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [1][6]
security_notes: ["CVE-2025-10184: OxygenOS 12 to 15 Telephony provider permission bypass let any app read SMS/MMS without permission; fixes rolled out from October 2025 [7]", "CVE-2017-5622 to CVE-2017-5626: OnePlus 3/3T bootloader and fastboot weaknesses (adbd on charge, hidden OEM commands, dm-verity bypass) [8]", "CVE-2016-10370: OnePlus OTA updater fetched images over HTTP without TLS [8]", "CVE-2020-7958: OnePlus 7 Pro debug code let root read raw fingerprint images [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary

OnePlus was founded in December 2013 by Pete Lau, a former Oppo vice-president, and Carl Pei, is headquartered in the Tairan Building in Futian, Shenzhen, and is a subsidiary of Oppo; it shares Oppo's manufacturing line and supply chain [1][3]. It sells OnePlus, Nord, Ace and other phone lines, OnePlus Buds, watches, Pad tablets and, in India, TVs, and its OxygenOS is Android-based [1]. The IEEE registry lists 19 MA-L blocks to "OnePlus Technology (Shenzhen) Co., Ltd" and one to "OnePlus Tech (Shenzhen) Ltd", both at Tairan Building addresses in Shenzhen [2]; a further block to "OnePlus Electronics (Shenzhen) Co., Ltd." at Qianhai is a separate registrant and not folded in here [2].

A MAC in a OnePlus block is most likely a OnePlus phone [1][2]. iFixit's OnePlus 6 teardown identifies a Qualcomm Snapdragon 845, a Qualcomm WCN3990 2x2 802.11ac Wi-Fi chip, an SDR845 RF transceiver and an NXP NFC controller [4], and its OnePlus Nord teardown a Qualcomm Atheros WCN3998, described as a Wi-Fi 6-ready chipset with Bluetooth 5 and WPA3 [5]. Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [6], so OnePlus phones on current OxygenOS should randomise, which is inferred, not documented for OnePlus.

Rapid7 disclosed CVE-2025-10184 in September 2025: an unprotected Telephony content provider in OxygenOS 12 to 15 let any installed app read SMS and MMS data, undermining SMS-based MFA, with fixes rolling out from October 2025 [7]. NVD also lists 2017 bootloader and fastboot weaknesses in the OnePlus 3/3T, an OTA updater without TLS, and leftover fingerprint debug code in the OnePlus 7 Pro [8]. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry; nothing is filled in from memory.

## Sources

1. OnePlus - Wikipedia - https://en.wikipedia.org/wiki/OnePlus (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. About OnePlus - OnePlus - https://www.oneplus.com/global/about-us (accessed 2026-10-27)
4. OnePlus 6 Teardown - iFixit - https://www.ifixit.com/Teardown/OnePlus+6+Teardown/109826 (accessed 2026-10-27)
5. OnePlus Nord Teardown - iFixit - https://www.ifixit.com/Teardown/OnePlus+Nord+Teardown/135734 (accessed 2026-10-27)
6. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
7. CVE-2025-10184: OnePlus OxygenOS Telephony provider permission bypass - Rapid7 - https://www.rapid7.com/blog/post/cve-2025-10184-oneplus-oxygenos-telephony-provider-permission-bypass-not-fixed (accessed 2026-10-27)
8. NVD CVE API, keyword OnePlus - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OnePlus (accessed 2026-10-27)
