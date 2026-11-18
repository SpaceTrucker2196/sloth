---
name: HMD Global Oy
aliases: []
affiliates: []
country: FI [1][2]
parent: independent, with Nokia holding a stake and Smart Connect LP as backer [1]
founded: 2016 [1]
kind: brand
device_classes: [phone [1][3], tablet [3]]
found_in: ["Nokia-branded smartphones and feature phones made under licence since December 2016 [1][3]", "HMD-branded phones since March 2024 [1][3]", "Nokia 2 (TA-1029) smartphone, Snapdragon 212 [4][5]"]
radios: ["Wi-Fi 4 [5]", "BLE 4.x/5.x [5]"]
silicon: ["Qualcomm Snapdragon 212 in Nokia 2 [4][5]"]
fcc_grantee: []
randomization: Android phones; Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [5][6]
security_notes: ["2019: a batch of Nokia 7 Plus phones sent location, SIM card number and serial number unencrypted to a Chinese server; HMD said it fixed the error in a January update and Finland's data protection ombudsman investigated [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary

HMD Global is a Finnish company headquartered in Espoo, incorporated in Helsinki in November 2015, which began marketing Nokia-branded phones on 1 December 2016 from the phone business Nokia had sold to Microsoft; Nokia holds a stake and receives royalties, Smart Connect LP backs it, and it has made HMD-branded phones since March 2024 [1]. Its site lists HMD smartphones such as the Fuse, Skyline and Crest, Nokia feature phones such as the 3210 4G and 2660 Flip 4G made under licence from Nokia, and tablets [3]. The IEEE registry lists 31 MA-L blocks to "HMD Global Oy" at Bertel Jungin aukio 9, Espoo [2].

A MAC in an HMD block is most likely a Nokia- or HMD-branded phone [1][2]. The Nokia 2, described as a budget Android smartphone by HMD Global, has a Qualcomm Snapdragon 212, 802.11 b/g/n Wi-Fi and Bluetooth 4.1 [5], and iFixit's teardown confirms the Snapdragon 212 [4]. Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [6], so HMD's Android phones on current releases should randomise, which is inferred rather than documented; feature phones are not covered by that source. HMD says it ships Android security patches as quickly as possible but states no fixed cadence or support period [8].

In March 2019 a batch of Nokia 7 Plus phones was reported to send location, SIM card number and serial number unencrypted to a Chinese server; HMD said it fixed the error in a January software update and that no identifying personal data was sent, and Finland's data protection ombudsman opened an investigation [7]. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry; nothing is filled in from memory.

## Sources
1. HMD Global - Wikipedia - https://en.wikipedia.org/wiki/HMD_Global (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. HMD global site - https://www.hmd.com/ (accessed 2026-10-27)
4. Nokia 2 Teardown - iFixit - https://www.ifixit.com/Teardown/Nokia+2+Teardown/149264 (accessed 2026-10-27)
5. Nokia 2 - Wikipedia - https://en.wikipedia.org/wiki/Nokia_2 (accessed 2026-10-27)
6. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
7. Finland is investigating Nokia phones sending data to China - Engadget - https://www.engadget.com/2019-03-21-finland-investigating-nokia-data-china.html (accessed 2026-10-27)
8. Security and maintenance updates - HMD - https://www.hmd.com/en_int/security-updates (accessed 2026-10-27)
