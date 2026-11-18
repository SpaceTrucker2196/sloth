---
name: "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD"
aliases: []
affiliates: []
country: CN [1][2]
parent: Guangdong Oujia Holdings Co., Ltd. since 2023; BBK Electronics from 2004 to 2023 [1]
founded: 2004 [1]
kind: brand
device_classes: [phone [1], tablet [1], wearable [1]]
found_in: ["OPPO smartphones such as the Find X8 Pro (ColorOS 15) [3]"]
radios: ["Wi-Fi 7 (Find X8 Pro) [3]", "BLE 5.x (Bluetooth 5.4 on Find X8 Pro) [3]", "LTE/5G (5G NR on Find X8 Pro) [3]"]
silicon: ["MediaTek Dimensity 9400 in OPPO Find X8 Pro [3]"]
fcc_grantee: []
randomization: randomizes by default on Android 10 and later per AOSP; Oppo-specific behaviour not documented [4]
security_notes: ["CVE-2025-27389: flawed verification of app installation sources in ColorOS could let malicious apps install without warning [6]", "2025, Thailand: Oppo and Realme phones shipped with a preinstalled loan app that could be disabled but not uninstalled; the companies said they would stop [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: inferred}
researched: 2026-10-27
---
## Summary

Oppo was founded on 10 October 2004 and is headquartered in Shenzhen, Guangdong; it was owned by BBK Electronics until 2023 and by Guangdong Oujia Holdings since, and lists OnePlus and Realme as subsidiaries [1]. It makes smartphones, tablets, audio devices and other smart devices, and its phones run its ColorOS software [1]. The IEEE registry lists 186 MA-L blocks to "GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD" at Haibin Road, Dongguan [2].

A MAC in an Oppo block is most likely an Oppo phone, tablet or wearable, though no source consulted ties a specific model to a specific block [1][2]. As an example of current radios and silicon, the Find X8 Pro lists Wi-Fi 7 with 2x2 MIMO, Bluetooth 5.4 with Low Energy, 5G NR and a MediaTek Dimensity 9400, running ColorOS 15 [3].

Android 10 and later use a randomized MAC by default [4], so a modern Oppo phone most likely joins networks with a random address rather than one from these blocks, though no source consulted documents ColorOS's own behaviour. Oppo's security response centre says its monthly version maintenance includes patches from the Android Security Bulletin [5]. NVD lists CVE-2025-27389, an install-source verification flaw in ColorOS [6]. FCC grantee codes are not listed because the FCC ID databases refused requests from the session that wrote this entry.

## Sources
1. Oppo - Wikipedia - https://en.wikipedia.org/wiki/Oppo (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. OPPO Find X8 Pro specifications - https://www.oppo.com/en/smartphones/series-find-x/find-x8-pro/specs/ (accessed 2026-10-27)
4. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
5. Security Advisories - OPPO Security Response Center - https://security.oppo.com/en/mend (accessed 2026-10-27)
6. CVE-2025-27389 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2025-27389 (accessed 2026-10-27)
