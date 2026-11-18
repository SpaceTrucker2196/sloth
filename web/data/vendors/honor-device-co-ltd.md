---
name: "Honor Device Co., Ltd."
aliases: []
affiliates: []
country: CN [1][2]
parent: majority-owned by Shenzhen Zhixin New Information Technology Co. Ltd. since Huawei sold Honor in November 2020 [1]
founded: 2013 [1]
kind: brand
device_classes: [phone [1][3], tablet [1][3], laptop [1][3], wearable [1][3], tv [1], ap/router [3]]
found_in: ["Honor Magic6 Pro smartphone (Snapdragon 8 Gen 3) [4]", "Honor tablets, laptops, wearables, audio and routers [3]"]
radios: ["Wi-Fi 7 [4]", "BLE 4.x/5.x [4]", "LTE/5G [4]"]
silicon: ["Qualcomm Snapdragon 8 Gen 3 in Honor Magic6 Pro [4]"]
fcc_grantee: []
randomization: Android-derived MagicOS; Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [1][5]
security_notes: ["NVD lists 52 CVEs (2023 to 2026) from one numbering authority whose records name Honor products, most for unnamed 'some Honor products': incorrect privilege assignment, information leaks, signature management and type confusion [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary

Honor was founded in 2013 as a Huawei sub-brand, headquartered in Futian district, Shenzhen; Huawei announced on 17 November 2020 that it had sold Honor entirely, and it is now majority-owned by Shenzhen Zhixin New Information Technology Co. Ltd. [1]. Honor develops smartphones, tablets, wearables and mobile software, has sold laptops since 2018, and its range includes earbuds, TVs and smart home devices [1]. Its global site lists phones, laptops, tablets, wearables, audio, accessories and routers [3]. The IEEE registry lists 60 MA-L blocks to "Honor Device Co., Ltd." at Shenzhen addresses [2].

A MAC in an Honor block is most likely an Honor phone, tablet or laptop [1][2]. The Honor Magic6 Pro is documented with a Qualcomm Snapdragon 8 Gen 3, Wi-Fi 7, Bluetooth 5.3 with LE, LTE and 5G, and NFC [4]. Honor phones run MagicOS, an Android-derived operating system [1], and Android 10 and later use a randomized MAC by default, persistent per network on Android 10 and 11 [5], so randomization is inferred rather than documented for Honor itself.

Honor's site has a security bulletin page and invites vulnerability reports [6]. NVD lists 52 CVEs from 2023 to 2026 from one numbering authority whose records name Honor products, most describing unnamed "some Honor products" affected by incorrect privilege assignment, information leaks, signature management or type confusion [7]. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry; nothing is filled in from memory.

## Sources
1. Honor (brand) - Wikipedia - https://en.wikipedia.org/wiki/Honor_(brand) (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. HONOR global site - https://www.honor.com/global/ (accessed 2026-10-27)
4. Honor Magic6 Pro - Wikipedia - https://en.wikipedia.org/wiki/Honor_Magic6_Pro (accessed 2026-10-27)
5. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
6. HONOR ESG governance, security bulletins - https://www.honor.com/global/honor-esg/governance/ (accessed 2026-10-27)
7. NVD CVE API, CVEs from the numbering authority for Honor products - https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=3836d913-7555-4dd0-a509-f5667fdf5fe4 (accessed 2026-10-27)
