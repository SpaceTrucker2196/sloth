---
name: "Samsung Electronics Co.,Ltd"
aliases: ["Samsung Electronics Co., Ltd.", "Samsung Electronics Co., Ltd", "Samsung Electronics Co., Ltd. ARTIK", "Samsung Electronics Co., Ltd., Memory Division"]
country: KR [1]
parent: Samsung Group [1]
founded: 1969 [1]
kind: brand
device_classes: [phone, tablet, wearable, laptop, tv, smart-home]
found_in: ["Samsung Galaxy phones, tablets, smartwatches, earbuds, laptops [3]", "Samsung Smart TVs running Tizen (since 2015) [4]", "Samsung Family Hub refrigerators running Tizen [4]", "SmartThings hubs and ecosystem (Samsung-owned since 2014) [8]"]
radios: ["Wi-Fi (Murata Wi-Fi/Bluetooth module in Galaxy S10; generation per model not stated in sources used) [6]", "2.4 GHz [6]", "5 GHz [6]", "BT Classic / BLE (same Murata combo module) [6]", "LTE/5G (Qualcomm SDR8150 cellular RF transceiver in Galaxy S10) [6]", "NFC (NXP PN80T in Galaxy S10) [6]"]
silicon: ["Qualcomm Snapdragon 855 / Samsung Exynos 9820 SoC in Galaxy S10 (region-dependent) [6]", "Murata KM8D03042 module in Galaxy S10 (iFixit: likely the Wi-Fi/Bluetooth module) [6]", "Qualcomm SDR8150 RF transceiver in Galaxy S10 [6]", "NXP PN80T NFC controller in Galaxy S10 [6]", "Samsung Exynos application processors (in-house System LSI) [1]"]
fcc_grantee: []
randomization: mixed [3][5]
security_notes: ["Monthly Security Maintenance Release (SMR) bulletins with Samsung-specific SVE items (Critical RCE / High LPE / Moderate access-control) for Galaxy mobile devices; latest shown SMR-OCT-2026 [7]", "Samsung Knox enterprise security platform; Knox Guard added May 2022 [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Samsung Electronics, founded 1969 and headquartered in Suwon, South Korea, is the flagship of the Samsung Group chaebol [1]. It holds 906 IEEE MA-L blocks under the exact spelling "Samsung Electronics Co.,Ltd" (most at the Gumi, Gyeongbuk registrant address, the rest at Suwon), plus a handful under the spellings listed as aliases, including three "ARTIK" IoT-module blocks [2]. A MAC in these blocks is most often a Galaxy phone, tablet, watch, earbud or laptop [3], a Tizen smart TV (Tizen on Samsung TVs since 2015) [4], or a Tizen appliance such as a Family Hub refrigerator [4]. Galaxy phones and tablets run Android [3], and Android 10 and later use a randomized MAC per network by default, with Android 12 re-randomizing after 24 h or an expired DHCP lease plus 4 h away [5]; a randomized MAC does not carry Samsung's OUI, so a Samsung-OUI station seen on the air is usually a TV, appliance, or wearable, or a phone whose owner disabled randomization (this last step is an inference from [3] and [5], not a documented Samsung statement). In the Galaxy S10 teardown the Wi-Fi/Bluetooth radio is a Murata combo module, the cellular RF transceiver is Qualcomm SDR8150, NFC is an NXP PN80T, and the SoC is Snapdragon 855 or Exynos 9820 by region [6]. Samsung publishes monthly SMR security bulletins for mobile devices covering Google patches plus Samsung-specific SVE items [7]; the SmartThings platform, Samsung-owned since 2014, added Matter support in October 2022 [8]. No FCC grantee code could be confirmed from a fetchable primary source in this session, so that field is left empty.
## Sources
1. Samsung Electronics - Wikipedia - https://en.wikipedia.org/wiki/Samsung_Electronics (accessed 2026-10-27)
2. IEEE MA-L (OUI) public listing - https://standards-oui.ieee.org/oui/oui.txt (accessed 2026-10-27)
3. Samsung Galaxy - Wikipedia - https://en.wikipedia.org/wiki/Samsung_Galaxy (accessed 2026-10-27)
4. Tizen - Wikipedia - https://en.wikipedia.org/wiki/Tizen (accessed 2026-10-27)
5. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
6. Samsung Galaxy S10 Teardown - iFixit - https://www.ifixit.com/Teardown/Samsung+Galaxy+S10+Teardown/120331 (accessed 2026-10-27)
7. Samsung Mobile Security - Security Updates - https://security.samsungmobile.com/securityUpdate.smsb (accessed 2026-10-27)
8. SmartThings - Wikipedia - https://en.wikipedia.org/wiki/SmartThings (accessed 2026-10-27)
