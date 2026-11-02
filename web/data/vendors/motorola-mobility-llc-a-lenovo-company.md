---
name: "Motorola Mobility LLC, a Lenovo Company"
aliases: []
affiliates: []
country: US [1]
parent: "Lenovo (acquired October 2014 from Google, which had owned it since May 2012) [1]"
founded: 2011 [1]
kind: brand
device_classes: [phone]
found_in: ["Moto G (since 2013), Moto E (since 2014), Edge (since 2020) and Razr foldable (since 2019/2020) smartphones [1]", "Moto G Play / Power / Stylus / Stylus 5G / Pure (2021) [2]", "Motorola Razr 50 / Razr 50s (2024) [3]"]
radios: ["Wi-Fi 5 (802.11a/b/g/n/ac dual-band) on Moto G 2021 series [2]", "2.4 GHz (dual-band 802.11ac, Moto G 2021 series) [2]", "5 GHz (dual-band 802.11ac, Moto G 2021 series) [2]", "BT Classic / BLE 5.0 on Moto G 2021 series [2]", "5G on Razr 50 [3]", "NFC on Razr 50 [3]"]
silicon: ["Qualcomm Snapdragon 662 in Moto G Power (2021); Snapdragon 460 in Moto G Play (2021); Snapdragon 678 in Moto G Stylus (2021); Snapdragon 480 in Moto G Stylus 5G (2021) [2]", "MediaTek Helio G25 in Moto G Pure (2021) [2]", "MediaTek Dimensity 7300X in Motorola Razr 50 (2024) [3]", "Qualcomm Snapdragon is the primary SoC supplier, MediaTek in budget/mid-range models, Samsung Exynos in some Motorola One phones [1]"]
fcc_grantee: []
randomization: "randomizes by default (Android 10 and later randomize per SSID) [4]"
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Motorola Mobility LLC was spun out of Motorola on 4 January 2011, bought by Google in May 2012 and sold to Lenovo in October 2014; it keeps its headquarters, R&D and product design at the Merchandise Mart in Chicago while Lenovo runs manufacturing and supply chain [1]. The IEEE registrant name carries 130 MA-L blocks [5], and the product lines are the Moto G, Moto E, Edge and Razr phones [1], so a MAC in one of these blocks is most likely a handset; the FCC grantee code and the accessory grants under it could not be confirmed because the FCC ID mirrors returned 403, so they are left out rather than recalled. Documented radios on recent models are dual-band 802.11ac Wi-Fi with Bluetooth 5.0 across the 2021 Moto G family [2], and 5G and NFC on the 2024 Razr 50 [3]; Wi-Fi 6/7 support on specific models was not confirmed in the sources reached. Silicon is Qualcomm Snapdragon in most phones (662/460/678/480 across the 2021 Moto G line), MediaTek in budget models (Helio G25) and in the Razr 50 (Dimensity 7300X), and Samsung Exynos in some Motorola One devices [1][2][3]. These are Android phones (the Razr 50 shipped Android 14 [3]), and Android 10 onward randomizes the Wi-Fi MAC per SSID by default [4], so the Motorola OUI is usually only visible when randomization has been turned off for a network, or in Bluetooth. No vendor security advisory feed was reachable in this session (motorola.com/us/security-advisories redirected to the storefront), so security notes are left empty rather than filled from memory.
## Sources
1. Motorola Mobility - Wikipedia - https://en.wikipedia.org/wiki/Motorola_Mobility (accessed 2026-10-27)
2. Moto G Power (Moto G 2021 series) - Wikipedia - https://en.wikipedia.org/wiki/Moto_G_Power (accessed 2026-10-27)
3. Motorola Razr (2024) - Wikipedia - https://en.wikipedia.org/wiki/Motorola_Razr_(2024) (accessed 2026-10-27)
4. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization (accessed 2026-10-27)
5. Motorola Mobility LLC, a Lenovo Company MAC address blocks - maclookup.app - https://maclookup.app/vendors/motorola-mobility-llc-a-lenovo-company (accessed 2026-10-27)
