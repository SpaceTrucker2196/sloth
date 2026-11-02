---
name: "Motorola Mobility LLC, a Lenovo Company"
aliases: []
country: US [1]
parent: "Lenovo (acquired October 2014 from Google, which had owned it since May 2012) [1]"
founded: 2011 [1]
kind: brand
device_classes: [phone]
found_in: ["Moto G (since 2013), Moto E (since 2014), Edge (since 2020) and Razr foldable (since 2019/2020) smartphones [1]", "Moto G Play / Power / Stylus / Stylus 5G / Pure (2021) [4]", "Motorola Razr 50 / Razr 50s (2024) [5]"]
radios: ["Wi-Fi 5 (802.11a/b/g/n/ac dual-band) on Moto G 2021 series [4]", "2.4 GHz (dual-band 802.11ac, Moto G 2021 series) [4]", "5 GHz (dual-band 802.11ac, Moto G 2021 series) [4]", "BT Classic / BLE 5.0 on Moto G 2021 series [4]", "5G on Razr 50 [5]", "NFC on Razr 50 [5]"]
silicon: ["Qualcomm Snapdragon 662 in Moto G Power (2021); Snapdragon 460 in Moto G Play (2021); Snapdragon 678 in Moto G Stylus (2021); Snapdragon 480 in Moto G Stylus 5G (2021) [4]", "MediaTek Helio G25 in Moto G Pure (2021) [4]", "MediaTek Dimensity 7300X in Motorola Razr 50 (2024) [5]", "Qualcomm Snapdragon is the primary SoC supplier, MediaTek in budget/mid-range models, Samsung Exynos in some Motorola One phones [1]"]
fcc_grantee: []
randomization: "randomizes by default (Android 10 and later randomize per SSID) [6]"
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Motorola Mobility LLC was spun out of Motorola on 4 January 2011, bought by Google in May 2012 and sold to Lenovo in October 2014; it keeps its headquarters, R&D and product design at the Merchandise Mart in Chicago while Lenovo runs manufacturing and supply chain [1]. The IEEE registrant name carries 130 MA-L blocks [7], and the product lines are the Moto G, Moto E, Edge and Razr phones [1], so a MAC in one of these blocks is most likely a handset; the FCC grantee code and the accessory grants under it could not be confirmed because the FCC ID mirrors returned 403, so they are left out rather than recalled. Documented radios on recent models are dual-band 802.11ac Wi-Fi with Bluetooth 5.0 across the 2021 Moto G family [4], and 5G and NFC on the 2024 Razr 50 [5]; Wi-Fi 6/7 support on specific models was not confirmed in the sources reached. Silicon is Qualcomm Snapdragon in most phones (662/460/678/480 across the 2021 Moto G line), MediaTek in budget models (Helio G25) and in the Razr 50 (Dimensity 7300X), and Samsung Exynos in some Motorola One devices [1][4][5]. These are Android phones (the Razr 50 shipped Android 14 [5]), and Android 10 onward randomizes the Wi-Fi MAC per SSID by default [6], so the Motorola OUI is usually only visible when randomization has been turned off for a network, or in Bluetooth. No vendor security advisory feed was reachable in this session (motorola.com/us/security-advisories redirected to the storefront), so security notes are left empty rather than filled from memory.
## Sources
1. Motorola Mobility - Wikipedia - https://en.wikipedia.org/wiki/Motorola_Mobility (accessed 2026-10-27)
2. Motorola Mobility LLC FCC ID Applications (IHD) - fccid.io - https://fccid.io/IHD (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403; nothing in this entry rests on it)
3. FCC ID IHDT56AY2 - Mobile Cellular Phone - fccid.io - https://fccid.io/IHDT56AY2 (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403; nothing in this entry rests on it)
4. Moto G Power (Moto G 2021 series) - Wikipedia - https://en.wikipedia.org/wiki/Moto_G_Power (accessed 2026-10-27)
5. Motorola Razr (2024) - Wikipedia - https://en.wikipedia.org/wiki/Motorola_Razr_(2024) (accessed 2026-10-27)
6. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization (accessed 2026-10-27)
7. Motorola Mobility LLC, a Lenovo Company MAC address blocks - maclookup.app - https://maclookup.app/vendors/motorola-mobility-llc-a-lenovo-company (accessed 2026-10-27)
