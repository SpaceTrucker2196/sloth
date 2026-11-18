---
name: Sony Corporation
aliases: []
affiliates: []
country: JP [1][2]
parent: Sony Group Corporation [1]
founded: 1946 [1]
kind: brand [1]
device_classes: [phone [1][3], tv [1], camera [1], speaker [1]]
found_in: ["Sony Xperia Android smartphones, made by Sony Mobile until it was folded into Sony Corporation in 2021 [3]", "BRAVIA televisions, Alpha digital cameras and consumer audio equipment [1]"]
radios: ["Wi-Fi 6 [4]", "2.4 GHz [4]", "5 GHz [4]", "BLE 4.x/5.x [4]", "LTE/5G [4]"]
silicon: ["Qualcomm Snapdragon 8 Gen 2 (SM8550-AB) in the Sony Xperia 1 V [4]"]
fcc_grantee: []
randomization: mixed: Xperia phones run Android, which since Android 10 uses a persistent per-network randomized MAC by default [5]; the TVs, cameras and audio products are not documented
security_notes: []
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary

Sony was founded in 1946 as Tokyo Tsushin Kogyo by Masaru Ibuka and
Akio Morita and is headquartered in Minato, Tokyo; after its move to a
holding-company structure the parent is Sony Group Corporation and the
electronics business continued under the name Sony Corporation [1].
That electronics business covers Xperia mobile devices, BRAVIA
televisions, Alpha digital cameras and consumer audio equipment, while
PlayStation hardware sits in a separate games segment [1]. The IEEE
registry lists 85 MA-L blocks to "Sony Corporation" at Tokyo addresses
in Konan, Higashi-Shinagawa, Gotenyama and Sony City Osaki [2]; the
PlayStation maker registers separately as Sony Interactive
Entertainment Inc. [2].

A MAC in one of these blocks is therefore most likely an Xperia phone,
a Sony TV, a camera or an audio product: Sony Mobile Communications,
the former Sony Ericsson joint venture, made the Xperia Android phones
and was integrated into Sony Corporation in 2021 [3]. As an example of
current hardware, the Xperia 1 V has a Qualcomm Snapdragon 8 Gen 2,
802.11 a/b/g/n/ac/ax Wi-Fi on 2.4 and 5 GHz, Bluetooth 5.3, 4G LTE and
5G NR [4]; other products' radios are not documented by the sources
consulted. Android 10 and later uses a persistent randomized MAC per
network profile by default, so an Xperia on a recent Android release
will usually not show its burned-in Sony address on Wi-Fi [5].

FCC grantee codes are not listed: the FCC ID databases (fccid.io,
fcc.report, the FCC grantee search) refused the session that wrote
this entry, and nothing is filled in from memory. No security advisory
was consulted, so security_notes is empty rather than clean.

## Sources
1. Sony - Wikipedia - https://en.wikipedia.org/wiki/Sony (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Sony Mobile - Wikipedia - https://en.wikipedia.org/wiki/Sony_Mobile (accessed 2026-10-27)
4. Sony Xperia 1 V - Wikipedia - https://en.wikipedia.org/wiki/Sony_Xperia_1_V (accessed 2026-10-27)
5. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
