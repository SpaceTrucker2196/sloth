---
name: ASUSTek COMPUTER INC.
aliases: []
country: TW [1]
parent: independent (publicly listed, 2357.TW) [2]
founded: 1989 [1]
kind: brand
device_classes: [laptop, ap/router, phone, tablet]
found_in: ["ASUS RT-AX88U router [3]", "ASUS RT-AC68U router (manufactured by Askey) [4]", "Zenbook, Vivobook, ProArt and ROG laptops and gaming hardware [1]", "ZenFone smartphones (ASUS exiting the smartphone business in 2026) [1]", "ZenWiFi mesh systems [8]"]
radios: ["Wi-Fi 5 (802.11ac) 3x3, RT-AC68U [4]", "Wi-Fi 6 (802.11ax) 4x4, RT-AX88U [3]", "2.4 GHz [3][4]", "5 GHz [3][4]"]
silicon: ["Broadcom BCM49408 SoC + BCM43684 4x4 radios in RT-AX88U [3]", "Broadcom BCM4708A0 SoC + BCM4360 3x3 radios in RT-AC68U [4]", "MediaTek MT7921L (via AzureWave AW-XB468NF module) in ASUS PCE-AX1800 adapter [5]"]
fcc_grantee: ["MSQ (e.g. FCC ID MSQ-RTAXHP00, MSQ-RTAC68U) [3][4]"]
randomization: "mixed - routers and PCs not documented here; ZenFone phones run Android, which uses a randomized MAC per network by default from Android 10 [7]"
security_notes: ["AiCloud flaw (2014) exposed USB storage on ASUS routers; 12,937 router IPs and 3,131 credentials leaked; FTC settlement 2016 [1]", "ASUS WebStorage updater abused by BlackTech over unencrypted HTTP (2019) [1]", "KadNap botnet infected over 14,000 ASUS routers from August 2025, more than 60 percent in the US [1]", "DNSpooq advisory CVE-2020-25681 through CVE-2020-25687 affecting RT-AX, RT-AC and ZenWiFi models [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
ASUSTeK Computer Inc. was founded in Taipei in 1989 by four former Acer engineers [1] and sells laptops (Zenbook, Vivobook, ProArt, ROG), motherboards and components, monitors and desktops, routers and mesh systems, and until its announced 2026 exit, ZenFone smartphones [1][2]. It holds 93 MA-L blocks registered from 1998 onward [6], and a MAC in one of them is most often a Wi-Fi router or AP, a PC's onboard Ethernet or Wi-Fi, or a laptop; ASUS laptops and adapters also commonly carry a third-party module's OUI instead (for example the AzureWave AW-XB468NF, built on MediaTek MT7921L, inside the ASUS PCE-AX1800 adapter [5]), so not every ASUS machine shows up as ASUS, and the reverse holds too: the RT-AC68U carries ASUS's OUI 74:D0:2B although DeviWiki records Askey as its manufacturer [4]. Documented router silicon is Broadcom end to end: BCM4708A0 with BCM4360 radios in the Wi-Fi 5 RT-AC68U [4] and BCM49408 with BCM43684 4x4 radios in the Wi-Fi 6 RT-AX88U [3]; ASUS's FCC grantee code is MSQ [3][4]. Randomization is mixed: Android-based ZenFones use a randomized MAC per network by default since Android 10 [7], while a router BSSID or a Windows laptop with default settings is not documented here and should be treated as unknown. Routers are the security story: the 2014 AiCloud leak and 2016 FTC settlement, the 2019 WebStorage supply-chain abuse, the 2025 KadNap botnet of 14,000+ routers [1], and vendor advisories such as DNSpooq (CVE-2020-25681..25687) across RT-AX, RT-AC and ZenWiFi [8]. An ASUS router seen on an unfamiliar network, or one still advertising old firmware, is a reasonable thing to flag.
## Sources
1. Asus - Wikipedia - https://en.wikipedia.org/wiki/Asus (accessed 2026-10-27)
2. About ASUS - ASUS - https://www.asus.com/about_asus/ (accessed 2026-10-27)
3. ASUS RT-AX88U - DeviWiki - https://deviwiki.com/wiki/ASUS_RT-AX88U (accessed 2026-10-27)
4. ASUS RT-AC68U - DeviWiki - https://deviwiki.com/wiki/ASUS_RT-AC68U (accessed 2026-10-27)
5. AzureWave AW-XB468NF - WikiDevi mirror - https://wikidevi.wi-cat.ru/AzureWave_AW-XB468NF (accessed 2026-10-27)
6. ASUSTek COMPUTER INC. MAC address blocks - maclookup.app - https://maclookup.app/vendors/asustek-computer-inc (accessed 2026-10-27)
7. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization-behavior (accessed 2026-10-27)
8. ASUS Product Security Advisory - ASUS - https://www.asus.com/us/content/asus-product-security-advisory/ (accessed 2026-10-27)
