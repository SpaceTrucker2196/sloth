---
name: Microsoft Corporation
aliases: []
country: US [8]
parent: independent [8]
founded: 1975 [8]
kind: brand
device_classes: [tablet, laptop, console, ap/router, unknown]
found_in: ["Surface Pro 4 tablet [5]", "Surface Pro / Laptop / Go / Studio / Hub lines [1][8]", "Xbox 360 wireless adapters and modules (WKS168, 1398, 1399, 1400, 1501) [4]", "Xbox One Wi-Fi module 1525, wireless controller 1537, USB adapter 1790 [4]", "Xbox Series X and Series S consoles [6][8]", "HoloLens headsets [1][8]", "Microsoft MN-series broadband routers (MN-500 to MN-740) [4]"]
radios: ["Wi-Fi 5 (802.11ac) 2.4 GHz + 5 GHz (Xbox Series X, Xbox One module 1525, Surface Pro 4) [4][5][6]", "Wi-Fi 4 (802.11n) (Xbox 360 modules, Xbox One controller) [4]", "Wi-Fi 802.11abg (Xbox 360 adapter WKS168) [4]", "BT Classic/BLE (Marvell 88W8897 combo in Surface Pro 4) [5]", "Xbox Wireless dedicated dual-band accessory radio (Series X) [6]"]
silicon: ["Marvell Avastar 88W8897 (802.11ac + Bluetooth + NFC) in Surface Pro 4 [5]", "Marvell 88W8897M / 88W8782U in Xbox One 802.11ac module 1525 [4]", "Qualcomm Atheros QCA4010 in Xbox One controller 1537 [4]", "Marvell 88W8388/88W8030 (WKS168), Atheros AR7010/AR9280 (1398), Atheros AR9271 (1399), Marvell 88W8786U (1400) in Xbox 360 adapters [4]", "MediaTek (model unrecorded) in Xbox One USB adapter 1790 [4]"]
fcc_grantee: ["C3K [4]"]
randomization: "mixed (Windows 10/11 offer a user-enabled 'random hardware addresses' setting, for all networks or per network; the support page does not state the default, and console and Surface firmware behaviour is not documented) [7]"
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Microsoft was founded on 4 April 1975 by Bill Gates and Paul Allen and is headquartered in Redmond, Washington; its own hardware began with the Surface in 2012 and spans Surface tablets and laptops, Xbox consoles (Series X/S since 2020) and HoloLens [8], plus Surface Hub, Azure Kinect and the discontinued Band and Zune lines [1]. The IEEE registry holds 108 prefixes (all MA-L plus one CID) for "Microsoft Corporation", registered from November 2000 through an October 2026 update [2], at One Microsoft Way, Redmond [3]. The most useful thing to know is that Microsoft OUIs are not all physical devices: DeviWiki's Microsoft page lists Xbox 360/One wireless modules, Surface models and the early-2000s MN-series routers under grantee code C3K [4], but Microsoft also registered blocks long before it shipped network hardware, so a Microsoft-OUI MAC on a LAN may be a virtual adapter rather than a Surface or Xbox. Documented silicon is Marvell for a decade - 88W8388 and 88W8786U in Xbox 360 adapters, 88W8897M in the Xbox One module 1525 [4], and the Marvell Avastar 88W8897 802.11ac/Bluetooth/NFC combo in the Surface Pro 4 [5] - with Qualcomm Atheros QCA4010 in the Xbox One controller and a MediaTek part in the 1790 USB adapter [4]; the Xbox Series X lists 802.11ac dual band, gigabit Ethernet and a dedicated dual-band Xbox Wireless accessory radio, and does not list Bluetooth [6]. Windows exposes "random hardware addresses" as a setting the user turns on, either for all networks or per network [7], so a Windows laptop may appear under a Microsoft or NIC-vendor OUI one day and a locally administered address the next; Xbox and Surface firmware behaviour is not documented. No vendor advisories specific to these radio modules were found.
## Sources
1. Microsoft hardware - Wikipedia - https://en.wikipedia.org/wiki/Microsoft_hardware (accessed 2026-10-27)
2. Microsoft Corporation MAC address blocks - maclookup.app - https://maclookup.app/vendors/microsoft-corporation (accessed 2026-10-27)
3. OUI 00:15:5D registrant record - maclookup.app - https://maclookup.app/macaddress/00155D (accessed 2026-10-27)
4. Microsoft vendor page (grantee C3K, device/chipset table) - DeviWiki - https://deviwiki.com/wiki/Microsoft (accessed 2026-10-27)
5. Microsoft Surface Pro 4 Teardown - iFixit - https://www.ifixit.com/Teardown/Microsoft+Surface+Pro+4+Teardown/51568 (accessed 2026-10-27)
6. Xbox Series X - Xbox.com - https://www.xbox.com/en-US/consoles/xbox-series-x (accessed 2026-10-27)
7. How to use random hardware addresses in Windows - Microsoft Support - https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc (accessed 2026-10-27)
8. Microsoft - Wikipedia - https://en.wikipedia.org/wiki/Microsoft (accessed 2026-10-27)
