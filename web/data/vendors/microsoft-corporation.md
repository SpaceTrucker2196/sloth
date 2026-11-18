---
name: Microsoft Corporation
aliases: [Microsoft, "Microsoft Corp.", "MICROSOFT CORP."]
affiliates: []
country: US [1][2]
parent: independent [2]
founded: 1975 [2]
kind: brand
device_classes: [tablet, laptop, console, ap/router, unknown]
found_in: ["Surface Pro 4 tablet [5]", "Surface Pro, Go, Laptop, Book, Studio and Hub lines [2][3][8]", "Xbox 360 wireless adapters and modules (WKS168, 1398, 1399, 1400, 1501) [4]", "Xbox One Wi-Fi module 1525, wireless controller 1537, USB adapter 1790 [4]", "Xbox consoles, the Series X and Series S among them [2][6][9]", "HoloLens headsets [2][3]", "Microsoft MN-series broadband routers (MN-500 to MN-740) [4]", "Hyper-V virtual machines, whose dynamic MACs all start 00:15:5D [10]"]
radios: ["Wi-Fi 5 (802.11ac) 2.4 GHz + 5 GHz (Xbox Series X and S, Xbox One module 1525, Surface Pro 4) [4][5][6][9]", "Wi-Fi 4 (802.11n) (Xbox 360 modules, Xbox One controller) [4]", "Wi-Fi 802.11abg (Xbox 360 adapter WKS168) [4]", "BT Classic/BLE (Marvell 88W8897 combo in Surface Pro 4) [5]", "Wi-Fi and Bluetooth on most Surface models listed [8]", "LTE/5G (Surface Pro LTE and 5G models, Surface Go LTE) [8]", "NFC (some Surface models) [8]", "Xbox Wireless dedicated dual-band accessory radio (Series X) [6]"]
silicon: ["Marvell Avastar 88W8897 (802.11ac + Bluetooth + NFC) in Surface Pro 4 [5]", "Marvell Avastar 88W8797 Wi-Fi/Bluetooth/FM SoC in Surface Pro 2 [11]", "Marvell Avastar (firmware 15.68.9125.57) in Surface 3, Surface Book, Surface Pro 4 and Surface Laptop (1st Gen) [12]", "Marvell 88W8897M / 88W8782U in Xbox One 802.11ac module 1525 [4]", "Qualcomm Atheros QCA4010 in Xbox One controller 1537 [4]", "Marvell 88W8388/88W8030 (WKS168), Atheros AR7010/AR9280 (1398), Atheros AR9271 (1399), Marvell 88W8786U (1400) in Xbox 360 adapters [4]", "MediaTek (model unrecorded) in Xbox One USB adapter 1790 [4]"]
fcc_grantee: ["C3K (Surface FCC IDs such as C3K1796, C3K2010, C3K2103) [4][8]"]
randomization: "mixed (Windows offers random hardware addresses, for all networks or per network, on Wi-Fi hardware that supports it, and the support page does not state the default; Hyper-V guests take 00:15:5D addresses from a per-host pool; console and Surface firmware behaviour is not documented) [7][10]"
security_notes: ["VU#730261 / CVE-2019-6496: Marvell Avastar block pool overflow during Wi-Fi scans, Microsoft listed as affected for Surface models carrying Avastar firmware [12]", "CVE-2024-38032: Microsoft Xbox remote code execution, CVSS 3.1 7.1 from an adjacent network [13]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary

Microsoft was founded on 4 April 1975 in Albuquerque by Bill Gates and Paul Allen and is headquartered in Redmond, Washington; its hardware includes the Xbox consoles (since 2001), the Surface line (since 2012) and HoloLens [2], plus Surface Hub, Azure Kinect and the discontinued Band and Zune lines [3]. In the registry copies shipped with sloth (ieee-data 20260625) Microsoft holds 101 MA-L blocks as Microsoft Corporation, nine MA-L blocks and one IAB as Microsoft, and one MA-L block each as Microsoft Corp. and MICROSOFT CORP.; all but two (a Federal Way, Washington block and the IAB's Redmond building address) are at Microsoft Way, Redmond, so the four spellings are one registrant and this entry is keyed by all of them [1]. Microsoft Mobile Oy, Microsoft XCG and Microsoft Research are separate registry names and are not aliases here [1].

A MAC in these blocks is a Surface laptop or tablet, an Xbox, or very often a Hyper-V virtual machine: Microsoft documents that Hyper-V builds dynamic MACs from its OUI 00:15:5D, the next two octets from the last two octets of the host's IP address and the last from a 256-address pool [10]. DeviWiki's Microsoft page lists Xbox 360 and Xbox One wireless modules, Surface models and the early-2000s MN-series routers under grantee code C3K [4], and Microsoft's Surface regulatory page lists Wi-Fi and Bluetooth on most Surface models (a few entries list only Bluetooth LE or NFC, or no radios), LTE or 5G NR on the LTE and 5G models and NFC on some, with FCC IDs under C3K [8]. The Xbox Series X and S carry 802.11ac Wi-Fi [9]; the Series X lists dual-band 802.11ac, gigabit Ethernet and a dedicated dual-band Xbox Wireless accessory radio, and does not list Bluetooth [6].

Documented silicon is Marvell for a decade: 88W8388 and 88W8786U in Xbox 360 adapters and 88W8897M in the Xbox One module 1525 [4], the Avastar 88W8797 2x2 WLAN/Bluetooth/FM SoC in the Surface Pro 2 [11] and the Avastar 88W8897 802.11ac/Bluetooth/NFC combo in the Surface Pro 4 [5], with Qualcomm Atheros QCA4010 in the Xbox One controller and a MediaTek part in the 1790 USB adapter [4]. CERT/CC's VU#730261 lists Microsoft as affected by the Avastar firmware flaw that lets an attacker in Wi-Fi range run code via malformed frames during network scans, naming Surface 3, Surface Book, Surface Book 2, Surface Pro 3, Surface Pro 4, Surface Pro (5th Gen), Surface Studio (1st Gen) and Surface Laptop (1st Gen) as devices with Avastar firmware 15.68.9125.57 [12]. NVD records CVE-2024-38032, a Microsoft Xbox remote code execution flaw scored 7.1 with an adjacent-network attack vector [13].

Windows offers random hardware addresses, for all networks or for one network, on Wi-Fi hardware that supports it, and Microsoft's page does not say whether it is on by default [7], so a Windows laptop may appear under a Microsoft or NIC-vendor OUI one day and a locally administered address the next. Xbox and Surface firmware behaviour is not documented, and newer Surface silicon was not documented by any source reachable from the sessions that wrote this entry, since the FCC ID databases refused automated access.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) and IAB assignments (iab.csv) (read from the copies shipped in sloth web/data/, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Microsoft - Wikipedia - https://en.wikipedia.org/wiki/Microsoft (accessed 2026-10-27)
3. Microsoft hardware - Wikipedia - https://en.wikipedia.org/wiki/Microsoft_hardware (accessed 2026-10-27)
4. Microsoft vendor page (grantee C3K, device/chipset table) - DeviWiki - https://deviwiki.com/wiki/Microsoft (accessed 2026-10-27)
5. Microsoft Surface Pro 4 Teardown - iFixit - https://www.ifixit.com/Teardown/Microsoft+Surface+Pro+4+Teardown/51568 (accessed 2026-10-27)
6. Xbox Series X - Xbox.com - https://www.xbox.com/en-US/consoles/xbox-series-x (accessed 2026-10-27)
7. How to use random hardware addresses in Windows - Microsoft Support - https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc (accessed 2026-10-27)
8. Surface regulatory information - Microsoft Support - https://support.microsoft.com/zh-tw/surface/surface-%E6%B3%95%E8%A6%8F%E8%B3%87%E8%A8%8A-95f836fc-fcaa-4a06-96de-a04902d2889f (accessed 2026-10-27)
9. Xbox Series X and Series S - Wikipedia - https://en.wikipedia.org/wiki/Xbox_Series_X_and_Series_S (accessed 2026-10-27)
10. Windows Hyper-V server has a default limit of 256 dynamic MAC addresses - Microsoft Learn - https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/default-limit-256-dynamic-mac-addresses (accessed 2026-10-27)
11. Microsoft Surface Pro 2 Teardown - iFixit - https://www.ifixit.com/Guide/Microsoft+Surface+Pro+2+Teardown/18604 (accessed 2026-10-27)
12. VU#730261 Marvell Avastar wireless SoCs have multiple vulnerabilities - CERT/CC - https://kb.cert.org/vuls/id/730261/ (accessed 2026-10-27)
13. CVE-2024-38032 - NVD CVE API - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38032 (accessed 2026-10-27)
