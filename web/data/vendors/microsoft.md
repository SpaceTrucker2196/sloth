---
name: Microsoft
aliases: ["Microsoft Corp.", "MICROSOFT CORP."]
country: US [1][2]
parent: independent [2]
founded: 1975 [2]
kind: brand [2]
device_classes: [laptop [3], tablet [3], console [2][4]]
found_in: ["Surface Pro, Surface Go, Surface Laptop, Surface Book and Surface Studio devices [3]", "Xbox consoles [2][4]", "Hyper-V virtual machines, whose dynamic MACs all start 00:15:5D [5]"]
radios: ["Wi-Fi 5 (Xbox Series X and S, 802.11ac) [4]", "Wi-Fi and Bluetooth on most Surface models listed [3]", "LTE/5G (Surface Pro LTE and 5G models, Surface Go LTE) [3]", "NFC (some Surface models) [3]"]
silicon: ["Marvell Avastar 88W8797 Wi-Fi/Bluetooth/FM SoC in Surface Pro 2 [6]", "Marvell Avastar (firmware 15.68.9125.57) in Surface 3, Surface Book, Surface Pro 4 and Surface Laptop (1st Gen) [7]"]
fcc_grantee: ["C3K (Surface FCC IDs such as C3K1796, C3K2010, C3K2103) [3]"]
randomization: optional: Windows offers random hardware addresses for all networks or per network when the Wi-Fi hardware supports it [8]; Hyper-V guests take 00:15:5D addresses from a per-host pool [5]
security_notes: ["VU#730261 / CVE-2019-6496: Marvell Avastar block pool overflow during Wi-Fi scans, Microsoft listed as affected for Surface models carrying Avastar firmware [7]", "CVE-2024-38032: Microsoft Xbox remote code execution, CVSS 3.1 7.1 from an adjacent network [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: documented}
researched: 2026-10-27
---
## Summary

Microsoft was founded on 4 April 1975 in Albuquerque by Bill Gates and Paul Allen and is headquartered in Redmond, Washington; its hardware includes the Xbox consoles (since 2001) and the Surface line (since 2012) [2]. The IEEE registry lists blocks under several spellings: over a hundred as Microsoft Corporation, nine MA-L blocks and one IAB as Microsoft, and single blocks as Microsoft Corp. and MICROSOFT CORP., all but two at Microsoft Way, Redmond [1]. Microsoft Mobile Oy, Microsoft XCG and Microsoft Research are separate registry names and are not aliases here [1].

A MAC in these blocks is a Surface laptop or tablet, an Xbox, or very often a Hyper-V virtual machine: Microsoft documents that Hyper-V builds dynamic MACs from its OUI 00:15:5D, the next two octets from the last two octets of the host's IP address and the last from a 256-address pool [5]. Microsoft's Surface regulatory page lists Wi-Fi and Bluetooth on most Surface models (a few entries list only Bluetooth LE or NFC, or no radios), LTE or 5G NR on the LTE and 5G models and NFC on some, with FCC IDs under grantee code C3K [3]. The Xbox Series X and S carry 802.11ac Wi-Fi [4].

iFixit's Surface Pro 2 teardown names a Marvell Avastar 88W8797 2x2 WLAN/Bluetooth/FM SoC [6]. CERT/CC's VU#730261 lists Microsoft as affected by the Avastar firmware flaw that lets an attacker in Wi-Fi range run code via malformed frames during network scans, naming Surface 3, Surface Book, Surface Book 2, Surface Pro 3, Surface Pro 4, Surface Pro (5th Gen), Surface Studio (1st Gen) and Surface Laptop (1st Gen) as devices with Avastar firmware 15.68.9125.57 [7]. NVD records CVE-2024-38032, a Microsoft Xbox remote code execution flaw scored 7.1 with an adjacent-network attack vector [9].

Windows offers random hardware addresses, for all networks or for one network, on Wi-Fi hardware that supports it, and Microsoft's page does not say whether it is on by default [8]. Newer Surface silicon was not documented by any source reachable from this session, since the FCC ID databases refused automated access.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) and IAB assignments (iab.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Microsoft - Wikipedia - https://en.wikipedia.org/wiki/Microsoft (accessed 2026-10-27)
3. Surface regulatory information - Microsoft Support - https://support.microsoft.com/zh-tw/surface/surface-%E6%B3%95%E8%A6%8F%E8%B3%87%E8%A8%8A-95f836fc-fcaa-4a06-96de-a04902d2889f (accessed 2026-10-27)
4. Xbox Series X and Series S - Wikipedia - https://en.wikipedia.org/wiki/Xbox_Series_X_and_Series_S (accessed 2026-10-27)
5. Windows Hyper-V server has a default limit of 256 dynamic MAC addresses - Microsoft Learn - https://learn.microsoft.com/en-us/troubleshoot/windows-server/virtualization/default-limit-256-dynamic-mac-addresses (accessed 2026-10-27)
6. Microsoft Surface Pro 2 Teardown - iFixit - https://www.ifixit.com/Guide/Microsoft+Surface+Pro+2+Teardown/18604 (accessed 2026-10-27)
7. VU#730261 Marvell Avastar wireless SoCs have multiple vulnerabilities - CERT/CC - https://kb.cert.org/vuls/id/730261/ (accessed 2026-10-27)
8. How to use random hardware addresses in Windows - Microsoft Support - https://support.microsoft.com/en-us/windows/how-to-use-random-hardware-addresses-in-windows-ac58de34-35fc-31ff-c650-823fc48eb1bc (accessed 2026-10-27)
9. CVE-2024-38032 - NVD CVE API - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-38032 (accessed 2026-10-27)
