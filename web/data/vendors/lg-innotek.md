---
name: LG Innotek
aliases: []
affiliates: []
country: KR [1]
parent: LG Electronics (40.8% owner) / LG Group [1][2]
founded: 1970 [1]
kind: module-maker
device_classes: [camera, automotive-infotainment, automotive-telematics, module-in-other-brands]
found_in: ["UDP Technology IPN100HD IP camera (TWFMKB304D Wi-Fi module; label OUI 94:44:44) [4]", "Audio/Video/Navigation head units of an unnamed European Tier-1 supplier, Wi-Fi 7 module in mass production from 2027 [3]", "Automotive 5G-V2X, 5G-NAD and automotive AP modules for OEMs (customers not named) [3]"]
radios: ["Wi-Fi 4 [4]", "2.4 GHz [4]", "Wi-Fi 7 (320 MHz channels, 4K-QAM, 2-antenna MIMO) [3]"]
silicon: ["Broadcom BCM43234 in TWFMKB304D (802.11bgn 1x1, USB) [4]", "Qualcomm Wi-Fi 7 chip (part not named) in the automotive Wi-Fi 7 communication module [3]"]
fcc_grantee: ["YZP [4]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
LG Innotek is the LG group's electronic-components arm, founded in February 1970 as Goldstar Precision and headquartered in Seoul, with LG Electronics holding 40.8% [1] (Korean Wikipedia dates it to February 1976 as Goldstar Alps Electronics and gives 40.79% [2]); most of its revenue comes from camera modules for the iPhone, which carry no MAC address [1]. The IEEE lists some fifty 24-bit blocks under this name; the twelve checked (4C:BA:D7, 64:CB:E9, F8:B9:5A, C4:36:6C, 1C:08:C1, CC:88:26, 2C:2B:F9, A0:6F:AA, 14:7F:67, 34:E6:E6, 30:34:DB, 1C:D3:AF) and 94:44:44 are all registered to Gwangju (Gwangsan-gu) plant addresses rather than the Seoul HQ, with two early blocks (00:05:C9, 00:1E:B2) at an Ansan R&D address [5]. On the air an LG Innotek OUI is a Wi-Fi module embedded in someone else's product: the one documented teardown is the TWFMKB304D (Broadcom BCM43234, 802.11bgn, FCC ID YZP-TWFMKB304D) inside a UDP Technology IP camera, whose label shows the 94:44:44 LG Innotek OUI [4]. The company's current radio business is automotive: it ships 5G-V2X, 5G-NAD and automotive AP modules, and in April 2026 announced a Qualcomm-based automotive Wi-Fi 7 module (320 MHz channels, 4K-QAM, dual-antenna MIMO, -40 to 105 C) for AVN head units of a European parts supplier, with TCU, RSE and DCU applications planned and mass production from 2027 [3]. Korean sources describe the automotive line as vehicle electrical components (ABS motors, torque angle sensors, transmission motors) without naming radio products [2]. Whether products with these OUIs randomize MACs is not documented in any source reached; embedded modules in cameras and head units are typically operated by the host, so treat behaviour as host-defined. No vendor-specific CVE class was looked up for this vendor.
## Sources
1. Wikipedia: LG Innotek - https://en.wikipedia.org/wiki/LG_Innotek (accessed 2026-10-27)
2. Korean Wikipedia: LG이노텍 - https://ko.wikipedia.org/wiki/LG이노텍 (accessed 2026-10-27)
3. PR Newswire: LG Innotek to Supply Cutting-Edge Automotive Wi-Fi 7 Communication Module to a leading European automotive parts company (2026-04-20) - https://prnewswire.com/news-releases/lg-innotek-to-supply-cutting-edge-automotive-wi-fi-7-communication-module-to-a-leading-european-automotive-parts-company-302746752.html (accessed 2026-10-27)
4. DeviWiki: UDP Technology IPN100HD (LG Innotek TWFMKB304D module) - https://deviwiki.com/wiki/UDP_Technology_IPN100HD (accessed 2026-10-27)
5. IEEE Registration Authority MA-L registry, the copy committed in sloth as web/data/oui.csv (Debian ieee-data 20260625) - https://github.com/SpaceTrucker2196/sloth/blob/main/web/data/oui.csv (accessed 2026-11-02)
