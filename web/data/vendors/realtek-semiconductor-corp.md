---
name: REALTEK SEMICONDUCTOR CORP.
aliases: ["Realtek Semiconductor Corp."]
affiliates: []
country: TW [1][2]
parent: independent [2]
founded: 1987 [2]
kind: chip-vendor
device_classes: [ap/router, laptop, iot-sensor, smart-home, tv, module-in-other-brands, unknown]
found_in: ["USB and PCIe Wi-Fi adapters and embedded boards built on RTL8188/RTL8189/RTL8191/RTL8192 families (DeviWiki documents 141 embedded systems on RTL8192CE alone; RTL8189ETV/FTV SDIO parts in Orange Pi boards) [3]", "Laptops and embedded Linux devices using RTL8723/RTL8821/RTL8822 (rtw88) and RTL8851/RTL8852/RTL8922 (rtw89) PCIe/USB/SDIO modules [4][5]", "Wi-Fi 7 AP routers on RTL8198G/RTL8198GB SoCs with RTL8932BR/RTL8934AR/RTL8902B radios (BE3600/BE7200 reference designs) [6]", "Consumer routers and IoT devices built on the Realtek 'Jungle' and eCos AP/router SDKs (D-Link and others, per CVE references) [7][8][9]"]
radios: ["Wi-Fi 4 (802.11b/g/n, RTL8188/8189/8191/8192 1x1 and 2x2) [3]", "Wi-Fi 5-class parts handled by Linux rtw88 (RTL8812A/8814A/8821A/8821C/8822B/8822C; generation inferred from the part numbers, the driver listing names no standard) [4]", "Wi-Fi 6/6E-class parts handled by Linux rtw89 (RTL8851B/8852A/8852B/8852BT/8852C; generation inferred as above) [5]", "Wi-Fi 7 (RTL8922A/RTL8922D clients, RTL8198G-family AP SoCs with BE3600/BE7200 designs) [5][6]", "2.4 GHz [3]", "5 GHz (dual-band parts; inferred from the part numbers) [4]", "BT Classic / BLE (RTL8723/RTL8821/RTL8822/RTL8852 combos; RTL8922D 'Wi-Fi/Bluetooth combo'; RTL8773DO Bluetooth wearable SoC) [4][6]", "Ethernet (RTL8139 and RTL8111 historically, RTL8127/RTL8159/RTL8261D today) [2][6]"]
silicon: ["RTL8180/8185/8187 802.11b/g, RTL8188C/E, RTL8189E/F, RTL8191S/C, RTL8192C/D/E/S, RTL8194AR 4x4 802.11n [3]", "RTL8703B, RTL8723B/D, RTL8812A, RTL8814A, RTL8821A/C, RTL8822B/C (Linux rtw88, PCI/USB/SDIO) [4]", "RTL8851B, RTL8852A/B/BT/C, RTL8922A/D (Linux rtw89) [5]", "RTL8198G/RTL8198GB AP SoCs, RTL8932BR, RTL8934AR, RTL8902B, RTL8194EAR, RTL8735C AIoT SoC, RTL8773DO [6]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2021-35394 (CVSS 9.8): Realtek Jungle SDK v2.x-v3.4.14B 'MP Daemon' UDPServer memory corruption and command injection, unauthenticated remote; in CISA KEV since December 2021 [7]", "CVE-2022-27255: stack overflow in SIP ALG of Realtek eCos RSDK 1.5.7p1 / MSDK 4.9.4p1, unauthenticated RCE via crafted SDP [8]", "CVE-2014-8361 (CVSS 9.8): Realtek SDK miniigd UPnP SOAP RCE, in CISA KEV (September 2023), used by HinataBot [9]", "2010: a Realtek code-signing certificate was compromised and used to sign malicious drivers; revoked by Verisign [2]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Realtek is a fabless semiconductor company founded in October 1987 and based in Hsinchu Science Park, Taiwan (TWSE 2379), making communications-network ICs (Ethernet, wireless LAN), computer peripheral ICs and multimedia ICs; its RTL8139 Fast Ethernet controllers held about 70% of the world market as of 2003 [2][11]. The IEEE lists three Realtek blocks: the 2000-vintage MA-L 00:E0:4C, a 2025 MA-S 8C:1F:64:D5:A and a June 2026 MA-L FC:93:4E [1][10]. Because Realtek sells chips, not boxes, a MAC in 00:E0:4C is a device whose maker left Realtek's default address in the Wi-Fi or Ethernet silicon: cheap USB Wi-Fi dongles and embedded boards on the RTL8188/8192 families (DeviWiki counts 141 embedded systems on RTL8192CE alone) [3], laptops and SBCs with the RTL8723/8821/8822 parts of Linux rtw88 or the RTL8852/8922 parts of rtw89 [4][5], and routers built on Realtek AP SoCs, which today reach Wi-Fi 7 with the RTL8198G/GB plus RTL8932BR/RTL8934AR radios [6]. Expect anything from a 2.4 GHz-only 1x1 802.11n client to a Wi-Fi 7 AP; the Wi-Fi generation of the rtw88 and rtw89 parts is inferred from their part numbers, since the kernel driver listings name files, not standards [4][5]. The security record is dominated by Realtek's router/IoT SDKs rather than its PC parts: CVE-2021-35394 (Jungle SDK UDPServer, CVSS 9.8, in CISA's KEV) [7], CVE-2022-27255 (eCos SDK SIP ALG stack overflow) [8] and CVE-2014-8361 (miniigd UPnP RCE, in CISA's KEV and exploited in the wild through 2023) [9], so a Realtek-default MAC on a router-class device is a reasonable prompt to check firmware age. Realtek's own advisory listing page rendered as a news feed with no advisories in this session, and the FCC ID databases were unreachable (HTTP 403), so no grantee code is recorded.
## Sources
1. MAC prefix 00:E0:4C - maclookup.app - https://maclookup.app/macaddress/00E04C (accessed 2026-10-27)
2. Realtek - Wikipedia - https://en.wikipedia.org/wiki/Realtek (accessed 2026-10-27)
3. Realtek (chipset list) - DeviWiki - https://deviwiki.com/wiki/Realtek (accessed 2026-10-27)
4. drivers/net/wireless/realtek/rtw88 - Linux kernel source tree (GitHub API listing) - https://api.github.com/repos/torvalds/linux/contents/drivers/net/wireless/realtek/rtw88 (accessed 2026-10-27)
5. drivers/net/wireless/realtek/rtw89 - Linux kernel source tree (GitHub API listing) - https://api.github.com/repos/torvalds/linux/contents/drivers/net/wireless/realtek/rtw89 (accessed 2026-10-27)
6. Communications Network ICs / What's Hot - Realtek - https://www.realtek.com/en/products/communications-network-ics (accessed 2026-10-27)
7. CVE-2021-35394 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2021-35394 (accessed 2026-10-27)
8. CVE-2022-27255 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2022-27255 (accessed 2026-10-27)
9. CVE-2014-8361 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2014-8361 (accessed 2026-10-27)
10. REALTEK SEMICONDUCTOR CORP. MAC address blocks - maclookup.app - https://maclookup.app/vendors/realtek-semiconductor-corp (accessed 2026-10-27)
11. About Realtek - https://www.realtek.com/en/about-realtek (accessed 2026-10-27)
