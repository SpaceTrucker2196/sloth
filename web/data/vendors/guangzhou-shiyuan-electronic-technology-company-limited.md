---
name: Guangzhou Shiyuan Electronic Technology Company Limited
aliases: ["Guangzhou Shiyuan Electronics Co., Ltd."]
affiliates: []
country: CN [2][3]
parent: independent (listed on the Shenzhen Stock Exchange, 002841) [3]
founded: 2005 [3][4]
kind: odm/ems
device_classes: [tv, module-in-other-brands]
found_in: ["LCD TV mainboards supplied to unnamed global TV brands [5]", "MAXHUB conferencing interactive flat panels [3][4]", "seewo (希沃) education interactive flat panels [3][4]", "Widevine L1 Android device registered under the company name with model string 'MT6681' [7]"]
radios: []
silicon: ["'MT6681' model string in a Widevine L1 device registration under the company name; chip vendor not stated in the source [7]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: inferred, radios: unknown, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
Guangzhou Shiyuan Electronic Technology (trading as CVTE, Shenzhen Stock Exchange 002841) is a Guangzhou, China display-electronics maker founded in 2005 whose core business is LCD display control boards, and which held the world's leading position in LCD display mainboard shipments in 2024 according to Frost & Sullivan data [3][4]. Its own brands are MAXHUB (conferencing panels) and seewo (education panels); its board business supplies "core driving force for global TV brands" without naming them [3][4][5]. The IEEE registry holds 35 MA-L blocks under two spellings of the name [1], registered at No.6 4th Yunpu Road, Yunpu Industry District, Guangzhou [2]. A MAC in these blocks is therefore most likely a smart TV or an interactive flat panel whose mainboard was built by CVTE for another brand; the brand on the bezel is not recoverable from the OUI, and the one community scan log found shows such a host sitting on a home LAN with all scanned TCP ports closed, consistent with a TV [6]. A Widevine system-ID overview lists an L1-certified Android device under the company name with model "MT6681", which points at an Android-TV-class platform, but the source does not state the chip vendor [7]. No public documentation found for the radios integrated on CVTE boards, for FCC grantee codes, or for MAC randomization behaviour; no vendor advisories or CVEs were found under this name.
## Sources
1. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
2. maclookup.app 18:84:C1 registrant record - https://maclookup.app/macaddress/1884C1 (accessed 2026-10-27)
3. 视源股份 (Shiyuan Co.) - Chinese Wikipedia - https://zh.wikipedia.org/wiki/视源股份 (accessed 2026-10-27)
4. CVTE corporate site (English) - https://www.cvte.com/en (accessed 2026-10-27)
5. CVTE LCD TV mainboard solution page - https://www.cvte.com/solution/yjzb (accessed 2026-10-27)
6. Kali-sentinel nmap scan log showing a Guangzhou Shiyuan host - https://github.com/Harry-Khatri/Kali-sentinel/blob/782cb3399a210f33f0b5eaecc87e87fff508375b/scan/scan_2025-07-13_10-31.txt (accessed 2026-10-27)
7. WV-System-ID-Overview (Widevine device list) - https://github.com/Cronick/WV-System-ID-Overview/blob/main/Overview.csv (accessed 2026-10-27)
