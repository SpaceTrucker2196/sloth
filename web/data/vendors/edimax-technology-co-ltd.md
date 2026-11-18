---
name: Edimax Technology Co. Ltd.
aliases: []
affiliates: []
country: TW [1][2]
parent: unknown
founded: 1986 [2]
kind: brand [2][3]
device_classes: [ap/router [3], switch [3], camera [2][6], smart-home [3]]
found_in: ["Edimax EW-7811Un USB Wi-Fi adapter [5]", "Edimax Pro IAP1200 access point [4]", "Belkin F5D7230-4 v9 and Hercules HWGUSB2-54V2-AP, which carry Edimax part-number labels [4]", "Edimax IC-7100 IP camera [6]"]
radios: ["Wi-Fi 4/5 [4][5]", "5 GHz [4]"]
silicon: ["Realtek RTL8188CUS in EW-7811Un [5]", "MediaTek MT7620A and MT7610E in BR-6208AC v2 [4]", "MediaTek MT7620A and MT7612EN in Edimax Pro IAP1200 [4]", "Qualcomm QCA9984 in EW-7955MN and EW-7955MAC [4]"]
fcc_grantee: ["NDD [4][5]"]
randomization: unknown
security_notes: ["CVE-2025-1316: IC-7100 IP camera fails to neutralise crafted requests, allowing remote code execution (published 2025-03-04) [6]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Edimax Technology was founded in June 1986 in Taipei, Taiwan, is headquartered in the Neihu District of Taipei and has traded on the Taiwan Stock Exchange (3047) since 2001 [2]. The IEEE registry lists seven MA-L blocks to "Edimax Technology Co. Ltd." at a Neihu, Taipei address [1]. Its own site groups its products as industrial and business switches and PoE gear, the Edimax Pro business line, home wireless routers and whole-home Wi-Fi systems, range extenders, USB adapters, smart plugs, powerline devices, air-quality sensors and network cameras [3], and Wikipedia also lists IP cameras [2].

A MAC in an Edimax block is most likely an Edimax-branded USB adapter, router, access point or camera; WikiDevi also shows Edimax part-number labels on Belkin and Hercules adapters, so the label on the box may name another brand [4]. Documented silicon is the Realtek RTL8188CUS (802.11b/g/n, 1x1) in the EW-7811Un USB adapter [5], MediaTek MT7620A with MT7610E in the BR-6208AC v2 router, MediaTek MT7620A with MT7612EN in the Edimax Pro IAP1200 and Qualcomm QCA9984 in the EW-7955 adapters [4]. WikiDevi gives NDD as Edimax's FCC grantee code, and the EW-7811Un's FCC ID is NDD9578111008 [4][5].

CVE-2025-1316 records that the Edimax IC-7100 IP camera does not neutralise specially crafted requests, allowing remote code execution [6]. The sources list 802.11b/g/n and 802.11a/n/ac modes and name 5 GHz products but do not state 2.4 GHz in words, so only 5 GHz is listed as a band [4][5]. Randomization is unknown: no source consulted documents it, and the FCC ID databases themselves (fccid.io, fcc.report) refused the session that wrote this entry.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Edimax - Wikipedia - https://en.wikipedia.org/wiki/Edimax (accessed 2026-10-27)
3. Edimax global site - https://www.edimax.com/edimax/global/ (accessed 2026-10-27)
4. Edimax - WikiDevi - https://wikidevi.wi-cat.ru/Edimax (accessed 2026-10-27)
5. Edimax EW-7811Un - WikiDevi - https://wikidevi.wi-cat.ru/Edimax_EW-7811Un (accessed 2026-10-27)
6. CVE-2025-1316 record - CVE.org - https://cveawg.mitre.org/api/cve/CVE-2025-1316 (accessed 2026-10-27)
