---
name: DrayTek Corp.
aliases: []
affiliates: []
country: TW [1][2]
parent: unknown
founded: 1997 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][3], switch [2]]
found_in: ["DrayTek Vigor routers such as the Vigor 2865ax, 2927ax and 3912S [2]", "DrayTek AP1060C access point [2]", "Vigor 2862ac, 2865Vac and 2915ac wireless routers [3]"]
radios: ["Wi-Fi 4/5/6 [3]"]
silicon: ["Intel (Lantiq) GRX350A3 with Intel WAV654A1 Wi-Fi in Vigor 2865ax [3]", "Intel (Lantiq) GRX350A3 with MediaTek MT7615DN in Vigor 2865Vac [3]", "MediaTek MT7621AT with MT7615DN in Vigor 2915ac [3]", "Lantiq PSB 80920 with Ralink RT5392L and Qualcomm Atheros QCA9880 in Vigor 2860ac [3]"]
fcc_grantee: ["VGY [3]"]
randomization: unknown
security_notes: ["CVE-2024-41592: stack-based overflow in query-string handling on Vigor3910 through firmware 4.3.2.6 (published 2024-10-03) [4]", "Press reports of DrayTek routers hijacked in 2023 and of 700,000+ internet-exposed routers open to remote hijacking in 2024 [2]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

DrayTek is a Taiwanese maker of customer-premises network equipment, founded in 1997 and headquartered in Hsinchu, selling firewalls, VPN devices, routers, managed switches and wireless LAN gear under the Vigor name [2]. The IEEE registry lists three MA-L blocks to "DrayTek Corp.", all at No. 26 Fushing Road, Hsinchu, two of them giving Hukou [1].

A MAC in a DrayTek block is most likely a Vigor router at a small-business or branch-office edge, or a DrayTek access point [2]. WikiDevi documents the silicon across the line: older Vigor models on Samsung S3C2510 and Infineon/Lantiq SoCs with Ralink or Atheros Wi-Fi, the 2865Vac on an Intel (Lantiq) GRX350A3 with a MediaTek MT7615DN, the 2865ax on the same GRX350A3 with an Intel WAV654A1 for Wi-Fi 6, and the 2915ac on a MediaTek MT7621AT with an MT7615DN [3]. WikiDevi gives VGY (Draytek Corporation) as the FCC grantee code and lists PHY modes from 802.11b/g/n to 802.11ax, but names no band in GHz, so no band is listed [3].

Wikipedia records severe vulnerabilities in DrayTek products in recent years, citing reports of hijacked routers in 2023, over 700,000 exposed routers open to remote hijacking in 2024 and a critical RCE across 29 models [2]. CVE-2024-41592 is one of them: a stack-based overflow in query-string handling on the Vigor3910 through firmware 4.3.2.6 [4]. Parent company and randomization are not documented by the sources consulted, and DrayTek's own about page refused the session that wrote this entry.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. DrayTek - Wikipedia - https://en.wikipedia.org/wiki/DrayTek (accessed 2026-10-27)
3. DrayTek - WikiDevi - https://wikidevi.wi-cat.ru/DrayTek (accessed 2026-10-27)
4. CVE-2024-41592 record - CVE.org - https://cveawg.mitre.org/api/cve/CVE-2024-41592 (accessed 2026-10-27)
