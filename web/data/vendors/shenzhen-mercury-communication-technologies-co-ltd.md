---
name: "SHENZHEN MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD."
aliases: ["MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD."]
affiliates: []
country: CN [1]
parent: TP-Link [2]
founded: unknown
kind: brand [3]
device_classes: [ap/router [3][4], camera [3][6], switch [3]]
found_in: ["Mercury MW305R v3.x wireless router, listed by DeviWiki under manufacturer/OEM/ODM TP-LINK TL-WR842N v4 [4]", "Mercury MAC1200R, MER1200, D196G and other Mercury routers [5][7]", "Mercury MIPC series IP cameras [6]"]
radios: ["Wi-Fi 4 [4]", "Wi-Fi 6 [3]", "Wi-Fi 7 [3]", "2.4 GHz [4]"]
silicon: ["Qualcomm Atheros QCA9531 SoC and radio in the Mercury MW305R v3.x [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Mercury routers: directory traversal on the MAC1200R (CVE-2021-27825) [7]", "Mercury routers: PPTP server command execution on the MER1200 (CVE-2020-22724), stack overflows shared with TP-Link and Fast firmware on the D196G (CVE-2022-26987, CVE-2022-26988) [5]", "Mercury MIPC IP cameras: remote code execution on the MIPC451-4 (CVE-2022-31849) and a run of RTSP authentication and denial-of-service flaws on the MIPC252W (2026) [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Shenzhen Mercury Communication Technology is described by Wikipedia as a Chinese-market subsidiary of TP-Link [2]. The IEEE registry lists 19 MA-L blocks to "SHENZHEN MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD." at Keyuan West, Shenzhen, and 8 to "MERCURY COMMUNICATION TECHNOLOGIES CO.,LTD." at Building 28, Cui Xi Fourth Road, Ke Yuan West, Nanshan, Shenzhen [1]; treating the two as one company rests on the shared name and district, an inference. Mercury's own Chinese site, whose copyright line names Shenzhen Mercury, sells routers including Wi-Fi 6 and Wi-Fi 7 models, network cards, enterprise wireless, switches, security cameras and network video recorders, and power-line adapters [3].

A MAC in these blocks is most likely a Mercury home router or IP camera on a Chinese network [3]. The Mercury MW305R v3.x, which DeviWiki lists under manufacturer/OEM/ODM TP-LINK TL-WR842N v4, is a Qualcomm Atheros QCA9531 2x2 802.11b/g/n router [4], which fits the TP-Link parentage [2].

NVD records a directory traversal on the MAC1200R [7], a PPTP command execution on the MER1200 and stack overflows on the D196G shared with TP-Link and Fast firmware [5], plus remote code execution on the MIPC451-4 camera and a series of RTSP authentication flaws on the MIPC252W [6]. Founding year, FCC grantee codes and randomization are unknown; the FCC ID databases refused the session's requests.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Mercury (disambiguation) - Wikipedia - https://en.wikipedia.org/wiki/Mercury_(company) (accessed 2026-10-27)
3. Mercury official site - https://www.mercurycom.com.cn/ (accessed 2026-10-27)
4. Mercury MW305R v3.x - DeviWiki - https://deviwiki.com/wiki/Mercury_MW305R_v3.x (accessed 2026-10-27)
5. Mercury router CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Mercury%20Router (accessed 2026-10-27)
6. Mercury MIPC CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Mercury%20MIPC (accessed 2026-10-27)
7. Mercury MAC1200R CVE record - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MERCURY%20MAC1200R (accessed 2026-10-27)
