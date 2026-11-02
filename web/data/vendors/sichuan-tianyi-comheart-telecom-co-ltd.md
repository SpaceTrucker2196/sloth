---
name: "Sichuan Tianyi Comheart Telecom Co.,LTD"
aliases: ["Sichuan tianyi kanghe communications co., LTD"]
country: CN [1][2]
parent: listed company, stock code 300504 [1][2]
founded: 2001 [1][2]
kind: network-equipment [1][3]
device_classes: [ap/router [1][3][5]]
found_in: ["GPON ONUs TG141, TG2212, TG5241, TG6241 and FG-R020 [3]", "China Telecom Tianyi Home Gateway TEWA-700G [5]"]
radios: ["Wi-Fi 4 (802.11n 2x2) in TG2212 [3]", "Wi-Fi 6 dual-band in TG6241 [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["China Telecom Tianyi Home Gateway TEWA-700G: insecure permissions exposing the default password to a local attacker (CVE-2023-41010) [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sichuan Tianyi Comheart Telecom, whose Chinese name is 四川天邑康和通信股份有限公司, was founded in 2001 and is based at No. 198, Section 1, Snow Mountain (Xueshan) Avenue, Dayi County, Chengdu, under stock code 300504 [1][2]. The IEEE registry lists 88 MA-L blocks and one MA-M block to "Sichuan Tianyi Comheart Telecom Co.,LTD", and five more MA-L blocks to "Sichuan tianyi kanghe communications co., LTD" at the same Xueshan Avenue address [4][6]. Kanghe matches 康和 in the company's Chinese name, and NVD names a "Sichuan Tianyi Kanghe Communication Co., Ltd" as the maker of a China Telecom gateway, so this entry treats both registry spellings as one company [2][4][5]. Its English site lists broadband network terminals, mobile communication network products, physical links and heat-shrink products, and its title names GPON ONU/ONT, 5G CPE, Wi-Fi 6 routers and IPTV set-top boxes [1].

A MAC in a Comheart block is most likely a fibre ONU or home gateway supplied by a Chinese broadband operator [1][3][5]. Its GPON ONU catalogue runs from a plain four-port unit to the TG2212 with 2x2 802.11n and the TG6241 with dual-band Wi-Fi 6 [3]. NVD records a China Telecom Tianyi Home Gateway, the TEWA-700G, which it attributes to Sichuan Tianyi Kanghe Communication, whose insecure permissions expose its default password (CVE-2023-41010) [5].

Silicon and FCC grantee codes are not listed: the FCC ID databases refused requests from this session and no teardown was found, and nothing is filled in from memory. Randomization behaviour is not documented.

## Sources

1. Sichuan Tianyi Comheart Telecom, English site - http://en.tianyisc.com/ (accessed 2026-10-27)
2. 四川天邑康和通信股份有限公司, Chinese site - http://www.tianyisc.com/ (accessed 2026-10-27)
3. Tianyi Comheart broadband network terminal products - http://en.tianyisc.com/product.aspx?t=15&s=44 (accessed 2026-10-27)
4. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
5. NVD CVE-2023-41010 - https://nvd.nist.gov/vuln/detail/CVE-2023-41010 (accessed 2026-10-27)
6. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
