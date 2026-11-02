---
name: "Qihoo  360  Technology Co.,Ltd"
aliases: []
affiliates: []
country: CN [1][2]
parent: none named; listed on the Shanghai Stock Exchange [2]
founded: 2005 [2]
kind: brand [2]
device_classes: [ap/router [3][4], wearable [2]]
found_in: ["360 Safe Router P0 to P4 [3]", "360F5 router [4]", "Xplora children's smartwatches made by Qihoo [2]"]
radios: ["Wi-Fi [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2018-19031: command injection in 360 Safe Router P0 to P4 firmware V2.0.61.58897 [3]", "CVE-2019-3405: 360F5 firmware 3.1.3.64296 and earlier can be made to send deauthentication frames by a crafted 802.11 Null Data frame [4]", "2020 report of a backdoor in Qihoo-made Xplora children's watches; US Entity List since May 2020 [2]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Qihoo 360 was founded in June 2005 by Zhou Hongyi and Qi Xiangdong, is headquartered in Chaoyang, Beijing, and after leaving the New York Stock Exchange in a roughly 9.3 billion US dollar take-private agreed in December 2015 is listed in Shanghai [2]. It is best known for security software and was added to the US Entity List in May 2020 [2]. The IEEE registry lists one MA-L block, D0:FA:1D, to Qihoo  360  Technology Co.,Ltd at a Beijing address, while two further blocks belong to the separate registrant Shenzhen Qihoo Intelligent Technology Co.,Ltd, not merged here [1].

A MAC in this block is most likely a 360-branded consumer device such as a 360 Wi-Fi router or a Qihoo-made children's smartwatch [2][3][4]. The 360 Safe Router P0 to P4 on firmware V2.0.61.58897 have a command injection flaw, CVE-2018-19031 [3], and the 360F5 router could be made to transmit deauthentication frames that disconnect its own clients, CVE-2019-3405, fixed by a firmware update [4]. In 2020 Mnemonic reported a backdoor in Xplora children's watches made by Qihoo [2].

No teardown naming silicon was found, the FCC ID databases refused this session's requests so no grantee code is listed, and no source documents MAC randomization.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Qihoo 360 - Wikipedia - https://en.wikipedia.org/wiki/Qihoo_360 (accessed 2026-10-27)
3. CVE-2018-19031 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2018-19031 (accessed 2026-10-27)
4. CVE-2019-3405 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-3405 (accessed 2026-10-27)
