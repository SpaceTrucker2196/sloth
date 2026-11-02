---
name: "vivo Mobile Communication Co., Ltd."
aliases: []
affiliates: []
country: CN [1][2]
parent: privately owned by Shen Wei since 2023, previously BBK Electronics (2009-2023) [1]
founded: 2009 [1]
kind: brand
device_classes: [phone [1][3], tablet [1], wearable [1]]
found_in: ["vivo X200, X200 Pro and X200 Pro Mini smartphones (MediaTek Dimensity 9400), X200 Ultra (Snapdragon 8 Elite) [4]", "iQOO and Jovi sub-brand devices [1]"]
radios: ["Wi-Fi 7 [4]", "BLE 4.x/5.x [4]", "LTE/5G [4]"]
silicon: ["MediaTek Dimensity 9400 in vivo X200, X200 Pro and X200 Pro Mini [4]", "Qualcomm Snapdragon 8 Elite in vivo X200 Ultra [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-12484: in a special mode for connecting to enterprise Wi-Fi certain options were not properly configured, so a same-named network could pose as the enterprise Wi-Fi for man-in-the-middle [5]", "CVE-2020-12492 and CVE-2021-26278: framework services mishandled Wi-Fi information and the Wi-Fi module exposed an interface with improper permission control, leaking sensitive information to malicious apps [5]", "CVE-2020-12483: exposed vivo appstore components allowed remote app download and install [5]", "CVE-2020-12487: vivo ABE service ran crafted commands with root privileges [5]", "India 2020: more than 13,500 vivo phones found operating with the same IMEI [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

vivo is a Chinese multinational technology company headquartered in Dongguan, Guangdong, founded in 2009 by Shen Wei and Duan Yongping; BBK Electronics owned it from 2009 to 2023 and Shen Wei has owned it since 2023 [1]. It makes smartphones, accessories, software and online services, including Vivo Watch wearables and Vivo Pad tablets, and sells under the sub-brands iQOO and Jovi, the latter in Brazil [1]. vivo's own site describes a manufacturing network with an annual capacity of nearly 200 million smartphones [3]. The IEEE registry lists 164 MA-L blocks to "vivo Mobile Communication Co., Ltd." at addresses in Chang'an, Dongguan [2].

A MAC in a vivo block is most likely a vivo or iQOO phone [1][2]. The vivo X200 family is documented with Wi-Fi 7, Bluetooth 5.4, 5G (SA/NSA, sub-6) and NFC, on a MediaTek Dimensity 9400 SoC, with the X200 Ultra on a Qualcomm Snapdragon 8 Elite [4]. NVD lists 25 CVEs assigned by vivo's own CNA, among them a Wi-Fi component that allowed a same-named rogue enterprise network (CVE-2020-12484) and framework and Wi-Fi interfaces that leaked Wi-Fi and device information to apps (CVE-2020-12492, CVE-2021-26278) [5]. In 2020 police in Meerut, India, registered a case after more than 13,500 vivo phones were found operating with the same IMEI [1].

Randomization is unknown: no source consulted states which Android version or randomization setting vivo ships. FCC grantee codes are not listed because the FCC ID databases (fccid.io, fcc.report, apps.fcc.gov) refused automated access from the session that wrote this entry; nothing is filled in from memory. iFixit's vivo X9 teardown identifies no chips [6].

## Sources
1. Vivo (technology company) - Wikipedia - https://en.wikipedia.org/wiki/Vivo_(technology_company) (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. About vivo - vivo - https://www.vivo.com/en/about-vivo/about (accessed 2026-10-27)
4. Vivo X200 - Wikipedia - https://en.wikipedia.org/wiki/Vivo_X200 (accessed 2026-10-27)
5. NVD CVE API, CVEs with source security@vivo.com - https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=security@vivo.com (accessed 2026-10-27)
6. Vivo X9 Teardown - iFixit - https://www.ifixit.com/Teardown/Vivo+X9+Teardown/190938 (accessed 2026-10-27)
