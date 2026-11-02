---
name: DWnet Technologies(Suzhou) Corporation
aliases: []
affiliates: []
country: CN [1][2]
parent: Sercomm Corporation, which lists DWnet Technology (Suzhou) Co. Ltd. among its sites and serves its own site from dwnet.com.cn [2][3]
founded: unknown
kind: odm/ems [2][3]
device_classes: [ap/router [3]]
found_in: []
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["TCP 32764 backdoor in Linksys, Netgear and Cisco routers, whose probable source the researcher names as parent Sercomm [4]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists nine MA-L blocks to DWnet Technologies(Suzhou) Corporation at No.8 Tangzhuang Road, Suzhou Industrial Park, Jiangsu [1]. Sercomm's contact page lists DWnet Technology (Suzhou) Co. Ltd. among its global sites at No. 26 Xinghai Street in the same park, sharing that address with Sercomm (Suzhou) Corporation, while the registry's No.8 Tangzhuang Road address is listed there for Sernet (Suzhou) Technology [2], and the dwnet.com.cn domain now serves Sercomm Corporation's own site [3].

Sercomm presents itself as a broadband and IoT equipment and manufacturing-services company with over three decades in broadband: DOCSIS, fibre, DSL and fixed-wireless 4G/5G CPEs, Wi-Fi routers, mesh repeaters and IP streamers, plus small cells, IoT and enterprise gear [3]. A MAC in these blocks is therefore most likely a Sercomm-built router, gateway or streamer sold under an operator's or another brand's name, though no source in hand names a product carrying a DWnet OUI [2][3].

The researcher who published the TCP 32764 backdoor in Linksys, Netgear, Cisco and other routers names Sercomm as its probable source, citing a header in Cisco GPL sources [4]; no source ties it to devices in DWnet's blocks. No CVE naming DWnet was found in NVD [5]. The FCC ID databases refused automated access, so founding year, radios, silicon and FCC grantee codes are not listed and randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Contact - Sercomm Corporation - https://www.sercomm.com/en/contact (accessed 2026-10-27)
3. Sercomm Corporation home page served at dwnet.com.cn - https://www.dwnet.com.cn/en (accessed 2026-10-27)
4. TCP-32764 backdoor - GitHub (elvanderb) - https://github.com/elvanderb/TCP-32764 (accessed 2026-10-27)
5. NVD CVE API keyword search DWnet - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=DWnet (accessed 2026-10-27)
