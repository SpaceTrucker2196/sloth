---
name: ASKEY COMPUTER CORP
aliases: []
affiliates: []
country: TW [1][2]
parent: ASUSTeK Computer Inc. [2][3]
founded: 1989 [2]
kind: odm/ems [2]
device_classes: [ap/router [4][5], tv [4]]
found_in: ["Askey RAC2V1K / RT4230W REV6 router installed by Spectrum [5]", "Fastweb Askey RTV1907VW [6]", "Askey RTF8115VW [7]"]
radios: ["Wi-Fi [4]", "LTE/5G [2][4]"]
silicon: ["Qualcomm IPQ8065 in the Askey RAC2V1K / RT4230W REV6 [5]"]
fcc_grantee: ["H8N (FCC ID H8NRAC2V1K, Askey RAC2V1K) [5]"]
randomization: unknown
security_notes: ["CVE-2019-12489: command injection through the usb_remove service in Fastweb Askey RTV1907VW firmware 0.00.81 [6]", "CVE-2021-27403: XSS in cgi-bin/te_acceso_router.cgi on Askey RTF8115VW [7]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Askey Computer Corp. was established in 1989, is a member of ASUSTeK Computer Inc., is headquartered in New Taipei City with about 6,000 staff, and runs plants in Vietnam, Taiwan and Suzhou, China [2]; the Asus Wikipedia article lists ASKEY among Asus's subsidiaries [3]. The IEEE registry lists many MA-L blocks to ASKEY COMPUTER CORP at its Chung-Ho / Zhonghe, Taipei address [1].

Askey's product lines include 5G fixed-wireless outdoor units, routers and dongles, Wi-Fi routers and mesh systems, FTTx and cable products, 5G and LTE small cells, Android TV set-top boxes, home IoT and surveillance products and V2X, and its news names operators such as Chunghwa Telecom, Far EasTone, Charter and NTT EAST [4]. A MAC in an Askey block is therefore likely a router, gateway or set-top box, possibly one an ISP installed: a Spectrum customer reported an Askey RAC2V1K installed by Spectrum, identified as the RT4230W REV6, built on a Qualcomm IPQ8065 and filed under FCC ID H8NRAC2V1K by Askey Computer Corp. [5].

Askey devices have public flaws: CVE-2019-12489 allows command injection through the mount parameter of the usb_remove service on the Fastweb Askey RTV1907VW, and CVE-2021-27403 is an XSS in cgi-bin/te_acceso_router.cgi on the Askey RTF8115VW [6][7]. The FCC ID databases refused this session's direct requests, so only the grantee code visible in a fetched source is listed, and no source documents MAC randomization.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About Askey - Askey Computer Corp. - https://www.askey.com/about/ (accessed 2026-10-27)
3. Asus - Wikipedia - https://en.wikipedia.org/wiki/Askey_Computer_Corporation (accessed 2026-10-27)
4. Askey Computer Corp. home page - https://www.askey.com.tw/ (accessed 2026-10-27)
5. Askey RAC2V1K / RT4230W REV6 Support - OpenWrt Forum - https://forum.openwrt.org/t/askey-rac2v1k-rt4230w-rev6-support/15830 (accessed 2026-10-27)
6. CVE-2019-12489 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-12489 (accessed 2026-10-27)
7. CVE-2021-27403 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2021-27403 (accessed 2026-10-27)
