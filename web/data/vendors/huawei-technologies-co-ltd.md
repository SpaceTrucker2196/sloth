---
name: "HUAWEI TECHNOLOGIES CO.,LTD"
aliases: ["Huawei Technologies Co., Ltd."]
affiliates: []
country: CN [1][2]
parent: independent; Huawei states it is employee-owned, with a trade union committee holding most shares, a point in dispute [1]
founded: 1987 [1]
kind: network-equipment [1]
device_classes: [phone [1], laptop [1], tablet [1], wearable [1], tv [1], ap/router [1][3]]
found_in: ["Huawei HG8245 fiber gateway (ONT) [3]", "Huawei B593u-12 LTE CPE router [3]", "Huawei HG532 ADSL wireless router [3][4]", "Huawei smartphones, laptops, tablets and smartwatches [1]"]
radios: ["802.11b/g/n 2x2 (HG532) [4]", "LTE/5G (4G LTE routers and CPE such as the B593u-12) [3]"]
silicon: ["HiSilicon SD5113 in the HG8245 [3]", "Broadcom BCM5358U with a Qualcomm MDM9200 LTE module in the B593u-12 [3]", "Ralink RT3052 in the HG532 [3][4]"]
fcc_grantee: ["QIS [3]"]
randomization: unknown
security_notes: ["CVE-2017-17215: remote code execution in customized versions of the HG532 via packets to port 37215 [5]", "2012: Australian and US intelligence concluded a hack on Australia's telecom networks was conducted by or through Huawei, which the operators disputed [1]", "November 2022: the US FCC banned sales or import of Huawei equipment on national security grounds; several other countries ban or restrict its products [1]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Huawei is a Chinese technology conglomerate founded in 1987 in Shenzhen by Ren Zhengfei and headquartered in Longgang, Shenzhen; it makes telecom equipment such as base stations, routers and switches as well as smartphones, laptops, tablets, smartwatches and smart TVs [1]. It describes itself as employee-owned, with a trade union committee holding most shares, though that is disputed [1]. The IEEE registry lists about 1,386 MA-L blocks to "HUAWEI TECHNOLOGIES CO.,LTD", most at a Songshan Lake, Dongguan address, and one to "Huawei Technologies Co., Ltd." in Shenzhen; a separate registrant, "Huawei Device Co., Ltd.", holds another 640 blocks and is not covered by this entry [2].

A MAC in these blocks may be a Huawei phone or consumer device or a piece of operator equipment, since WikiDevi lists Huawei access points, wireless routers, LTE CPE, fiber ONTs, DSL modems, cable modems and range extenders [1][3]. Documented silicon includes a HiSilicon SD5113 in the HG8245 ONT, a Broadcom BCM5358U with a Qualcomm MDM9200 LTE module in the B593u-12, and a Ralink RT3052 in the HG532 ADSL router, which runs 802.11b/g/n 2x2 [3][4]. Huawei's FCC grantee code is QIS, as in QISHG532S (HG532s) and QISEG8245H [3].

CVE-2017-17215 is a remote code execution flaw in customized HG532 firmware reached through port 37215 [5]. Australian and US intelligence concluded in 2012 that a hack on Australia's telecom networks ran through Huawei, and in November 2022 the US FCC banned sales or import of Huawei equipment on national security grounds [1]. Randomization behaviour is not documented by the sources consulted; the FCC ID databases (fccid.io, fcc.report, apps.fcc.gov) refused automated access from this session.

## Sources
1. Huawei - Wikipedia - https://en.wikipedia.org/wiki/Huawei (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Huawei - WikiDevi - https://wikidevi.wi-cat.ru/Huawei (accessed 2026-10-27)
4. Huawei HG532 - WikiDevi - https://wikidevi.wi-cat.ru/Huawei_HG532 (accessed 2026-10-27)
5. CVE-2017-17215 - CIRCL Vulnerability-Lookup - https://cve.circl.lu/vuln/cve-2017-17215 (accessed 2026-10-27)
