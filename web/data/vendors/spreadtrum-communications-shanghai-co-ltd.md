---
name: "Spreadtrum Communications (Shanghai) Co., Ltd."
aliases: []
country: CN [3]
parent: "Tsinghua Unigroup (acquired Spreadtrum in 2013; brand consolidated as UNISOC in 2018) [1]"
founded: 2001 [1]
kind: chip-vendor
device_classes: [phone, tablet, wearable]
found_in: ["Samsung Galaxy A03 (Unisoc T606) and Galaxy A03 Core (SC9863A) [5]", "Motorola Moto G20 XT2128-2 (Unisoc T700) [8]", "Xiaomi Watch S4 Sport and nubia Neo 3 series [4]"]
radios: ["Wi-Fi 5 (802.11a/b/g/n/ac) 2.4 GHz + 5 GHz (Galaxy A03) [5]", "BLE 5.1 (Galaxy A03) [5]", "Wi-Fi 6 (self-developed IP, per Unisoc) [4]", "LTE/5G (T8300 5G SoC) [9]"]
silicon: ["SC9863A in Galaxy A03 Core [1][5]", "T606 in Galaxy A03 [1][5]", "T610, T618 (T-series) [1]", "T700 in Moto G20 [8]", "T8300 5G SoC, T9100 [9]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2022-20210: NAS message-parsing bug in the Unisoc modem allowing remote modem crash (DoS, potential RCE), Critical in the June 2022 Android Security Bulletin under 'Unisoc components', CVSS 9.4 per Check Point, found on a Moto G20 with T700 [6][7][8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Spreadtrum Communications started in 2001, was bought by Tsinghua Unigroup in 2013 and merged into the UNISOC brand in 2018; in Q1 2026 UNISOC held 14% of global smartphone SoC shipments, fourth behind MediaTek, Qualcomm and Apple [1]. The IEEE registry holds a single MA-L block under the Spreadtrum name, 40:45:DA, registered February 2014 at Building 1, Spreadtrum Center, 2288 Zuchongzhi Rd, Shanghai [2][3]. Because this is a chip vendor's block, a MAC here is a budget phone, tablet or wearable built on a Spreadtrum/Unisoc SoC whose maker left the reference Wi-Fi MAC range in place rather than using its own OUI; which brands do that is not documented, so treat the device class as inferred. Documented hosts of the silicon are the Samsung Galaxy A03 (T606, Wi-Fi a/b/g/n/ac, Bluetooth 5.1) and A03 Core (SC9863A) [5], the Moto G20 (T700) [8], and the Xiaomi Watch S4 Sport and nubia Neo 3 [4]; current flagships are the T8300 5G SoC and T9100 [9], and Unisoc says its own Wi-Fi 6 IP has matured [4]. The security note that matters is CVE-2022-20210, a modem NAS-parsing flaw rated Critical under "Unisoc components" in the June 2022 Android bulletin (CVSS 9.4 per Check Point), remotely crashing the baseband [6][7][8]. No FCC grantee code is recorded for the vendor in the sources, and no MAC-randomization behaviour is attributable to the vendor rather than to the Android build on the device.
## Sources
1. UNISOC - Wikipedia - https://en.wikipedia.org/wiki/Unisoc (accessed 2026-10-27)
2. Spreadtrum Communications (Shanghai) Co., Ltd. MAC address blocks - maclookup.app - https://maclookup.app/vendors/spreadtrum-communications-shanghai-co-ltd (accessed 2026-10-27)
3. OUI 40:45:DA registrant record - maclookup.app - https://maclookup.app/macaddress/4045DA (accessed 2026-10-27)
4. About UNISOC - unisoc.com - https://www.unisoc.com/en_us/home/about-us (accessed 2026-10-27)
5. Samsung Galaxy A03 - Wikipedia - https://en.wikipedia.org/wiki/Samsung_Galaxy_A03 (accessed 2026-10-27)
6. CVE-2022-20210 record - CVE.org (MITRE CVE Services API) - https://cveawg.mitre.org/api/cve/CVE-2022-20210 (accessed 2026-10-27)
7. Android Security Bulletin, June 2022 - source.android.com - https://source.android.com/security/bulletin/2022-06-01 (accessed 2026-10-27)
8. Vulnerability within the UNISOC baseband - Check Point Research - https://research.checkpoint.com/2022/vulnerability-within-the-unisoc-baseband/ (accessed 2026-10-27)
9. UNISOC products - unisoc.com - https://www.unisoc.com/en_us/home/products (accessed 2026-10-27)
