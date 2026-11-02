---
name: HUMAX NETWORKS
aliases: []
country: KR [2]
parent: unknown
founded: unknown
kind: network-equipment
device_classes: [ap/router]
found_in: ["HNR2306P tri-band Wi-Fi 7 router, and the HNRM30 and HNR2306 Wi-Fi 7 routers for which the vendor announced FCC conditional approval [1]", "Operator CPE: DOCSIS 3.0/3.1 cable gateways, GPON/XGS-PON/10G-EPON ONTs, VDSL2/G.fast gateways, 5G FWA units, femtocells, EasyMesh routers and extenders, LoRa gateways [3][4][5]", "Moni Pod Wi-Fi-sensing home monitor [1][4]", "Vodafone network-automation field trial of the OCRA antenna alignment robot (Tirana, Albania) [1]"]
radios: ["Wi-Fi 6/6E [3][4]", "Wi-Fi 7 [1][3][4]", "5G (fixed wireless access) [5]", "LoRa [5]"]
silicon: ["Not documented for HUMAX Networks' own products in the sources reached; the HUMAX Co., Ltd. Quantum router line used MediaTek MT7628 (E2), MT7621A (E10) and Realtek RTL8197FS (E3) [14]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Humax-branded gateways from HUMAX Co., Ltd. carry CVE-2017-7315/7316/7317 and CVE-2017-11435 (HG100R: credentials in unauthenticated backup, XSS, auth bypass), CVE-2019-19889/19890 (HGB10R-2: admin credentials in backup and over cleartext HTTP), CVE-2020-9477/9370 (HGA12R-02 cleartext password capture, session hijacking) and CVE-2020-27366 (HGB10R-02 XSS); none names a HUMAX Networks model [15]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
HUMAX Networks is a South Korean broadband-CPE vendor at 7F HUMAX Village, 216 Hwangsaeul-ro, Bundang-gu, Seongnam-si, selling to service providers: DOCSIS 3.0/3.1 cable gateways, GPON/XGS-PON/10G-EPON fibre ONTs, VDSL2/G.fast gateways, 5G fixed-wireless units and femtocells, Wi-Fi 6/6E/7 EasyMesh routers and extenders, LoRa gateways, the Moni Pod Wi-Fi-sensing home monitor and the OCRA antenna-alignment robot trialled with Vodafone in Tirana, Albania [1][2][3][4][5]. Its own news names the HNR2306P tri-band Wi-Fi 7 router (prplWare 4.0 certified) and FCC conditional approval for the HNRM30 and HNR2306 Wi-Fi 7 routers [1]. It is a different IEEE registrant from HUMAX Co., Ltd., the set-top-box maker founded in 1989 and also headquartered in Seongnam, whose operator customers include BT, Freesat, Google Fiber, Spectrum, DirecTV and AT&T Fiber (the BGW320-500 gateway) [13]: the Wireshark OUI database lists five blocks for Humax Networks (28:25:5F, 3C:71:4B, 48:E2:AD, A8:40:F8, BC:9A:8E) against 31 for HUMAX Co., Ltd. [16]. The corporate relationship between the two companies and HUMAX Networks' founding date are not stated in any source reached, and the humaxnetworks.com domain (no hyphen) serves unrelated Korean gambling content, so humax-networks.com is the vendor's site [18]. A MAC in a HUMAX Networks block is therefore most likely an ISP-issued gateway, router or mesh extender, and on the air a dual- or tri-band AP of the Wi-Fi 6/6E/7 generation [3][4]; band plans, channel widths, the FCC grantee code and the chipsets of the current line are not documented in the sources reached (the FCC ID mirrors were not reachable from the session that verified this entry), so they are left unknown rather than inferred. HUMAX Co.'s Quantum routers used MediaTek MT7628/MT7621A and Realtek RTL8197FS [14]. The security history is on the HUMAX Co. side: NVD lists nine CVEs from 2017-2020 for HG100R, HGB10R and HGA12R gateways (credentials in backup files, cleartext credentials, auth bypass, session hijacking, XSS), none naming a HUMAX Networks model [15].
## Sources
1. HUMAX Networks home page (news: HNR2306P prplWare 4.0 certification, Wi-Fi 7 FCC conditional approval for HNRM30/HNR2306, Vodafone OCRA trial) - https://www.humax-networks.com/ (accessed 2026-10-27)
2. HUMAX Networks - CEO message page (company address) - https://www.humax-networks.com/ceo_message_ (accessed 2026-10-27)
3. HUMAX Networks - Broadband Solutions (DOCSIS, xPON, xDSL, Wi-Fi 6/6E/7, EasyMesh) - https://www.humax-networks.com/broadband/view (accessed 2026-10-27)
4. HUMAX Networks - Home Network Solutions (router/extender, wireless sensing) - https://www.humax-networks.com/homenetwork/view (accessed 2026-10-27)
5. HUMAX Networks - Wireless Access Solutions (5G FWA, femtocell, LoRa) - https://www.humax-networks.com/wireless/view (accessed 2026-10-27)
6. FCC grantee 2AXXQ - Humax Networks, INC - https://fccid.io/2AXXQ (accessed 2026-10-27) (not reachable 2026-10-27)
7. FCC ID 2AXXQBGW320 - BGW320-500 Wireless Integrated ONT Residential Gateway - https://fccid.io/2AXXQBGW320 (accessed 2026-10-27) (not reachable 2026-10-27)
8. FCC ID 2AXXQBGW321 external photos exhibit - https://fccid.io/2AXXQBGW321/External-Photos/External-Photos-7828089 (accessed 2026-10-27) (not reachable 2026-10-27)
9. FCC ID 2AXXQHNR2306 - Tri-Band AP Router - https://fccid.io/2AXXQHNR2306 (accessed 2026-10-27) (not reachable 2026-10-27)
10. FCC ID 2AXXQMLBADA - Location Bridge - https://fccid.io/2AXXQMLBADA (accessed 2026-10-27) (not reachable 2026-10-27)
11. fccid.io search "Humax" - https://fccid.io/search/?q=Humax (accessed 2026-10-27) (not reachable 2026-10-27)
12. FCC grantee O6Z - Humax Co., Ltd. - https://fccid.io/O6Z (accessed 2026-10-27) (not reachable 2026-10-27)
13. Wikipedia - Humax (HUMAX Co., Ltd.: founded 1989, Seongnam; operators incl. BT, Freesat, Google Fiber, Spectrum, DirecTV, AT&T Fiber) - https://en.wikipedia.org/wiki/Humax (accessed 2026-10-27)
14. DeviWiki - Humax (Quantum E2/E3/E10 CPUs) - https://deviwiki.com/wiki/Humax (accessed 2026-10-27)
15. NVD CVE API keyword search "Humax" (9 results, 2017-2020) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Humax (accessed 2026-10-27)
16. Wireshark manuf OUI database ("Humax Networks" blocks 28:25:5F, 3C:71:4B, 48:E2:AD, A8:40:F8, BC:9A:8E; HUMAX Co., Ltd. has 31 further blocks) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
17. fccid.io company profile - Humax Networks, Inc - https://fccid.io/company/Humax-Networks-Inc (accessed 2026-10-27) (not reachable 2026-10-27)
18. humaxnetworks.com (domain observed serving unrelated Korean gambling content on 2026-10-27; not the vendor) - https://www.humaxnetworks.com (accessed 2026-10-27)
