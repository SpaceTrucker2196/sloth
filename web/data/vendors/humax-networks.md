---
name: HUMAX NETWORKS
aliases: []
affiliates: []
country: KR [2]
parent: unknown
founded: unknown
kind: network-equipment
device_classes: [ap/router]
found_in: ["HNR2306P tri-band Wi-Fi 7 router, and the HNRM30 and HNR2306 Wi-Fi 7 routers for which the vendor announced FCC conditional approval [1]", "Operator CPE: DOCSIS 3.0/3.1 cable gateways, GPON/XGS-PON/10G-EPON ONTs, VDSL2/G.fast gateways, 5G FWA units, femtocells, EasyMesh routers and extenders, LoRa gateways [3][4][5]", "Moni Pod Wi-Fi-sensing home monitor [1][4]", "Vodafone network-automation field trial of the OCRA antenna alignment robot (Tirana, Albania) [1]"]
radios: ["Wi-Fi 6/6E [3][4]", "Wi-Fi 7 [1][3][4]", "5G (fixed wireless access) [5]", "LoRa [5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
HUMAX Networks is a South Korean broadband-CPE vendor at 7F HUMAX Village, 216 Hwangsaeul-ro, Bundang-gu, Seongnam-si, selling to service providers: DOCSIS 3.0/3.1 cable gateways, GPON/XGS-PON/10G-EPON fibre ONTs, VDSL2/G.fast gateways, 5G fixed-wireless units and femtocells, Wi-Fi 6/6E/7 EasyMesh routers and extenders, LoRa gateways, the Moni Pod Wi-Fi-sensing home monitor and the OCRA antenna-alignment robot trialled with Vodafone in Tirana, Albania [1][2][3][4][5]. Its own news names the HNR2306P tri-band Wi-Fi 7 router (prplWare 4.0 certified) and FCC conditional approval for the HNRM30 and HNR2306 Wi-Fi 7 routers [1]. It is a different IEEE registrant from HUMAX Co., Ltd., the set-top-box maker founded in 1989 and also headquartered in Seongnam, whose operator customers include BT, Freesat, Google Fiber, Spectrum, DirecTV and AT&T Fiber (the BGW320-500 gateway) [6]: the Wireshark OUI database lists five blocks for Humax Networks (28:25:5F, 3C:71:4B, 48:E2:AD, A8:40:F8, BC:9A:8E) against 31 for HUMAX Co., Ltd. [9]. The corporate relationship between the two companies and HUMAX Networks' founding date are not stated in any source reached, and the humaxnetworks.com domain (no hyphen) serves unrelated Korean gambling content, so humax-networks.com is the vendor's site [10]. A MAC in a HUMAX Networks block is therefore most likely an ISP-issued gateway, router or mesh extender, and on the air a dual- or tri-band AP of the Wi-Fi 6/6E/7 generation [3][4]; band plans, channel widths, the FCC grantee code and the chipsets of the current line are not documented in the sources reached (the FCC ID mirrors were not reachable from the session that verified this entry), so they are left unknown rather than inferred. HUMAX Co.'s Quantum routers used MediaTek MT7628/MT7621A and Realtek RTL8197FS [7]. The security history is on the HUMAX Co. side: NVD lists nine CVEs from 2017-2020 for HG100R, HGB10R and HGA12R gateways (credentials in backup files, cleartext credentials, auth bypass, session hijacking, XSS), none naming a HUMAX Networks model [8].
## Sources
1. HUMAX Networks home page (news: HNR2306P prplWare 4.0 certification, Wi-Fi 7 FCC conditional approval for HNRM30/HNR2306, Vodafone OCRA trial) - https://www.humax-networks.com/ (accessed 2026-10-27)
2. HUMAX Networks - CEO message page (company address) - https://www.humax-networks.com/ceo_message_ (accessed 2026-10-27)
3. HUMAX Networks - Broadband Solutions (DOCSIS, xPON, xDSL, Wi-Fi 6/6E/7, EasyMesh) - https://www.humax-networks.com/broadband/view (accessed 2026-10-27)
4. HUMAX Networks - Home Network Solutions (router/extender, wireless sensing) - https://www.humax-networks.com/homenetwork/view (accessed 2026-10-27)
5. HUMAX Networks - Wireless Access Solutions (5G FWA, femtocell, LoRa) - https://www.humax-networks.com/wireless/view (accessed 2026-10-27)
6. Wikipedia - Humax (HUMAX Co., Ltd.: founded 1989, Seongnam; operators incl. BT, Freesat, Google Fiber, Spectrum, DirecTV, AT&T Fiber) - https://en.wikipedia.org/wiki/Humax (accessed 2026-10-27)
7. DeviWiki - Humax (Quantum E2/E3/E10 CPUs) - https://deviwiki.com/wiki/Humax (accessed 2026-10-27)
8. NVD CVE API keyword search "Humax" (9 results, 2017-2020) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Humax (accessed 2026-10-27)
9. Wireshark manuf OUI database ("Humax Networks" blocks 28:25:5F, 3C:71:4B, 48:E2:AD, A8:40:F8, BC:9A:8E; HUMAX Co., Ltd. has 31 further blocks) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
10. humaxnetworks.com (domain observed serving unrelated Korean gambling content on 2026-10-27; not the vendor) - https://www.humaxnetworks.com (accessed 2026-10-27)
