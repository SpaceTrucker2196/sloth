---
name: Commscope
aliases: ["CommScope Inc", "Commscope, Inc"]
country: US [1]
parent: independent [1]
founded: 1976 [1]
kind: network-equipment
device_classes: [ap/router, tv]
found_in: ["Comcast Xfinity XB3 gateway = ARRIS TG1682G (OUI 14:CF:E2 on the sampled unit) [10]", "Comcast Xfinity XB6 gateway = ARRIS TG3482ER (OUI F8:A0:97 on the sampled unit) [11]", "Cable modems and gateways deployed by Comcast, Charter, Cox and others (CM/SB/SBG/TG series), set-top boxes (Xi6-A, C61W-700, VIP6102W), NVG DSL/fibre CPE, VAP extenders [9]", "Retail ARRIS SURFboard modems and routers (SBG10, SBG6950, SBR-AC series, W-series mesh) [5][9]", "Ruckus R/T/H-series Wi-Fi access points and Q410/Q710/Q910/Q950 LTE access points [7][13]", "Australia's National Broadband Network CPE [2]", "AT&T NVG589 / NVG599 gateways (CVE listings) [13][21]"]
radios: ["Wi-Fi 4 through Wi-Fi 6 (802.11bgn to ax) across the ARRIS CPE portfolio [9]", "Wi-Fi 6E / 7 6 GHz: Ruckus H670 granted at 5955-7095 MHz (2025-12-02) [8]", "2.4 GHz (2412-2462 MHz) [6]", "5 GHz (5180-5240, 5260-5320, 5500-5700, 5745-5825 MHz) [6]", "6 GHz [8]", "Thread/Zigbee (802.15.4) and BLE radios in the Comcast XB6 (TG3482ER) [11]", "MoCA 2.0 in TG3482ER [11]", "LTE/5G: Ruckus Q410/Q710/Q910/Q950 LTE access points [7]; ARRIS NVG653 5G NR fixed-wireless router [5]", "DOCSIS 3.0 (TG1682G) and DOCSIS 3.1 (TG3482ER) cable [10][11]"]
silicon: ["Intel Puma DHCE2652 SoC with Qualcomm Atheros QCA9880 (5 GHz 3x3) and Atheros AR9381 (2.4 GHz 3x3) in ARRIS TG1682G / Comcast XB3 [10]", "Intel Puma FHCE2712 SoC with Quantenna QT10GU + QT7810C (5 GHz 8x8) and QT6210B (2.4 GHz 2x2) in ARRIS TG3482ER / Comcast XB6 [11]", "Broadcom, Intel Puma, Qualcomm Atheros and Quantenna across the 55 ARRIS devices catalogued [9]"]
fcc_grantee: ["UID (ARRIS home-networks grantee; applicant shown as ARRIS on UIDG20 in 2023, grantee record now held by Vantiva USA LLC) [5][6]", "S9G (Ruckus Wireless LLC) [7]"]
randomization: unknown
security_notes: ["Ruckus security bulletins recur with unauthenticated remote code execution and auth bypass in SmartZone, Unleashed, ZoneDirector, Network Director and IoT Controller (e.g. 2025-10-31 critical RCE in Network Director; 2026-03-13 'AirSnitch' AP vulnerabilities) [12]", "CVE-2021-33218 and CVE-2021-33221: hard-coded system passwords giving shell access and unauthenticated API endpoints in Ruckus IoT Controller 1.7.1.0 and earlier [13][15][16]", "CVE-2022-45701: ARRIS TG2482A firmware through 9.1.103GEM9 allows remote code execution via the ping utility [13][17]", "CVE-2021-41552: command injection in SURFboard SBG6950AC2 9.1.103AA23 [13][18]", "CVE-2022-26991 and CVE-2022-26994: command injection in SBR-AC1200P / AC1900P / AC3200P routers (ntp TimeZone and pptp parameters) [13][19][20]", "CVE-2017-9490: CSRF configuration changes on Comcast-firmware TG1682G [13][21]", "CVE-2022-31793: arbitrary file read in muhttpd before 1.1.7 on Arris NVG443/NVG589/NVG599 gateways [22]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
CommScope, founded in 1976 in Hickory, North Carolina and headquartered in Richardson, Texas since November 2025, is a network-infrastructure company that absorbed Andrew Corporation (2007), TE Connectivity's broadband unit (2015) and, on 4 April 2019 for USD 7.4 billion, ARRIS International - which had itself bought Motorola's home division (2013), Pace (2016) and Ruckus Wireless (2017) [1][2]. The "Commscope" IEEE registrant is the largest in this batch at 345 MA-L blocks, including legacy prefixes such as 00:00:CA [14], and in practice those blocks sit on ARRIS cable modems, telephony gateways and set-top boxes supplied by Comcast, Charter, Cox and others, on retail SURFboard gear, and on Ruckus enterprise access points [5][7][9]. The ownership has since moved on: CommScope agreed in October 2023 to sell the Home Networks business (ARRIS/SURFboard CPE) to Vantiva for a 25% stake, closing on 2 January 2024 [1][4], the UID grantee record now reads Vantiva USA LLC [5], and Ruckus passed to Belden on 1 July 2026 [3], so a Commscope OUI identifies the hardware lineage, not the company that supports the device today. Documented hardware is Intel Puma 6 with Qualcomm Atheros QCA9880/AR9381 radios in the Comcast XB3 (TG1682G) and Intel Puma 7 with Quantenna 8x8 5 GHz radios plus Zigbee, BLE and MoCA in the XB6 (TG3482ER) [10][11]; the installed base runs 802.11bgn through Wi-Fi 6 [9], while the Ruckus H670 is granted through 5955-7095 MHz [8]. As infrastructure these devices present fixed MACs on their LAN/WLAN interfaces, but no vendor statement was found, so randomization is recorded unknown. Security history is substantial on both halves: Ruckus controllers and managers carry a long run of unauthenticated RCE and auth-bypass bulletins [12], and ARRIS CPE has published command-injection and RCE CVEs on TG2482A, SBG6950AC2 and the SBR-AC series, and CSRF on the Comcast TG1682G firmware [13][17][18][19][20][21].
## Sources
1. CommScope - Wikipedia - https://en.wikipedia.org/wiki/CommScope (accessed 2026-10-27)
2. Arris International - Wikipedia - https://en.wikipedia.org/wiki/Arris_International (accessed 2026-10-27)
3. Ruckus Networks - Wikipedia - https://en.wikipedia.org/wiki/Ruckus_Networks (accessed 2026-10-27)
4. Vantiva - Wikipedia - https://en.wikipedia.org/wiki/Vantiva (accessed 2026-10-27)
5. Vantiva USA LLC (formerly ARRIS) FCC ID Applications (UID) - fccid.io - https://fccid.io/UID (accessed 2026-10-27)
6. FCC ID UIDG20 - DOCSIS Gateway (applicant ARRIS) - fccid.io - https://fccid.io/UIDG20 (accessed 2026-10-27)
7. Ruckus Wireless LLC FCC ID Applications (S9G) - fccid.io - https://fccid.io/S9G (accessed 2026-10-27)
8. FCC ID S9GH670 - H670 Access Point - fccid.io - https://fccid.io/S9GH670 (accessed 2026-10-27)
9. Arris - DeviWiki (ex WikiDevi) - https://deviwiki.com/wiki/Arris (accessed 2026-10-27)
10. Arris TG1682G - DeviWiki (ex WikiDevi) - https://deviwiki.com/wiki/Arris_TG1682G (accessed 2026-10-27)
11. Arris TG3482G - DeviWiki (ex WikiDevi) - https://deviwiki.com/wiki/Arris_TG3482G (accessed 2026-10-27)
12. RUCKUS Security Bulletins - https://support.ruckuswireless.com/security (accessed 2026-10-27)
13. CVE search commscope / arris (ruckus_iot_controller, arris_tg2482a_firmware, arris_surfboard_sbg7600ac2_firmware, sbr-ac1900p_firmware, tg1682g_firmware, nvg589, nvg599) - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/browse/commscope (accessed 2026-10-27)
14. Commscope MAC address blocks - maclookup.app - https://maclookup.app/vendors/commscope (accessed 2026-10-27)
15. CVE-2021-33218 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2021-33218 (accessed 2026-10-27)
16. CVE-2021-33221 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2021-33221 (accessed 2026-10-27)
17. CVE-2022-45701 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2022-45701 (accessed 2026-10-27)
18. CVE-2021-41552 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2021-41552 (accessed 2026-10-27)
19. CVE-2022-26991 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2022-26991 (accessed 2026-10-27)
20. CVE-2022-26994 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2022-26994 (accessed 2026-10-27)
21. CVE-2017-9490 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2017-9490 (accessed 2026-10-27)
22. CVE-2022-31793 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2022-31793 (accessed 2026-10-27)
