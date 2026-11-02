---
name: Vantiva USA LLC
aliases: ["Vantiva Connected Home - Technologies Telco"]
country: US [13]
parent: Vantiva SA (Paris, France; formerly Technicolor SA, formerly Thomson) [1][2]
founded: 2022 [1]
kind: network-equipment
device_classes: [ap/router, tv]
found_in: ["Operator broadband gateways and set-top boxes for Comcast, Orange, Bouygues Telecom, Proximus, Telstra, Jio, Airtel, Altibox, Armstrong, Breezeline, Claro, Etisalat, Fastweb, LGU, Mega, Millicom/Tigo, Shaw, Sky Brasil, Tata Play, Telecom Argentina, TIM, WowWay [4][5][6]", "Technicolor TC8717C DOCSIS gateway (Comcast XB3) [9]", "Technicolor CGM4331COM DOCSIS 3.1 Wi-Fi 6 gateway [10]", "Technicolor TC8706C, CGA series, DWA1230, TG589vac v2 and the CM-7600 set-top box (Comcast, Mediacom) [8]", "Ex-Cisco/Scientific Atlanta customer-premises line acquired 2015 (DPC39xx cable gateways) [2][3][12]"]
radios: ["Wi-Fi 5 [9]", "Wi-Fi 6 [10]", "2.4 GHz [9]", "5 GHz [9]", "Bluetooth (version not stated) [10]", "Thread/Zigbee (802.15.4) (Zigbee flag on the CGM4331COM) [10]", "DECT/CAT-iq [9]"]
silicon: ["Broadcom BCM33843 + 2x BCM4360 (3x3 ac) in TC8717C, with BCM53124S switch, BCM6803 MoCA and Dialog SC14441 DECT [9]", "Broadcom BCM3390, BCM63138 and Quantenna/Marvell radios across documented Technicolor gateways [8]"]
fcc_grantee: ["G95 [9][10]"]
randomization: unknown
security_notes: ["CVE-2024-36397 XSS in Vantiva MediaAccess DGA2232 firmware 19.4 (CVSS 6.1) [11]", "40 NVD entries under the Technicolor name, incl. CVE-2014-0620/0621 (TC7200 XSS/CSRF), CVE-2014-9144 (TD5130 remote command execution), CVE-2016-7454 (DPC3941T CSRF), CVE-2017-5135 (DPC3928SL SNMP access bypass), CVE-2017-11502 (DPC3928AD path traversal) [12]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Vantiva USA LLC is the US registrant for the Connected Home business of Vantiva SA, the Paris-based company that was Thomson, then Technicolor SA, and took the Vantiva name on 27 September 2022 when it spun off its studios [1][2]. The IEEE registry copy shipped with sloth lists 98 MA-L blocks under this name, nearly all at two Georgia addresses - 5030 Sugarloaf Parkway, Lawrenceville, and 4855 Peachtree Industrial Blvd, Norcross - with three at San Diego, plus related blocks under "Vantiva Connected Home - Technologies Telco" (D8:D8:E5) and "Vantiva Technologies Belgium" (9C:97:26, Edegem) [13]. Lawrenceville was Scientific Atlanta's home; Cisco completed its purchase in February 2006 and sold the resulting Connected Devices unit to Technicolor in November 2015, so these blocks carry that cable-CPE lineage [2][3]. A MAC here is most likely an ISP-issued device: a DOCSIS, fiber (50G PON is the newest) or 5G-FWA gateway, a Wi-Fi extender, or an Android TV / RDK set-top box or dongle ("tv" above means operator STB or dongle), with Comcast, Orange, Telstra, Jio and some 350 operators in all as customers [4][5][6][7]. Documented silicon is Broadcom: BCM33843 with twin BCM4360 radios in the Comcast TC8717C, and BCM3390/BCM63138 in later gateways, with Quantenna/Marvell radios in some [8][9]; the CGM4331COM is a 4x4 Wi-Fi 6 DOCSIS 3.1 gateway whose DeviWiki record also flags Bluetooth and Zigbee [10]. FCC grants use grantee code G95 [9][10]. No source states anything about MAC randomization on these gateways, so it is left unknown. The CVE record is long on the Technicolor and ex-Cisco DPC lines (XSS, CSRF, RCE, SNMP bypass) and one recent Vantiva-branded gateway XSS [11][12]; an exposed Vantiva/Technicolor management interface deserves a look.
## Sources
1. Wikipedia: Vantiva - https://en.wikipedia.org/wiki/Vantiva (accessed 2026-10-27)
2. Wikipedia: Technicolor SA - https://en.wikipedia.org/wiki/Technicolor_SA (accessed 2026-10-27)
3. Wikipedia: Scientific Atlanta - https://en.wikipedia.org/wiki/Scientific_Atlanta (accessed 2026-10-27)
4. Vantiva: home page (customer logos) - https://www.vantiva.com/ (accessed 2026-10-27)
5. Vantiva: Broadband - https://www.vantiva.com/connected-home/broadband/ (accessed 2026-10-27)
6. Vantiva: Video Solutions - https://www.vantiva.com/connected-home/video-solutions/ (accessed 2026-10-27)
7. Vantiva: Connected Home - https://www.vantiva.com/connected-home/ (accessed 2026-10-27)
8. DeviWiki: Technicolor - https://deviwiki.com/wiki/Technicolor (accessed 2026-10-27)
9. DeviWiki: Technicolor TC8717C - https://deviwiki.com/wiki/Technicolor_TC8717C (accessed 2026-10-27)
10. DeviWiki: Technicolor CGM4331COM - https://deviwiki.com/wiki/Technicolor_CGM4331COM (accessed 2026-10-27)
11. NVD CVE API, keyword "Vantiva" (CVE-2024-36397) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Vantiva&resultsPerPage=8 (accessed 2026-10-27)
12. NVD CVE API, keyword "Technicolor" (40 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Technicolor&resultsPerPage=10 (accessed 2026-10-27)
13. IEEE Registration Authority MA-L registry (local export web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
