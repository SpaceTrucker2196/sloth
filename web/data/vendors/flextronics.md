---
name: FLEXTRONICS
aliases: ["Flextronics", "Flextronics International", "Flextronics International GmbH & Co. Nfg. KG", "Flextronics International Kft", "FLEXTRONICS MANUFACTURING(ZHUHAI)CO.,LTD.", "Flextronics Tech.(Ind) Pvt Ltd", "FLEXTRONICS TECHNOLOGIES (INDIA) PVT LTD", "Flextronics Technologies India Private Limited", "Flextronics Automotive USA, Inc", "Flextronics Canafa Design Services"]
country: SG [1]
parent: independent [1]
founded: 1969 [1]
kind: odm/ems
device_classes: [module-in-other-brands, ap/router, tv, unknown]
found_in: ["Apple Mac Pro (built by Flex since 2013), LG LCD televisions, Fitbit Force, Huawei smartphones and 5G base stations (products Flex manufactures for brands) [1]", "Google Chromecast H2G2-42 (manufacturer named as Flextronics International LTD in its FCC test report; the device itself transmits under Google and AzureWave OUIs) [12]", "Flextronics-branded Celeno 802.11n 5 GHz video bridges MWS1000 / MWB1305 that carry OUI 00:0B:8C [10][11]"]
radios: ["Wi-Fi 4 (802.11a/n 5 GHz, 2x2, Celeno/Ralink video bridges) [10][11]", "5 GHz [10][11]"]
silicon: ["Ralink RT2880 + RT2850 in Flextronics MWS1000 (Celeno VXT1025 bridge) [10]", "Celeno CL1300 + Maxim MAX2828 in Flextronics MWB1305 (Celeno VXT1300 access point / bridge) [11]", "Marvell 88DE3005 SoC + Marvell 88W8787 (AzureWave AW-NH387 module) in the Flextronics-built Google Chromecast H2G2-42 [12]"]
fcc_grantee: ["XQO (FCC IDs XQOMWS-1000 and XQOMWB-1305 on the Flextronics MWS1000 / MWB1305 video bridges) [10][11]"]
randomization: unknown
security_notes: ["No CVE in NVD matches the keyword 'Flextronics' as of 2026-10-27 [14]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Flextronics is the former name of Flex Ltd., founded in 1969, legally domiciled in Singapore with U.S. operations in Austin, Texas, publicly traded on Nasdaq, and the world's third-largest electronics manufacturing services / original design manufacturer by revenue; it renamed itself Flex in July 2015 [1]. It builds products for other brands rather than selling its own, so a MAC in one of its many IEEE blocks (00:0B:8C, 28:38:5C and 70:E1:FD as "Flextronics", 00:21:CC and 14:0D:4F as "Flextronics International", plus regional subsidiaries in Austria, Hungary, India, Mexico, Zhuhai and elsewhere) is normally an unbranded module or a contract-built device whose brand did not assign its own OUI [13]. Documented examples of Flex-built hardware include the Apple Mac Pro, LG TVs, Fitbit Force and Huawei phones/base stations [1], and the first Google Chromecast, whose FCC test report names Flextronics International LTD as the manufacturer although the device transmits under Google and AzureWave OUIs [12]. The devices documented transmitting under the Flextronics OUI 00:0B:8C are the Celeno-based 802.11n 5 GHz 2x2 video bridges MWS1000 (Ralink RT2880/RT2850) and MWB1305 (Celeno CL1300 + Maxim MAX2828), both certified under FCC grantee XQO [10][11]. Flex's other FCC grantee codes and the products filed under them could not be confirmed in this session because fccid.io returned HTTP 403 for every page fetched, so they are not listed. Because the OUI says nothing about the end product, treat an unknown Flextronics MAC as a contract-manufactured device of undetermined class and look at its traffic instead. No CVE in NVD names the company [14].
## Sources
1. Wikipedia - Flex Ltd. - https://en.wikipedia.org/wiki/Flex_Ltd. (accessed 2026-10-27)
2. fccid.io search "Flextronics" (grantee list and filing frequency ranges) - https://fccid.io/search/?q=Flextronics (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
3. FCC grantee ID4 - Flextronics International (Taiwan) Ltd. - https://fccid.io/ID4 (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
4. FCC grantee 2AG9G - Flextronics America LLC - https://fccid.io/2AG9G (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
5. FCC grantee 2AF5R - Flextronics International - https://fccid.io/2AF5R (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
6. FCC grantee QQD - Flextronics Canada Design Services Inc. - https://fccid.io/QQD (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
7. FCC grantee XQO - Flextronics Special Business Solutions Ltd. - https://fccid.io/XQO (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
8. FCC grantee WDG - Flextronics International GmbH - https://fccid.io/WDG (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
9. FCC grantee 2AVSM - Flextronics Computing (Suzhou) Co., Ltd - https://fccid.io/2AVSM (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
10. DeviWiki - Flextronics MWS1000 - https://deviwiki.com/wiki/Flextronics_MWS1000 (accessed 2026-10-27)
11. DeviWiki - Flextronics MWB1305 - https://deviwiki.com/wiki/Flextronics_MWB1305 (accessed 2026-10-27)
12. DeviWiki - Google Chromecast (H2G2-42) - https://deviwiki.com/wiki/Google_Chromecast_(H2G2-42) (accessed 2026-10-27)
13. Wireshark manuf OUI database (Flextronics blocks) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
14. NVD CVE API keyword search "Flextronics" (0 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Flextronics (accessed 2026-10-27)
