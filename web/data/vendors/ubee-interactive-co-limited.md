---
name: "Ubee Interactive Co., Limited"
aliases: ["Ubee Interactive co, Limited."]
country: TW [2]
parent: unknown
founded: 1991 [2]
kind: network-equipment [2][3]
device_classes: [ap/router [2][4]]
found_in: ["Spectrum RAC2V1U (Ubee UBH1707-AA00) router [4]", "cable operators' DOCSIS modems and Wi-Fi gateways [2][3]", "SFR neufbox Trio2, built by Ambit, Ubee's former name [2][5]"]
radios: ["Wi-Fi 4 [4]", "Wi-Fi 5 [4]", "2.4 GHz [4]", "5 GHz [4]"]
silicon: ["Broadcom BCM3383 cable SoC with BCM4331 Wi-Fi in DVW323 [4]", "Broadcom BCM33843 with two BCM4360 Wi-Fi in DVW32C [4]", "Broadcom BCM3384ZU with BCM4331 and BCM4360 in UBC1310-BA00 [4]", "Broadcom BCM4709C0 with BCM4360/BCM4366E in Spectrum RAC2V1U [4]", "TI TNETC4830 with Atheros AR9130 in DDW3600 [4]"]
fcc_grantee: ["XCN [4]"]
randomization: unknown
security_notes: ["CVE-2024-23726 predictable default WPA2 keys derivable from SSID and BSSID on DDW365 [6]", "CVE-2016-15056 unauthenticated config backup with plaintext admin password on EVW3226 [6]", "CVE-2018-20400 credentials exposed over SNMP on DVW2108/DVW2110 [6]", "CVE-2024-28092 stored XSS on DDW365 and CVE-2021-47820 CSRF enabling remote access on EVW327 [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Ubee Interactive is a broadband CPE maker founded in 1991 and headquartered in Zhubei, Hsinchu County, Taiwan; it was formerly Ambit Microsystems, renamed in March 2009, was an early adopter of DOCSIS, and sells cable modems, VoIP and IPTV gateways and Wi-Fi gateways to cable and telecom operators [2]. The IEEE registry lists 13 MA-L blocks under Ubee Interactive Co., Limited and one under Ubee Interactive co, Limited., all at North Point, Hong Kong addresses [1]. The company's site says it specialises in broadband solutions for cable and telecommunications service providers in Europe and the Americas, with DOCSIS, PON (GPON, XGS-PON, 10G EPON) and Wi-Fi mesh products [3].

A MAC in a Ubee block is almost always an operator-supplied cable modem or gateway rather than a retail product. DeviWiki lists the FCC grantee code XCN, and documents Broadcom cable SoCs from the BCM3349 to the DOCSIS 3.1 BCM3390, with Texas Instruments TNETC4830 on some older boards, paired with Broadcom 802.11n and 802.11ac radios such as the BCM4331 and BCM4360 across the DVW and UBC lines, plus the Spectrum-branded RAC2V1U [4]. The French Wikipedia says SFR's neufbox Trio2 was made by Ambit and links that name to the Ubee Interactive article [5]. NVD lists default WPA2 keys derivable from the SSID and BSSID on the DDW365, an unauthenticated config backup exposing the admin password on the EVW3226, SNMP credential exposure, XSS and CSRF [6].

Parent company and randomisation behaviour are unknown, the FCC databases themselves refused the session that wrote this entry, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Ubee Interactive - Wikipedia - https://en.wikipedia.org/wiki/Ubee_Interactive (accessed 2026-10-27)
3. Ubee Interactive home page - https://www.ubeeinteractive.com/ (accessed 2026-10-27)
4. Ubee - DeviWiki - https://deviwiki.com/wiki/Ubee (accessed 2026-10-27)
5. Neuf Box - Wikipedia (French) - https://fr.wikipedia.org/wiki/Neuf_Box (accessed 2026-10-27)
6. NVD CVE API keyword search Ubee - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Ubee&resultsPerPage=30 (accessed 2026-10-27)
