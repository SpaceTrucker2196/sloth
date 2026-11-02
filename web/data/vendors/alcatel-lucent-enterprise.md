---
name: Alcatel-Lucent Enterprise
aliases: []
country: FR [2]
parent: China Huaxin Post and Telecom Technologies [2]
founded: 2014 [2]
kind: network-equipment [2]
device_classes: [ap/router [3], switch [5], phone [4]]
found_in: ["OmniAccess Stellar Wi-Fi 6, 6E and 7 access points [3]", "OmniSwitch Ethernet switches [5]", "ALE 8008 Cloud Edition deskphone [4]"]
radios: ["Wi-Fi 6 [2][3]", "Wi-Fi 6E [3]", "Wi-Fi 7 [3]", "2.4 GHz [3]", "5 GHz [3]", "6 GHz [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["ALE 8008 Cloud Edition deskphone firmware 1.50.13: command injection (CVE-2019-14260) [4]", "Alcatel-Lucent OmniPCX Enterprise and IP Touch phones: mini-switch enabled by default and TFTP address caching (CVE-2007-2512, CVE-2007-5361), buffer overflows in the Unified Maintenance Tool (CVE-2011-0344) [4]", "Alcatel-Lucent OmniSwitch management web interface: weak session identifiers (CVE-2015-2804) and CSRF that creates local accounts (CVE-2015-2805) [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Alcatel-Lucent Enterprise (ALE) is the former enterprise division of Alcatel-Lucent, bought by China Huaxin Post and Telecom Technologies in 2014 with Alcatel-Lucent keeping a 15% stake; it has its main offices in Colombes, France, and stayed a separate company when Nokia absorbed Alcatel-Lucent in 2016 [2]. It develops access networking, data-centre, wireless, voice-over-IP, unified communications and contact-centre products, and in 2019 released what Wikipedia calls the first certified Wi-Fi 6 outdoor access point [2]. The IEEE registry lists 12 MA-L blocks to "Alcatel-Lucent Enterprise" at Calabasas and Thousand Oaks, California [1].

A MAC in these blocks is most likely enterprise network equipment: an OmniAccess Stellar access point, an OmniSwitch or an ALE deskphone [3][4][5]. ALE's current Stellar range runs from Wi-Fi 6 (AP1301 to AP1351, the dual-band outdoor AP1360) through Wi-Fi 6E (the tri-band AP1431 and the AP1451) to Wi-Fi 7 (AP1501 tri-band on 2.4, 5 and 6 GHz, AP1511, AP1521 and the AP1540, AP1561 and AP1570 series) [3]. The registry's other Alcatel and Alcatel-Lucent names are not covered here [1]; Alcatel-Lucent itself merged into Nokia Networks in 2016 [2].

NVD records a command injection in the ALE 8008 Cloud Edition deskphone, older OmniPCX Enterprise and IP Touch flaws, and OmniSwitch management-interface flaws from 2015 [4][5]. Silicon, FCC grantee codes and randomization are unknown: no teardown was found on DeviWiki and the FCC ID databases refused the session's requests.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Alcatel-Lucent Enterprise - Wikipedia - https://en.wikipedia.org/wiki/Alcatel-Lucent_Enterprise (accessed 2026-10-27)
3. WLAN products - Alcatel-Lucent Enterprise - https://www.al-enterprise.com/en/products/wlan (accessed 2026-10-27)
4. Alcatel-Lucent Enterprise CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Alcatel-Lucent%20Enterprise (accessed 2026-10-27)
5. OmniSwitch CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=OmniSwitch (accessed 2026-10-27)
