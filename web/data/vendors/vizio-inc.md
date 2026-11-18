---
name: Vizio, Inc
aliases: []
affiliates: []
country: US [1][2]
parent: Walmart (acquisition completed 3 December 2024) [1]
founded: 2002 [1]
kind: brand
device_classes: [tv, speaker]
found_in: ["Vizio smart TVs (D-, V-, M-Series Quantum, P-Series Quantum, OLED) running Vizio OS, formerly SmartCast [1]", "Vizio soundbars (V-Series, M-Series, Elevate) [1]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["FTC / New Jersey settlement, 6 Feb 2017, $2.2M: ACR 'Smart Interactivity' collected second-by-second viewing data from 11 million TVs without consent; required deletion and a privacy programme [3]", "CVE-2021-27942 (USB arbitrary code execution), CVE-2021-27943 (brute-forceable pairing), CVE-2021-27944 (high-privilege APIs without access control, CVSS 9.8) on P65-F1 6.0.31.4-2 and E50x-E1 10.0.31.4-2 firmware [4]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Vizio is an Irvine, California television and soundbar brand founded in 2002 by William Wang, acquired by Walmart on 3 December 2024 for $2.3 billion; its sets are built by ODM assemblers in Mexico, China and Vietnam [1][5]. In the IEEE registry copy shipped with sloth it holds 16 MA-L blocks under the single name "Vizio, Inc", the oldest (00:19:9D) registered 25 September 2006 to 39 Tesla, Irvine [2][6]. A MAC in these blocks is most likely a Vizio smart TV or soundbar running Vizio OS (formerly SmartCast) [1]. On the wire, expect ACR telemetry: the 2017 FTC settlement established that Vizio's "Smart Interactivity" feature reported second-by-second viewing data from 11 million TVs [3]. The 2021 CVE trio on P65-F1 and E50x-E1 firmware (brute-forceable pairing, high-privilege APIs without access control) argues for keeping the set off the management LAN [4]. The Wi-Fi modules, SoCs, radio bands and FCC grantee codes of Vizio products could not be verified for this entry (the WikiDevi mirror that documented them refused connections), so radios, silicon and fcc_grantee are left empty rather than recalled, and MAC randomization behaviour is not documented either; the Wireshark manuf fetch came back truncated, so the block count is read from the registry copy in the repository.
## Sources
1. Vizio - Wikipedia - https://en.wikipedia.org/wiki/Vizio (accessed 2026-10-27)
2. maclookup.app 00:19:9D registrant record - https://maclookup.app/macaddress/00199D (accessed 2026-10-27)
3. FTC press release, "VIZIO to Pay $2.2 Million to FTC, State of New Jersey..." (6 Feb 2017) - https://www.ftc.gov/news-events/news/press-releases/2017/02/vizio-pay-22-million-ftc-state-new-jersey-settle-charges-it-collected-viewing-histories-11-million (accessed 2026-10-27)
4. NVD CVE API, keyword "vizio" (3 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=vizio&resultsPerPage=20 (accessed 2026-10-27)
5. Vizio, About VIZIO - https://www.vizio.com/en/about-vizio (accessed 2026-10-27)
6. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
