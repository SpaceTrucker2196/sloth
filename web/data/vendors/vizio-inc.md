---
name: Vizio, Inc
aliases: []
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
security_notes: ["FTC / New Jersey settlement, 6 Feb 2017, $2.2M: ACR 'Smart Interactivity' collected second-by-second viewing data from 11 million TVs without consent; required deletion and a privacy programme [4]", "CVE-2021-27942 (USB arbitrary code execution), CVE-2021-27943 (brute-forceable pairing), CVE-2021-27944 (high-privilege APIs without access control, CVSS 9.8) on P65-F1 6.0.31.4-2 and E50x-E1 10.0.31.4-2 firmware [5]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Vizio is an Irvine, California television and soundbar brand founded in 2002 by William Wang, acquired by Walmart on 3 December 2024 for $2.3 billion; its sets are built by ODM assemblers in Mexico, China and Vietnam [1][11]. In the IEEE registry copy shipped with sloth it holds 16 MA-L blocks under the single name "Vizio, Inc", the oldest (00:19:9D) registered 25 September 2006 to 39 Tesla, Irvine [2][12]. A MAC in these blocks is most likely a Vizio smart TV or soundbar running Vizio OS (formerly SmartCast) [1]. On the wire, expect ACR telemetry: the 2017 FTC settlement established that Vizio's "Smart Interactivity" feature reported second-by-second viewing data from 11 million TVs [4]. The 2021 CVE trio on P65-F1 and E50x-E1 firmware (brute-forceable pairing, high-privilege APIs without access control) argues for keeping the set off the management LAN [5]. The Wi-Fi modules, SoCs, radio bands and FCC grantee codes of Vizio products could not be verified for this entry (the WikiDevi mirror that documented them refused connections), so radios, silicon and fcc_grantee are left empty rather than recalled, and MAC randomization behaviour is not documented either; the Wireshark manuf fetch came back truncated, so the block count is read from the registry copy in the repository.
## Sources
1. Vizio - Wikipedia - https://en.wikipedia.org/wiki/Vizio (accessed 2026-10-27)
2. maclookup.app 00:19:9D registrant record - https://maclookup.app/macaddress/00199D (accessed 2026-10-27)
3. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27) (does not support the claim: the fetch returned a truncated file with no Vizio lines; source 12 carries the blocks)
4. FTC press release, "VIZIO to Pay $2.2 Million to FTC, State of New Jersey..." (6 Feb 2017) - https://www.ftc.gov/news-events/news/press-releases/2017/02/vizio-pay-22-million-ftc-state-new-jersey-settle-charges-it-collected-viewing-histories-11-million (accessed 2026-10-27)
5. NVD CVE API, keyword "vizio" (3 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=vizio&resultsPerPage=20 (accessed 2026-10-27)
6. WikiDevi: VIZIO XWR100 - https://wikidevi.wi-cat.ru/VIZIO_XWR100 (accessed 2026-10-27) (not reachable 2026-10-27: connection refused)
7. WikiDevi: Wistron NeWeb DNUR-W7601 - https://wikidevi.wi-cat.ru/Wistron_NeWeb_DNUR-W7601 (accessed 2026-10-27) (not reachable 2026-10-27: connection refused)
8. WikiDevi: Arcadyan WN7511E - https://wikidevi.wi-cat.ru/Arcadyan_WN7511E (accessed 2026-10-27) (not reachable 2026-10-27: connection refused)
9. WikiDevi: Wistron NeWeb DNUR-W5370 - https://wikidevi.wi-cat.ru/Wistron_NeWeb_DNUR-W5370 (accessed 2026-10-27) (not reachable 2026-10-27: connection refused)
10. WikiDevi full-text search "Vizio" - https://wikidevi.wi-cat.ru/index.php?title=Special:Search&search=Vizio&fulltext=1 (accessed 2026-10-27) (not reachable 2026-10-27: connection refused)
11. Vizio, About VIZIO - https://www.vizio.com/en/about-vizio (accessed 2026-10-27)
12. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
