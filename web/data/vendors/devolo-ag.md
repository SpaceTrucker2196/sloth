---
name: devolo AG
aliases: []
country: DE [1][2]
parent: "SOL Capital (acquired essential parts in an asset deal after the 2024 insolvency; continued as devolo solutions GmbH) [3]"
founded: 2002 [2][3]
kind: brand [4]
device_classes: [ap/router [4][5], smart-home [3], industrial [2][3]]
found_in: ["devolo Magic powerline adapters (G.hn) [3][4]", "devolo dLAN powerline adapters (HomePlug AV) [2][3]", "devolo Wi-Fi mesh systems, repeaters and routers [4][5]", "devolo-built adapters supplied to telecom operators as an OEM [2]"]
radios: ["Wi-Fi 6 [4]", "Wi-Fi 7 [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-25249 authentication bypass enabling hidden services in dLAN 500 AV Wireless+ firmware 3.1.0-1 [6]", "CVE-2019-25250 cross-site request forgery in dLAN 500 AV Wireless+ [6]", "CVE-2019-25231 unquoted service path in the dLAN Cockpit 4.3.1 utility [6]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

devolo is a German home-networking company founded in Aachen in 2002 that sends data over a building's electrical wiring with powerline communication, using HomePlug AV in older dLAN adapters and G.hn in current consumer models, some combining powerline with Wi-Fi [2]. The German Wikipedia records that it began as a management buyout of ELSA AG's data communications division, filed for insolvency in February 2022 and again in December 2023, and that after the second proceeding closed in April 2024 the Austrian investor SOL Capital took over essential parts of the business, continued as devolo solutions GmbH in Aachen [3]. The IEEE registry lists 6 MA-L blocks under devolo AG at an Aachen address [1].

A MAC in a devolo block is most likely a Magic powerline adapter, a Wi-Fi repeater or mesh unit, or a devolo router; the current range advertises Wi-Fi 6 and Wi-Fi 7 products [4], and the company's portrait lists Wi-Fi mesh systems, Magic powerline, repeaters, routers, fibre optic solutions and switches alongside business DIN-rail powerline modules [5]. devolo also supplies telecom operators as an OEM and builds industrial and smart-grid devices [2], and its range has included smart-home and smart meter gateway products [3]. NVD lists an authentication bypass that enables hidden services and a CSRF flaw in dLAN 500 AV Wireless+ firmware and an unquoted service path in the dLAN Cockpit utility that lets a local user run code with elevated privileges [6].

The documented chipsets inside devolo products, FCC grantee codes and MAC randomisation behaviour are left unknown: the FCC ID databases refused the session that wrote this entry, no teardown was found, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. devolo - Wikipedia - https://en.wikipedia.org/wiki/Devolo (accessed 2026-10-27)
3. Devolo - Wikipedia (German) - https://de.wikipedia.org/wiki/Devolo (accessed 2026-10-27)
4. devolo home page - https://www.devolo.com/en/ (accessed 2026-10-27)
5. devolo portrait - https://www.devolo.com/en/about-devolo/portrait (accessed 2026-10-27)
6. NVD CVE API keyword search devolo - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=devolo&resultsPerPage=30 (accessed 2026-10-27)
