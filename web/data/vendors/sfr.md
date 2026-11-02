---
name: SFR
aliases: []
country: FR [1][2]
parent: Altice France [2]
founded: 1987 [2]
kind: carrier/isp [2]
device_classes: [ap/router [3]]
found_in: ["SFR-branded home gateways (neufbox, SFR Box) [3]", "neufbox Trio2 built by Ambit [3]", "neufbox 4 and later built by Foxconn and Sercomm [3]"]
radios: ["Wi-Fi 4 [3]", "Wi-Fi 5 [3]", "Wi-Fi 6 [3]", "Wi-Fi 7 [3]", "LTE/5G [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

SFR is a French telecommunications operator founded in 1987 so that its then parent Compagnie Generale des Eaux could offer a mobile phone service; it is now part of Altice France and sells fixed and mobile internet, telephony and IP television [2]. The IEEE registry lists 12 MA-L blocks under the name SFR at addresses in Boulogne-Billancourt, La Plaine Saint-Denis and Nanterre [1].

As an operator rather than a hardware maker, SFR's own blocks most plausibly sit on the home gateways it hands to subscribers; that link between the blocks and the boxes is inferred, not documented by a source in hand. The French Wikipedia history of those gateways records that the neufbox Trio2 was made by Ambit, that the neufbox 4 and later models were made by Foxconn and Sercomm to secure supply, that the firmware was developed by Efixo on an OpenWrt base, and that the line moved from 802.11n on the neufbox 4 and 5 through 802.11ac on the Box Plus and Wi-Fi 6 on the SFR Box 8 to Wi-Fi 7 on the SFR Box 10+ and the Box 5G WiFi 7, with 4G and 5G fixed-wireless boxes alongside [3].

Chipsets, FCC grantee codes and randomisation are unknown: the article names no chip vendor, a French operator's boxes are not expected in the FCC databases, and those databases refused the session in any case. An NVD keyword search for neufbox returned no CVEs [4].

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. SFR (company) - Wikipedia - https://en.wikipedia.org/wiki/SFR_(company) (accessed 2026-10-27)
3. Neuf Box - Wikipedia (French) - https://fr.wikipedia.org/wiki/Neuf_Box (accessed 2026-10-27)
4. NVD CVE API keyword search neufbox - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=neufbox&resultsPerPage=30 (accessed 2026-10-27)
