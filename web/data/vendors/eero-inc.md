---
name: eero inc.
aliases: []
country: US [2]
parent: Amazon (acquired 2019) [1]
founded: unknown
kind: brand [1]
device_classes: [ap/router [1]]
found_in: ["eero mesh Wi-Fi systems: eero, eero Pro, eero Beacon, eero 6 and 6+, eero Pro 6 and 6E, eero PoE 6, eero Max 7, eero 7, eero Pro 7, eero Outdoor 7 [1]"]
radios: ["Wi-Fi 5/6/6E/7 [1]", "2.4 GHz [1]", "5 GHz [1]", "6 GHz [1]", "Thread/Zigbee (802.15.4), Thread on models from 2017 on [1]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2023-5324: denial of service through the Ethernet interface in eeroOS up to 6.16.4-11, from the local network [3]", "the original eero stopped receiving guaranteed feature and security updates on 30 September 2022 [1]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

eero is a home mesh Wi-Fi brand whose first system went on sale on 23 February 2016; its developer, Eero LLC, has been a wholly owned subsidiary of Amazon since Amazon bought it in 2019 for 97 million dollars [1]. The IEEE registry lists 110 MA-L blocks to "eero inc." at a San Francisco, California address [2]. A MAC in an eero block is almost certainly one of its mesh nodes or gateways: the line ran from the Wi-Fi 5 eero of 2016 through the Wi-Fi 6 eero 6 family of 2020, the 6 GHz Wi-Fi 6E eero Pro 6E of 2022 and, from the eero Max 7 of 2023, its first Wi-Fi 7 system, to the eero Outdoor 7, eero 7 and eero Pro 7 of 2024 and 2025 [1].

Beyond Wi-Fi, Wikipedia's hardware table lists Thread support from the 2017 eero Beacon and eero Pro on and Matter support from the eero 6 on, so an eero node may also be heard on 802.15.4 [1]. NVD records CVE-2023-5324, a denial of service in eeroOS up to 6.16.4-11 reachable from the local network through the Ethernet interface [3]. The original eero lost guaranteed security updates on 30 September 2022 [1]. Silicon and FCC grantee codes are not listed because the FCC ID databases and teardown sites were not reachable from the session that wrote this entry, and the founding year is not stated by the sources consulted; randomization of the node's own addresses is not documented [1].

## Sources

1. Eero (company) - Wikipedia - https://en.wikipedia.org/wiki/Eero_(company) (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. NVD - CVE-2023-5324 - https://nvd.nist.gov/vuln/detail/CVE-2023-5324 (accessed 2026-10-27)
