---
name: "CradlePoint, Inc"
aliases: []
country: US [1][2][3]
parent: Ericsson (acquired September 2020) [2]
founded: unknown
kind: network-equipment [3]
device_classes: [ap/router [3], automotive-telematics [3][4], industrial [3]]
found_in: ["Cradlepoint WWAN routers and adapters for fixed sites, vehicles and IoT [3]", "Cradlepoint IBR900 and IBR600 routers [5]", "Ericsson in-vehicle 5G router [4]"]
radios: ["LTE/5G [3][4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2021-37471 restricted-shell escape denying NetCloud Manager, console and SSH on IBR900/IBR600 before 7.21.10 [5]", "CVE-2022-3086 shell escape to unrestricted shell for non-superusers on IBR600 NCOS 6.5.0.160bc2e and earlier [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Cradlepoint is a US-based carrier equipment manufacturer that Ericsson acquired in September 2020 for 1.1 billion US dollars [2]. The IEEE registry lists 2 MA-L blocks under CradlePoint, Inc at a Boise, Idaho address [1], which is also the North America headquarters on the current site, now branded Ericsson Enterprise Wireless Solutions [3][4].

A MAC in a Cradlepoint block is most likely a 4G or 5G WWAN router, adapter or access point at a fixed site, in a vehicle or on an IoT deployment; the site groups its hardware into WWAN routers, LAN switches and access points, WWAN adapters and private 5G/neutral host radios, sells NetCloud Manager, and offers to deploy secure 5G and LTE where fiber does not reach [3]. Its press releases include an Ericsson in-vehicle 5G router with dual-SIM failover [4]. NVD lists two restricted-shell escapes in the IBR900 and IBR600 routers [5].

Founding year, chipsets, FCC grantee codes, Wi-Fi generations and randomisation are unknown: Wikipedia's Cradlepoint article redirects to Ericsson, the FCC databases refused the session that wrote this entry, no teardown was found, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Cradlepoint (redirects to Ericsson) - Wikipedia - https://en.wikipedia.org/wiki/Cradlepoint (accessed 2026-10-27)
3. Ericsson Enterprise Wireless Solutions (Cradlepoint) home page - https://cradlepoint.ericsson.com/ (accessed 2026-10-27)
4. Ericsson Enterprise Wireless Solutions press releases - https://cradlepoint.ericsson.com/about/press-releases/ (accessed 2026-10-27)
5. NVD CVE API keyword search Cradlepoint - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cradlepoint&resultsPerPage=30 (accessed 2026-10-27)
