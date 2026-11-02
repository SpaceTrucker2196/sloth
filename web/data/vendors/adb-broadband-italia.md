---
name: ADB Broadband Italia
aliases: ["ADB Italia "]
country: IT [1]
parent: Advanced Digital Broadcast (ADB Group), inferred from the registrant name; ADB bought Pirelli Broadband Solutions in 2010 [2][3]
founded: unknown
kind: network-equipment [2]
device_classes: [ap/router [2][4]]
found_in: ["operator-supplied broadband gateways running ADB's epiCentro CPE middleware, on more than 30 million devices [4]", "ADB P.DGA4001N router (formerly Pirelli Broadband Solutions) [5]"]
radios: ["Wi-Fi 6 (fibre gateway, 2021) [2]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2018-13108, CVE-2018-13109, CVE-2018-13110: local root jailbreak, authorization bypass and CLI privilege escalation on all ADB gateways built on epiCentro [6]", "CVE-2015-0558: the P.DGA4001N, and possibly other routers, derive the default WPA key from the constant 1236790 and the MAC address [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 24 MA-L blocks to "ADB Broadband Italia" and two to "ADB Italia " (with a trailing space), all at Viale Sarca addresses in Milan, Italy [1]. ADB Broadband Italia is, by its name and address (the sources consulted do not name it), the Italian broadband arm of Advanced Digital Broadcast, the Swiss set-top-box and residential-gateway company founded in 1995 and headquartered in Bellevue near Geneva, which entered broadband by buying Pirelli's broadband business in 2010 [2][3]; NVD still describes the gear as ADB, formerly Pirelli Broadband Solutions [5]. A MAC in these blocks is most likely a broadband home gateway supplied through an operator: ADB supplies gateway platforms built with ODM partners and runs its epiCentro CPE middleware on more than 30 million devices [4], ADB supplies its residential gateways to operators [2], and it added Wi-Fi mesh in 2018 and a Wi-Fi 6 fibre gateway in 2021 [2].

The security history matters for an operator watching the air: on the P.DGA4001N, and possibly other routers, the default WPA key is derived from a constant and the device's MAC address (CVE-2015-0558), so a heard BSSID can give away the key [5]. All epiCentro-based ADB gateways were affected in 2018 by a local root jailbreak, an authorization bypass of ISP-locked settings and a CLI privilege escalation (CVE-2018-13108 to 13110) [6]. Silicon, FCC grantee codes and founding year of the Italian unit are not documented by the sources consulted (the FCC ID databases and DeviWiki pages were not reachable), and randomization is unknown [4].

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Advanced Digital Broadcast - Wikipedia - https://en.wikipedia.org/wiki/Advanced_Digital_Broadcast (accessed 2026-10-27)
3. ADB - Our History - https://www.adbglobal.com/our-history/ (accessed 2026-10-27)
4. ADB epiCentro broadband CPE software - https://adbglobal.com/broadband-epicentro/ (accessed 2026-10-27)
5. NVD - CVE-2015-0558 - https://nvd.nist.gov/vuln/detail/CVE-2015-0558 (accessed 2026-10-27)
6. NVD - CVE-2018-13108 - https://nvd.nist.gov/vuln/detail/CVE-2018-13108 (accessed 2026-10-27)
