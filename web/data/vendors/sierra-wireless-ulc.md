---
name: "Sierra Wireless, ULC"
aliases: []
country: CA [1][2]
parent: Semtech (acquisition closed January 2023) [2]
founded: 1993 [2]
kind: module-maker [2]
device_classes: [module-in-other-brands [2][4], ap/router [2][5], laptop [4]]
found_in: ["EM7455 module labelled Dell 5811e in a Dell Latitude 7275, per a user report [4]", "AirLink cellular routers and gateways [2][5]"]
radios: ["LTE/5G [2][3]"]
silicon: ["Qualcomm Snapdragon X7 LTE modem in the AirPrime EM7455 [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CISA ICSA-23-341-06 (December 2023): seven flaws in AirLink ALEOS before 4.9.9 and 4.17.0, including ACEManager DoS and XSS, a root password hash readable in debug mode and a hard-coded TLS certificate and key [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sierra Wireless was founded in 1993 and is headquartered in Richmond, British Columbia; Semtech agreed to buy it in August 2022 for about 1.2 billion US dollars including debt and closed in January 2023 [2]. It sells IoT and machine-to-machine products, embedded cellular modules and AirLink gateways and routers, and the AirVantage and Octave cloud platforms; it sold its AirCard mobile-broadband line to NETGEAR in 2013 and its automotive module business in 2020 [2]. The IEEE registry lists six MA-L blocks to Sierra Wireless, ULC at Wireless Way, Richmond [1].

A MAC in a Sierra block is most likely either a cellular module's network interface inside another maker's laptop or machine, or an AirLink router [2][4]. The AirPrime EM7455 is an LTE-Advanced Category 6 M.2 module based on the Qualcomm Snapdragon X7 LTE modem [3]; a user on Sierra's forum reports an EM7455 labelled Dell 5811e in a Dell Latitude 7275 [4].

On 7 December 2023 CISA advisory ICSA-23-341-06 covered seven ALEOS flaws in AirLink routers, including denial of service and cross-site scripting in ACEManager, the SHA512 hash of the root password readable in debug mode and a hard-coded TLS certificate and key for ACEManager, fixed in ALEOS 4.9.9 and 4.17.0 [5]. The FCC ID databases refused this session's requests, so no grantee code is listed, and no source documents MAC randomization.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Sierra Wireless - Wikipedia - https://en.wikipedia.org/wiki/Sierra_Wireless (accessed 2026-10-27)
3. Sierra AirPrime EM7455 LTE-A Module in M.2 Format - 4GLTEMall - https://www.4gltemall.com/blog/tag/lte-a-module/ (accessed 2026-10-27)
4. EM7455 - Dell Latitude 7275 - Sierra Wireless Forum - https://forum.sierrawireless.com/t/em7455-dell-latitude-7275/8947 (accessed 2026-10-27)
5. Sierra Wireless AirLink with ALEOS firmware, ICSA-23-341-06 - CISA - https://www.cisa.gov/news-events/ics-advisories/icsa-23-341-06 (accessed 2026-10-27)
