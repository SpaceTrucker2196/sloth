---
name: "GD Midea Air-Conditioning Equipment Co.,Ltd."
aliases: []
country: CN [1][2]
parent: Midea Group, inferred: Midea Group lists GD Midea as a wholly owned subsidiary and the registry address is the Midea Global Innovation Center [1][2]
founded: unknown
kind: brand [2]
device_classes: [smart-home [3][4]]
found_in: ["Midea, Comfee and Inventor EVO air conditioners and dehumidifiers with Midea Wi-Fi [4]", "air conditioners sold by Electrolux, Qlima, Artel, Carrier, Comfee, Inventor and Senville that speak the Midea UART protocol [3]"]
radios: ["Wi-Fi, generation not documented [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2024-56972: the Midea Home iOS app 9.3.12 leaks sensitive user information via a crafted link (the companion app, not the appliance) [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 50 MA-L blocks to GD Midea Air-Conditioning
Equipment Co.,Ltd. at the Midea Global Innovation Center, Beijiao Town,
Shunde, Foshan, China [1]. Midea Group, founded in 1968 by He Xiangjian
and headquartered in Beijiao, Shunde, is a Chinese appliance maker
whose core business is residential and commercial air conditioning,
listed in Shenzhen and Hong Kong, which lists GD Midea and KUKA as
wholly owned subsidiaries, bought Toshiba's home-appliance business in
2016, and does most of its export business as an OEM and ODM for other
brands [2]. A MAC in one of these
blocks is most likely a networked air conditioner or dehumidifier:
open-source integrations talk to Midea, Comfee and Inventor EVO units
with Midea Wi-Fi, discovering them on UDP port 6445 and then speaking
an encrypted protocol on TCP port 6444, with version 3 firmware
requiring a token and key pair [4]. ESPHome documents the same
appliances' 9600 baud UART protocol and lists Electrolux, Qlima,
Artel, Carrier, Comfee, Inventor and Senville among the vendors that
use it, so the brand on the unit is often not Midea [3]. That those
appliances carry this particular registrant's blocks, rather than
another Midea entity's, is inferred and not stated by any source
consulted [1][3][4].

NVD records one issue against Midea's companion app, CVE-2024-56972 in
Midea Home for iOS [5]. The Wi-Fi module's silicon, the FCC grantee
codes and the address randomisation behaviour are not listed: no
teardown was found, the FCC ID databases refused the session that
wrote this entry, web search was unavailable, and nothing is filled in
from memory [1].

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Midea Group - Wikipedia - https://en.wikipedia.org/wiki/Midea_Group (accessed 2026-10-27)
3. Midea Air Conditioner - ESPHome - https://esphome.io/components/climate/midea/ (accessed 2026-10-27)
4. midea-beautiful-air - GitHub - https://github.com/nbogojevic/midea-beautiful-air (accessed 2026-10-27)
5. CVE-2024-56972 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-56972 (accessed 2026-10-27)
