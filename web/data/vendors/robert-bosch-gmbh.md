---
name: Robert Bosch GmbH
aliases: ["ROBERT BOSCH GmbH", "Robert Bosch GmbH AnP", "Robert Bosch Gmbh, CM-CI2", "Robert Bosch GmbH, VT-ATMO"]
country: DE [1][2]
parent: Robert Bosch Stiftung, a charitable foundation holding about 94% of the shares without voting rights [1]
founded: 1886 [1]
kind: automotive [1]
device_classes: [smart-home [3], industrial [1][4], camera [4]]
found_in: ["Bosch Smart Home Controller and Smart Home Controller II [3][4]", "Bosch BCC101, BCC102 and BCC50 connected thermostats [4]", "Bosch Rexroth Nexo cordless nutrunners [4]", "Bosch IP cameras [4]"]
radios: ["868 MHz (first-generation Bosch Smart Home devices, reached from the Controller II through a radio stick) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["BOSCH-SA-473852 (2024): open port 8899 on BCC101, BCC102 and BCC50 thermostats [4]", "BOSCH-SA-711465 (2024): multiple vulnerabilities in Rexroth Nexo cordless nutrunners [4]", "BOSCH-SA-662084 (2019): multiple vulnerabilities in the Bosch Smart Home Controller [4]", "BOSCH-SA-638184-BT (2023) and BOSCH-SA-659648-BT (2024): command injection and unauthenticated information leak in Bosch IP camera firmware [4]", "BOSCH-SA-943700 (2026): vulnerabilities in BSH ELP electronic platforms [4]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Robert Bosch GmbH is the German engineering group founded by Robert
Bosch in Stuttgart in 1886 and headquartered in Gerlingen; the Robert
Bosch Stiftung owns about 94% of it without voting rights and the
Bosch family about 5% [1]. Mobility is its largest business, about 61%
of 2024 revenue, beside consumer goods (BSH home appliances, power
tools, eBike systems), industrial technology (Bosch Rexroth) and
energy and building technology [1]. The IEEE registry lists five MA-L
blocks to "Robert Bosch GmbH" at Gerlingen, Leonberg, Reutlingen and
Stuttgart addresses, plus one each to "ROBERT BOSCH GmbH", "Robert
Bosch GmbH AnP", "Robert Bosch Gmbh, CM-CI2" and "Robert Bosch GmbH,
VT-ATMO" [2]; the group's subsidiaries (Bosch Rexroth, Bosch Security
Systems, Robert Bosch Smart Home GmbH and others) hold their own
blocks under their own names and are not covered here [2].

The sources consulted do not say which product a MAC in these blocks
belongs to, so the device classes above are the group's connected
product lines, not a mapping of the blocks [1][3][4]. The Smart Home
Controller II is advertised as Matter-ready and reaches
first-generation Bosch Smart Home devices on 868 MHz through a radio
stick [3]. Bosch PSIRT has published advisories for the connected
thermostats, the Smart Home Controller, Rexroth cordless nutrunners,
IP cameras and BSH appliance electronics [4]. No silicon, FCC grantee
code or randomization behaviour is listed: the FCC ID databases
(fccid.io, fcc.report, the FCC grantee search) refused the session that
wrote this entry, and no teardown was reached.

## Sources

1. Robert Bosch GmbH - Wikipedia - https://en.wikipedia.org/wiki/Robert_Bosch_GmbH (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Bosch Smart Home Controller - Bosch Smart Home - https://www.bosch-smarthome.com/uk/en/products/devices/smart-home-controller/ (accessed 2026-10-27)
4. Security Advisories - Bosch PSIRT - https://psirt.bosch.com/security-advisories/ (accessed 2026-10-27)
