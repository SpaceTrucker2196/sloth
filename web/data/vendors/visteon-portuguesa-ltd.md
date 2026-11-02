---
name: "Visteon Portuguesa, Ltd"
aliases: []
affiliates: []
country: PT [1]
parent: Visteon Corporation, the Ford spin-off with facilities in Portugal (inferred from the name) [2][3]
founded: unknown
kind: automotive [2]
device_classes: [automotive-infotainment [2][3][4], automotive-telematics [2]]
found_in: ["Mazda Connect CMU infotainment unit manufactured by Visteon, in models such as the Mazda 3 MY2014-2021 (Visteon group; plant not stated) [4]"]
radios: ["Bluetooth (Murata LBEE6Z2U0C-584 module in the Mazda CMU) [4]"]
silicon: ["Freescale SCIMX06DAVT10AC application SoC and Renesas R5F35MCEJFF CAN MCU in the Visteon-built Mazda Connect CMU [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["ZDI 2024: CVE-2024-8355 to CVE-2024-8360 in the Visteon-built Mazda Connect CMU, reachable with a crafted USB device, some giving root code execution [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists one MA-L block to "Visteon Portuguesa, Ltd" at Estrada Nacional 252, Palmela, Portugal [1]. Visteon is the American automotive cockpit electronics supplier that Ford spun off in June 2000, headquartered in Van Buren Township, Michigan, making digital instrument clusters, infotainment systems and telematics control units, with facilities in Portugal among other countries [2]. The Palmela plant employs around 1,200 people making automotive electronics including audio components and airbag control modules, and new facilities there were inaugurated in September 2025 [3].

A MAC in this block is most likely a car's infotainment head unit, audio unit or instrument cluster built at Palmela; which products carry it is not documented, so that reading is inferred from the plant's output [1][3]. As an example of Visteon hardware, the Mazda Connect CMU studied by Trend Micro's Zero Day Initiative was manufactured by Visteon and carries a Freescale application SoC, a Renesas MCU on the CAN bus and a Murata Bluetooth module [4]. ZDI disclosed six vulnerabilities in it in November 2024, CVE-2024-8355 to CVE-2024-8360, exploitable by a physically present attacker with a crafted USB device and in some cases giving root code execution [4].

Founding year and FCC grantee codes are unknown: no source in hand describes the Portuguese subsidiary's history, and the FCC ID databases refused automated access from this session. Randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Visteon - Wikipedia - https://en.wikipedia.org/wiki/Visteon (accessed 2026-10-27)
3. Visteon Palmela investment - Eurofound European Restructuring Monitor - https://apps.eurofound.europa.eu/restructuring-events/detail/203466 (accessed 2026-10-27)
4. Multiple Vulnerabilities in the Mazda In-Vehicle Infotainment (IVI) System - Zero Day Initiative - https://www.zerodayinitiative.com/blog/2024/11/7/multiple-vulnerabilities-in-the-mazda-in-vehicle-infotainment-ivi-system (accessed 2026-10-27)
