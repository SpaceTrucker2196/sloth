---
name: Balboa Instruments
aliases: []
country: US [1]
parent: Helios Technologies, which acquired BWG Holdings I Corp. (Balboa Water Group) on 6 November 2020 (inferred to be the same company) [2][3]
founded: unknown
kind: brand [3]
device_classes: [smart-home [3][4]]
found_in: ["Balboa bwa Wi-Fi module (part 50350) for BP Series spa control packs, controlled by the Spa Control app [3][4]"]
radios: ["Wi-Fi (bwa Wi-Fi module) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists one MA-L block, 00:15:27, to "Balboa Instruments" at 1382 Bell Ave, Tustin, California [1]. Helios Technologies completed the acquisition of BWG Holdings I Corp., which its filing calls Balboa Water Group, on 6 November 2020, and describes it as a market leader of electronic controls for the health and wellness industry [2]; the Spa Control app, published by Balboa Water Group, requires the Balboa BP Series spa control pack bwa Wi-Fi module, part number 50350 [3].

A MAC in this block is almost certainly that bwa Wi-Fi module on a hot tub: community protocol documentation attributes OUI 00:15:27 to Balboa Instruments and shows the module answering a UDP broadcast on port 30303 with its hostname (for example BWGSPA) and its MAC, then bridging the spa's RS-485 control bus to a TCP connection on port 4257 [4]. That this Balboa Instruments registration and Balboa Water Group are the same business is inferred from the shared Balboa brand and the OUI attribution, not stated by a source [3][4].

Founding year, chipset and FCC grantee codes are not documented by the sources consulted; the FCC ID databases refused automated access from this session. Randomization is unknown, and no security advisory for the module was found.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Helios Technologies Form 10-Q, Q2 FY2021, acquisition note - https://www.sec.gov/Archives/edgar/data/1024795/000156459021042912/R8.htm (accessed 2026-10-27)
3. Spa Control - BWA - App Store - https://apps.apple.com/app/id469882268 (accessed 2026-10-27)
4. balboa_worldwide_app wiki - GitHub (ccutrer) - https://github.com/ccutrer/balboa_worldwide_app/wiki (accessed 2026-10-27)
