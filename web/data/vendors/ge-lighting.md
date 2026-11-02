---
name: GE Lighting
aliases: []
country: US [1][2]
parent: Savant Systems, which acquired GE Lighting on 1 July 2020 [2][3]
founded: 1911 [2]
kind: brand [2][4]
device_classes: [smart-home [4][5]]
found_in: ["Cync smart bulbs, light strips, fixtures, switches, plugs, cameras, thermostat and sensors, the line formerly called C by GE [4][5]"]
radios: ["Wi-Fi (band not documented) on Cync Wi-Fi devices [5][6]", "Bluetooth on Bluetooth-only Cync devices, which form a Bluetooth mesh [5][6]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

GE Lighting traces its origins to Thomas Edison's lighting work, lists 1911 as its founding, and is headquartered at Nela Park, East Cleveland, Ohio [2]. General Electric sold it to Savant Systems on 1 July 2020, its last consumer business, for a reported 250 million dollars, and it is now a division of Savant [3]. Its site carries the name GE Lighting, a Savant Company, with the GE monogram used under licence from General Electric [4]. The IEEE registry lists three MA-L blocks to GE Lighting at 1975 Noble Rd, East Cleveland [1].

A MAC in these blocks is most likely a Cync smart-home device: Cync, formerly C by GE, is GE Lighting's line of smart devices [5], and GE Lighting's site lists Cync bulbs, light strips, fixtures, switches, plugs, cameras, a thermostat and sensors [4]. The Home Assistant integration needs at least one Wi-Fi connected Cync device on the account and notes that older Bluetooth-only devices may need a Cync bridge [5]; a community integration likewise needs a Wi-Fi device and reports that the wireless motion sensor talks only on the Bluetooth mesh the devices form [6]. Both integrations are cloud based through the Cync servers [5][6].

No CVE naming Cync or GE Lighting smart products was found in NVD [7]. The FCC ID databases refused automated access and no teardown was reached, so silicon, FCC grantee codes and the Wi-Fi band are not listed and randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. GE Lighting - Wikipedia - https://en.wikipedia.org/wiki/GE_Lighting (accessed 2026-10-27)
3. Savant Systems - Wikipedia - https://en.wikipedia.org/wiki/Savant_Systems (accessed 2026-10-27)
4. GE Lighting, a Savant company - home page - https://www.gelighting.com/ (accessed 2026-10-27)
5. Cync integration - Home Assistant - https://www.home-assistant.io/integrations/cync/ (accessed 2026-10-27)
6. cync_lights - GitHub (nikshriv) - https://github.com/nikshriv/cync_lights (accessed 2026-10-27)
7. NVD CVE API keyword search Cync - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Cync (accessed 2026-10-27)
