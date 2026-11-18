---
name: Orbit Irrigation
aliases: []
affiliates: []
country: US [1][4]
parent: "Husqvarna Group, Gardena Division (acquired 2021) [1]"
founded: 1971 [1]
kind: brand
device_classes: [smart-home, iot-sensor]
found_in: ["B-hyve Smart 6-Zone indoor/outdoor sprinkler controller (57946), listed as Wi-Fi and Bluetooth [3]", "B-hyve 12-Station (57950), 4-Station indoor (57915), 8-Zone indoor (57925) and XR 8-/16-Station (57985, 57995) sprinkler controllers, listed as Wi-Fi [3]", "B-hyve Wi-Fi Hub Gen 1 (21006) and Gen 2 (21027); the hose-faucet timers (21205, XD 24511/24632/24634) are Bluetooth, sold alone or bundled with the Gen 2 Hub [3]", "B-hyve leak detectors [2]"]
radios: ["2.4 GHz Wi-Fi, generation not documented [2]", "Bluetooth (version and Classic/BLE not documented) on the 57946 controller and the hose-faucet timers [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Orbit is a Utah lawn-and-garden irrigation maker: founded in 1971 as Pro-Mark, Inc. in North Salt Lake, trading as Orbit since 1981, and part of Husqvarna Group's Gardena Division since 2021 [1]. It holds a single MA-L block, 44:67:55, registered in November 2015 to a P.O. box in Bountiful, Utah [4][5]. A MAC in that block is a B-hyve smart-watering device [2]; Orbit's B-hyve line splits into Wi-Fi sprinkler controllers (57946 also lists Bluetooth; 57950, 57915, 57925 and the XR 57985/57995 list Wi-Fi), Bluetooth hose-faucet timers (21205, XD 24511/24632/24634), and the Wi-Fi Hub (21006, 21027) that the hose timers are bundled with [3], so the Wi-Fi station an operator sees is a controller or a hub, not a hose timer itself. B-hyve advertises "a 2.4 GHz Wi-Fi chip" with installation up to 200 feet from the Wi-Fi source and claims more than a million households on the platform [2]; the 802.11 generation, Bluetooth version and the chipset are not stated by Orbit and no teardown or FCC exhibit was reachable for this entry (fccid.io and fcc.report refused the fetch), so silicon and the FCC grantee code are left unknown rather than guessed. These are fixed-function outdoor appliances whose WeatherSense feature adjusts watering to the weather [2]; nothing in the sources addresses MAC randomization, and no vendor security advisory was found.
## Sources
1. About Us - Orbit - https://www.orbitonline.com/pages/about-us (accessed 2026-10-27)
2. B-hyve Smart Watering - Orbit - https://bhyve.orbitonline.com/ (accessed 2026-10-27)
3. B-hyve collection (models and radio type) - Orbit - https://www.orbitonline.com/collections/b-hyve (accessed 2026-10-27)
4. MAC block 44:67:55 - maclookup.app API - https://api.maclookup.app/v2/macs/44:67:55 (accessed 2026-10-27)
5. IEEE Registration Authority MA-L registry, the copy committed in sloth as web/data/oui.csv (Debian ieee-data 20260625) - https://github.com/SpaceTrucker2196/sloth/blob/main/web/data/oui.csv (accessed 2026-11-02)
