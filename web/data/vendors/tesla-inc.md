---
name: "Tesla,Inc."
aliases: ["Tesla Inc"]
country: US [1][2]
parent: independent [1]
founded: 2003 [1]
kind: automotive [1]
device_classes: [automotive-infotainment [4]]
found_in: ["Tesla Model 3 and Model Y, whose phone-as-a-key authenticates over Bluetooth Low Energy [5]", "Tesla Model S touchscreen computer [4]"]
radios: ["BLE 4.x/5.x [5]"]
silicon: ["NVIDIA Tegra 3, then an Intel Atom SoC (about 2018), then an AMD Ryzen SoC (2021 refresh) in the Model S touchscreen computer [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["BLE phone-as-a-key passive entry vulnerable to relay attacks; Tesla called relay attacks a known limitation (NCC Group, 2022) [5][6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Tesla is the US electric-vehicle and energy company incorporated in
2003 by Martin Eberhard and Marc Tarpenning, public on NASDAQ since
2010 and headquartered at Gigafactory Texas in Austin; it sells the
Model 3, Model Y, Semi and Cybertruck, the Powerwall and Powerpack
batteries and solar products [1]. The IEEE registry lists five MA-L
blocks and one MA-M block to "Tesla,Inc." at the Palo Alto address and
one MA-L block to "Tesla Inc" at the Austin address [2][3]. A MAC in a
Tesla block is most likely a vehicle: the car's touchscreen computer
has run an NVIDIA Tegra 3, then from about 2018 an Intel Atom SoC and
from the 2021 refresh an AMD Ryzen SoC, and the car pairs phones over
Bluetooth and takes over-the-air software updates [4].

On the air expect Bluetooth Low Energy, since the Model 3 and Model Y
phone-as-a-key authenticates over BLE [5]; the car's Wi-Fi and
cellular radios are not documented by the sources consulted (Tesla's
own support pages and the FCC ID databases were not reachable from the
session that wrote this entry), so they are not listed rather than
assumed. NCC Group showed in 2022 that the BLE passive entry can be
relayed with as little as 8 ms of added round-trip latency, and Tesla
answered that relay attacks are a known limitation [5]; Wikipedia
records the same May 2022 relay attack on the Model 3 and Model Y [6].
Randomization is unknown, and FCC grantee codes are not listed for the
reason above.

## Sources

1. Tesla, Inc. - Wikipedia - https://en.wikipedia.org/wiki/Tesla,_Inc. (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
4. Tesla Model S - Wikipedia - https://en.wikipedia.org/wiki/Tesla_Model_S (accessed 2026-10-27)
5. Technical Advisory - Tesla BLE Phone-as-a-Key Passive Entry Vulnerable to Relay Attacks - NCC Group - https://www.nccgroup.com/us/research-blog/technical-advisory-tesla-ble-phone-as-a-key-passive-entry-vulnerable-to-relay-attacks/ (accessed 2026-10-27)
6. Tesla Model 3 - Wikipedia - https://en.wikipedia.org/wiki/Tesla_Model_3 (accessed 2026-10-27)
