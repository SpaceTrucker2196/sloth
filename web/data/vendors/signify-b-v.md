---
name: Signify B.V.
aliases: []
country: NL [1]
parent: unknown
founded: unknown
kind: brand [2]
device_classes: [smart-home [3]]
found_in: ["Philips Hue Bridge and Hue bulbs [3]", "Philips Hue Bridge model 2.x [4]"]
radios: ["Thread/Zigbee (802.15.4) [3]", "BT Classic or BLE, version not stated (bulbs since 2019) [3]", "Wi-Fi, band not stated (Hue Bridge Pro) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-6007: heap buffer overflow in Hue Bridge 2.x firmware up to 1935144020 when handling a long ZCL string during Zigbee commissioning, leading to remote code execution [4]", "2016 research showed Hue bulbs could be taken over from up to 70 m with a malicious firmware update, since resolved [3]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Signify is the Eindhoven lighting company formerly called Philips Lighting N.V., separated from Royal Philips in 2016 and renamed Signify in 2018; it sells under the licensed Philips brand and as Philips Hue, Color Kinetics, WiZ and others [2]. The IEEE registry lists two MA-L blocks to Signify B.V. at High Tech Campus 7, Eindhoven [1]; the fetched sources do not state how this B.V. sits under Signify N.V., so parent and founding year are unknown.

A MAC in a Signify block is most likely Philips Hue equipment, which Signify makes [3]. The Hue Bridge connects over wired Ethernet and relays commands to bulbs over a Zigbee mesh, the 2025 Hue Bridge Pro adds built-in Wi-Fi and Matter, and since 2019 bulbs also speak Bluetooth [3]; which Signify products carry these particular blocks is not documented, so found_in and radios are inferred. NVD records CVE-2020-6007, a heap overflow in Hue Bridge 2.x firmware reachable over Zigbee commissioning that gives remote code execution [4], and Wikipedia records a resolved 2016 flaw that let bulbs be reflashed from up to 70 m [3]. Silicon, FCC grantee codes and randomization are not listed: the FCC ID databases refused access from the session that wrote this entry, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Signify N.V. - Wikipedia - https://en.wikipedia.org/wiki/Signify_N.V. (accessed 2026-10-27)
3. Philips Hue - Wikipedia - https://en.wikipedia.org/wiki/Philips_Hue (accessed 2026-10-27)
4. NVD, CVE-2020-6007 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-6007 (accessed 2026-10-27)
