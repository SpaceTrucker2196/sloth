---
name: Smart Innovation LLC
aliases: []
country: CN [3][11]
parent: Anker Innovations (inferred from consistent eufy device attributions; no corporate filing found) [4][5][6][8][9]
founded: unknown
kind: brand
device_classes: [camera, smart-home]
found_in: ["eufy video doorbell on 8C:85:80 (home DHCP inventory) [4]", "eufy HomeBase hub on 04:17:B6 (university IoT lab inventory) [5]", "eufy HomeBase 2 on 10:2C:B1 (HomeKit home inventory) [6]", "8C:85:80 mapped to 'Eufy (Anker)' in a camera-OUI finder [8]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Late 2022: eufy cameras marketed as local-only were found uploading thumbnails/video to eufy's AWS-hosted servers; eufy rewrote its privacy-commitment page in Dec 2022 [9]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
"Smart Innovation LLC" is an opaque IEEE registrant: five MA-L blocks registered between 29 March 2017 and 5 September 2025 (8C:85:80, 04:17:B6, 10:2C:B1, 90:BF:D9, 2C:8D:48), four of them at 7F Tower B, Jianxing, Shenzhen, China, despite the US-style "LLC" suffix, and 10:2C:B1 at a Bellevue, Washington address [1][2][3][11]; a community device-type database groups 04:17:B6 and 8C:85:80 under this registrant [10]. Every independent sighting reached attributes these blocks to eufy security products: a home DHCP inventory labels an 8C:85:80 host "Eufy doorbell", a university IoT lab lists 04:17:b6 as "eufy-hub", a HomeKit household lists 10:2c:b1 as "eufy HomeBase 2", and a camera-OUI finder maps 8C:85:80 to "Eufy (Anker)" [4][5][6][8]. eufy is the smart-home brand of Anker Innovations, founded in Shenzhen in 2011 by Steven Yang and now headquartered in Changsha, selling cameras, video doorbells and HomeBase hubs [9]; the corporate link between "Smart Innovation LLC" and Anker is inferred from these attributions, not from a filing. A MAC in these blocks is therefore most likely a eufy camera, doorbell or HomeBase. Relevant to operators: in late 2022 eufy cameras sold as local-storage devices were shown to upload images to eufy's AWS servers, after which the privacy page was rewritten [9]. No public documentation found for the radios, chipsets, FCC grantee codes or MAC randomization behaviour behind these blocks (eufy's support article on Wi-Fi bands and the FCC databases were unreachable).
## Sources
1. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
2. maclookup.app vendor page, Smart Innovation LLC (five blocks, registration dates) - https://maclookup.app/vendors/smart-innovation-llc (accessed 2026-10-27)
3. maclookup.app 8C:85:80 registrant record (Shenzhen address) - https://maclookup.app/macaddress/8C8580 (accessed 2026-10-27)
4. cjnaz/routermonitor README, example inventory ("Smart Innovation LLC  Eufy doorbell") - https://github.com/cjnaz/routermonitor/blob/6cd2ae5e72abdba698c8e9afb81c94c56d1ca8b6/README.md (accessed 2026-10-27)
5. NEU-SNS iot-ipv6 lab device list (04:17:b6 eufy-hub) - https://github.com/NEU-SNS/iot-ipv6/blob/main/dest-analysis/devices-ipv6-mac.txt (accessed 2026-10-27)
6. kistanovdev/homekit-monitoring inventory (10:2c:b1 eufy HomeBase 2) - https://github.com/kistanovdev/homekit-monitoring/blob/main/inventory.md (accessed 2026-10-27)
7. ricardoalcaraz/DotFiles ansible README host table (not reachable 2026-10-27: HTTP 404) - https://github.com/ricardoalcaraz/DotFiles/blob/main/ansible/README.md (accessed 2026-10-27)
8. Raspyjack cam_finder.py camera OUI table (8C:85:80 Eufy) - https://github.com/7h30th3r0n3/Raspyjack/blob/main/payloads/reconnaissance/cam_finder.py (accessed 2026-10-27)
9. Anker Innovations - Wikipedia - https://en.wikipedia.org/wiki/Anker_Innovations (accessed 2026-10-27)
10. ManySecured D3DB device-type assertion for Smart Innovation LLC - https://github.com/TechWorksHub/ManySecured-D3DB/blob/main/manufacturers/S/SmartInn/device.type.d3.yaml (accessed 2026-10-27)
11. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv: four blocks at 7F Tower B Jianxing Shenzhen, 10:2C:B1 at 400 108th Ave NE, Bellevue WA) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
