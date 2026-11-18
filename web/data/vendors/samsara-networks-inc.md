---
name: SAMSARA NETWORKS INC
aliases: []
affiliates: []
country: US [1]
parent: independent (NYSE-listed since December 2021) [1]
founded: 2015 [1]
kind: brand
device_classes: [automotive-telematics, camera, iot-sensor, wearable]
found_in: ["Samsara Vehicle Gateway (VG55, VG55-FN) cellular telematics with GPS and CAN bus [4][5]", "Samsara AI Dash Cams CM33 (front-facing) and CM34 (dual-facing), AI Multicam [4]", "Samsara Asset Gateways (powered, unpowered, trailer) [4]", "Samsara Wearable (SOS alerts, fall detection) [4]", "Samsara Site Gateway / Site Gateway Lite cloud NVRs [4]"]
radios: ["LTE (4G LTE bands 2, 4, 5, 12, 13 in North America; FirstNet bands 2, 4, 5, 12, 14 on the VG55-FN; no 5G is specified) [5]", "Wi-Fi 4 (integrated 802.11g/n hotspot) [5]", "2.4 GHz [5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Device-side controls documented by the vendor: command allowlist to the vehicle, asymmetric-signature verification, no default passwords or debug interfaces, TLS 1.2 / AES-256 in transit, SOC 2 Type 2 report, Bugcrowd bug bounty [6]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Samsara is a US fleet-telematics and industrial-IoT company founded in 2015 in San Francisco by the Meraki founders, listed on the NYSE as IOT since December 2021, with about 3,500 staff and customers including DHL, Sysco and several US cities and states [1]. The IEEE registrant "SAMSARA NETWORKS INC" holds three blocks: MA-M C0:D3:91:E (2016), MA-L FC:DB:21 (2019, registered at 1 De Haro St, San Francisco) and MA-L 28:EA:5B (2025) [2][3]. A MAC in these blocks is a Samsara endpoint, most likely a Vehicle Gateway plugged into a truck or van, or one of its AI dash cams, asset gateways, wearables or site gateways [4]. The Vehicle Gateway is a cellular device with GPS/GLONASS positioning and a CAN-bus interface, using 4G LTE bands 2, 4, 5, 12 and 13 in North America and FirstNet bands 2, 4, 5, 12 and 14 on the VG55-FN [4][5]; it also runs an integrated 2.4 GHz 802.11g/n Wi-Fi hotspot for in-cab tablets and phones [5], which is the radio a passive monitor near a vehicle will most often hear, acting as an access point rather than a client. Neither 5G nor Bluetooth is mentioned in the gateway specification reached [5]. Samsara publishes device-security controls rather than advisories: a command allowlist for vehicle commands, asymmetric digital signatures, no default passwords and disabled debug interfaces, TLS 1.2 and AES-256 for data in transit, a SOC 2 Type 2 report and a Bugcrowd bounty programme [6]. Chipset and FCC grantee were not found: the Samsara knowledge base returned 403 and the FCC ID mirrors were blocked, so those fields are left empty rather than guessed. No public MAC-randomization documentation exists for these fixed-function devices, so that field is unknown.
## Sources
1. Wikipedia - Samsara (company) - https://en.wikipedia.org/wiki/Samsara_(company) (accessed 2026-10-27)
2. maclookup.app - Samsara Networks Inc vendor page - https://maclookup.app/vendors/samsara-networks-inc (accessed 2026-10-27)
3. maclookup.app - OUI FC:DB:21 registration - https://maclookup.app/macaddress/FCDB21 (accessed 2026-10-27)
4. Samsara - Hardware models - https://www.samsara.com/products/models (accessed 2026-10-27)
5. Samsara - Vehicle Gateway - https://www.samsara.com/products/models/vehicle-gateway (accessed 2026-10-27)
6. Samsara - Security - https://www.samsara.com/security (accessed 2026-10-27)
