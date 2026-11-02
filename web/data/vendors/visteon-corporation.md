---
name: Visteon Corporation
aliases: []
affiliates: []
country: US [1][2]
parent: independent [1]
founded: 2000 [1]
kind: automotive
device_classes: [automotive-infotainment [3], automotive-telematics [2]]
found_in: ["Vehicles from BMW, Ford, Geely, General Motors, Honda, Jaguar/Land Rover, Mahindra, Mazda, Mercedes-Benz, Mitsubishi, Nissan, Renault, Stellantis, Tata, Toyota and Volkswagen (Visteon's listed customers; Ford 26%, GM 12% and Volkswagen 10% of 2025 net sales) [3]", "Android-based infotainment with Apple CarPlay / Android Auto integration, digital instrument clusters, cockpit domain controllers, displays and battery management systems [3]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2024-8355 through CVE-2024-8360: six Visteon Infotainment vulnerabilities published 2024-11-22 (DeviceManager iAP serial-number SQL injection, VIP MCU firmware-update authenticity LPE, App SoC missing immutable root of trust, UPDATES_ExtractFile and REFLASH_DDU command-injection RCE), requiring physical access or low-privilege code execution [4]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Visteon is a Nasdaq-listed (VC) automotive cockpit-electronics supplier headquartered in Van Buren Township, Michigan; Ford spun it off as an independent supplier in June 2000 [1][2]. It reports one segment, Electronics: digital instrument clusters, information displays, Android-based infotainment with Android Auto and Apple CarPlay integration, cockpit domain controllers, battery management systems and high-voltage power electronics, sold to BMW, Ford, Geely, GM, Honda, JLR, Mahindra, Mazda, Mercedes-Benz, Mitsubishi, Nissan, Renault, Stellantis, Tata, Toyota and Volkswagen, with Ford, GM and Volkswagen the largest [3]; its own site adds telematics to the portfolio [2]. A MAC in a Visteon block is therefore most likely a vehicle head unit or cluster. The radios, chipsets and FCC grantee codes could not be verified for this entry: the FCC ID database mirrors (fccid.io) answered HTTP 403 to every fetch, so radios, silicon and fcc_grantee are left empty rather than recalled. In the IEEE registry copy shipped with sloth, "Visteon Corporation" holds seven MA-L blocks (00:09:93, 00:0A:30, 0C:D9:C1, 7C:FC:3C, A8:40:0B, F8:55:CD, FC:35:E6) at Allen Park and Van Buren Township, Michigan, and "Visteon Portuguesa, Ltd" one (D0:B2:70); the Yanfeng Visteon joint-venture blocks (4C:53:69, F0:65:C2, MA-M 2C:48:35:B, MA-S 70:B3:D5:93:B) belong to the Chinese JV entities and are not covered here [5][6][7]. Security: in November 2024 NVD published six Visteon Infotainment CVEs (2024-8355..8360) covering SQL injection, command injection in the reflash/update path and missing root of trust, all requiring physical or local access [4].
## Sources
1. Wikipedia - Visteon - https://en.wikipedia.org/wiki/Visteon (accessed 2026-10-27)
2. Visteon - About Visteon (company snapshot) - https://www.visteon.com/company/about-visteon/default.aspx (accessed 2026-10-27)
3. Visteon Corporation Form 10-K for FY2025 - https://www.sec.gov/Archives/edgar/data/1111335/000111133526000006/vc-20251231.htm (accessed 2026-10-27)
4. NVD CVE API keyword search "Visteon" (CVE-2024-8355..8360) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Visteon (accessed 2026-10-27)
5. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
6. IEEE Registration Authority MA-M public listing (mam.csv; read from the copy shipped in sloth web/data/mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
7. IEEE Registration Authority MA-S public listing (oui36.csv; read from the copy shipped in sloth web/data/oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
