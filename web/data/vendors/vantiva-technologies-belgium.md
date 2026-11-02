---
name: Vantiva Technologies Belgium
aliases: []
country: BE [1][2]
parent: Vantiva SA, the former Thomson and Technicolor, which lists an office in Edegem (inferred from the shared name and address) [3]
founded: unknown
kind: network-equipment [3]
device_classes: [ap/router [3][4], tv [3][4]]
found_in: ["Vantiva broadband gateways, including the Falcon 5G indoor FWA gateway (inferred: Vantiva group products, not tied to this entity's blocks by a source) [3][4]", "Vantiva Android TV set-top boxes and the Pendula Android TV dongle (inferred, as above) [3][4]", "Vantiva MediaAccess DGA2232 gateway [5]"]
radios: ["Wi-Fi 7 in Vantiva fiber gateways [4]", "Wi-Fi 6 in the Falcon 5G FWA gateway [4]", "LTE/5G in the Falcon 5G FWA gateway [4]"]
silicon: ["Qualcomm 5G single-SoC CPE architecture in the Vantiva Falcon 5G FWA gateway [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2024-36397: cross-site scripting (CWE-79) in the web interface of the Vantiva MediaAccess DGA2232 v19.4, all versions listed affected (2024) [5]"]
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists twelve MA-L blocks to "Vantiva Technologies Belgium" at Prins Boudewijnlaan 47, Edegem, the same address the registry gives for the older "Thomson Telecom Belgium" blocks [1]. OpenCorporates records Vantiva Technologies Belgium as an active Belgian company registered at that Edegem address [2]. Vantiva SA is the Paris-headquartered company founded in 1893 that was Thomson until 2010 and Technicolor until 2022; its Connected Home business makes broadband gateways, modems, set-top boxes and Android TV devices, it lists Edegem, Belgium among its offices, and it took over CommScope's Home Networks division on 2 January 2024 [3].

A MAC in these blocks is most likely an operator-supplied home gateway or set-top box; that this Belgian entity's blocks go into Vantiva group products is inferred from the name and address, not stated by a source [1][3]. Vantiva demonstrated its own implementation of Wi-Fi 7 in its fiber gateways in 2023, and builds the Falcon 5G indoor FWA gateway, with its Wi-Fi 6 4+4 design, on Qualcomm's 5G single-SoC CPE architecture [4]. Its Pendula is an Android TV dongle with AV1 decoding [4]. Its MediaAccess DGA2232 gateway carries CVE-2024-36397, a cross-site scripting flaw published in June 2024 and fixed in v19.4-810 [5].

Founding year of the Belgian entity, FCC grantee codes and randomization are not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Vantiva Technologies Belgium - OpenCorporates - https://opencorporates.com/companies/be/0428837295 (accessed 2026-10-27)
3. Vantiva - Wikipedia - https://en.wikipedia.org/wiki/Vantiva (accessed 2026-10-27)
4. VANTIVA Demonstrates Innovative Ultra-Broadband and Wi-Fi 7 Solutions for the Connected Home at ANGA COM 2023 - Vantiva - https://www.vantiva.com/resources/vantiva-demonstrates-innovative-ultra-broadband-and-wi-fi-7-solutions-for-the-connected-home-at-anga-com-2023/ (accessed 2026-10-27)
5. CVE-2024-36397 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2024-36397 (accessed 2026-10-27)
