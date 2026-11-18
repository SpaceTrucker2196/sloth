---
name: Mitsubishi Electric Corporation
aliases: []
affiliates: []
country: JP [1][2]
parent: member of the Mitsubishi Group [1]
founded: 1921 [1]
kind: other
device_classes: [smart-home [3], industrial [1][4]]
found_in: ["Mitsubishi Electric Wi-Fi interfaces, HEMS adapters, air conditioners and other connected home appliances [3]", "Mitsubishi Electric factory-automation products such as GX Works3, the CNC series and CC-Link IE TSN equipment [4]"]
radios: ["Wi-Fi (Wi-Fi interfaces for air conditioners and home appliances) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2022-33321: HTTP Basic authentication in cleartext lets a sniffer take credentials on many consumer devices, including Wi-Fi interfaces and air conditioners (CVSS 9.8) [3]", "Identified in early 2020 as the victim of year-long cyberattacks by Chinese hackers [1]", "Factory-automation advisories, among them a GX Works3 password authentication bypass and a CC-Link IE TSN information tampering and DoS issue (2026) [4]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Mitsubishi Electric Corporation is a Japanese electrical and
electronics maker founded in 1921 as a spin-off of Mitsubishi
Shipbuilding's electrical machinery division and headquartered at
2-7-3 Marunouchi, Chiyoda, Tokyo; it is a member of the Mitsubishi
Group [1]. Its products include air conditioners, factory automation
(programmable controllers, servo systems, inverters, industrial
robots), car multimedia, elevators and escalators, and satellites [1].
The IEEE registry lists seven MA-L blocks to "Mitsubishi Electric
Corporation" at the Marunouchi head office [2]; its regional and
service subsidiaries register under their own names and are not
covered here [2].

The sources do not map these blocks to a product line, so found_in is
marked inferred [1][2]. On a home network the most likely radio is
Wi-Fi: CVE-2022-33321 names Mitsubishi Electric Wi-Fi interfaces, HEMS
adapters, air conditioners, refrigerators and other appliances that
sent HTTP Basic credentials in cleartext [3]. On an industrial network
expect factory-automation gear, the subject of Mitsubishi Electric
PSIRT advisories [4]. The company itself was identified in early 2020 as the victim of
year-long cyberattacks by Chinese hackers [1]. The FCC ID databases refused the session that
wrote this entry, so no grantee code or silicon is listed.

## Sources
1. Mitsubishi Electric - Wikipedia - https://en.wikipedia.org/wiki/Mitsubishi_Electric (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. NVD CVE API, keyword search Mitsubishi Electric Wi-Fi Interface (CVE-2022-33321) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Mitsubishi%20Electric%20Wi-Fi%20Interface (accessed 2026-10-27)
4. Mitsubishi Electric PSIRT vulnerability feed - https://www.mitsubishielectric.com/psirt/vulnerability/xml/info.xml (accessed 2026-10-27)
