---
name: Cisco Meraki
aliases: []
country: US [1][2]
parent: Cisco Systems (acquired December 2012) [1]
founded: 2006 [1]
kind: network-equipment [1]
device_classes: [ap/router [3][4], switch [1], camera [1]]
found_in: ["Meraki MR cloud-managed access points (MR12 to MR55 and later) [3][4]", "Meraki MX security appliances and Z1/Z3 teleworker gateways [1][3][5]", "Meraki MS switches [1]", "Meraki Systems Manager agent on managed endpoints [6]"]
radios: ["Wi-Fi 4/5/6 [3][4]", "2.4 GHz [4]", "5 GHz [4]", "BLE (version not stated), MR46 beacon and scanning radio [4]"]
silicon: ["Qualcomm IPQ8074 with QCN5054 and QCN5024 in MR45 and MR55 [3]", "Broadcom BCM53016 with two BCM43520 in MR32 [3]", "Qualcomm Atheros QCA9557 with AR9582 in MR18 [3]", "Freescale P1020 with BCM43460 and BCM43431 in MR34 [3]", "AppliedMicro APM82181 with AR9390 and AR9380 in MR24 [3]"]
fcc_grantee: ["UDX (inferred from the FCC ID prefix of every listed Meraki device) [3]"]
randomization: unknown
security_notes: ["CVE-2018-0284: authenticated configuration-file modification through the local status page of MR, MS, MX, Z1 and Z3 [5]", "CVE-2024-20509: AnyConnect VPN server on MX and Z-series, session hijack or DoS [7]", "CVE-2024-20430: local privilege escalation in the Systems Manager agent for Windows [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Cisco Meraki is the cloud-managed networking company founded in 2006 by Sanjit Biswas, John Bicket and Hans Robertson, partly on MIT's Roofnet mesh project, and bought by Cisco in a deal announced on 18 November 2012 for about 1.2 billion dollars; it is headquartered in San Francisco [1]. The IEEE registry lists 57 MA-L blocks to "Cisco Meraki", nearly all at 500 Terry A. Francois Blvd, San Francisco [2]. A MAC in a Meraki block is most likely an enterprise access point, but can also be an MX security appliance, an MS switch, a security camera or a Z-series teleworker gateway, all managed from the web [1][3].

DeviWiki lists Meraki devices with FCC IDs all beginning UDX and documents their silicon, for example Qualcomm IPQ8074 with QCN5054 and QCN5024 radios in the Wi-Fi 6 MR45 and MR55, and Broadcom BCM53016 with BCM43520 radios in the MR32 [3]. A recent AP such as the MR46 runs four radios at once: 802.11ax client radios on 2.4 and 5 GHz, a dual-band WIDS/WIPS and location scanning radio, and a Bluetooth Low Energy beacon and scanning radio, so one AP may show several BSSIDs plus BLE adverts [4]. NVD records a local-status-page configuration flaw across MR, MS, MX, Z1 and Z3 (CVE-2018-0284) [5], an AnyConnect VPN server flaw on MX and Z-series allowing session hijack or denial of service (CVE-2024-20509) [7], and a Systems Manager agent privilege escalation (CVE-2024-20430) [6]. Randomization is unknown.

## Sources

1. Cisco Meraki - Wikipedia - https://en.wikipedia.org/wiki/Cisco_Meraki (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Meraki - DeviWiki - https://deviwiki.com/wiki/Meraki (accessed 2026-10-27)
4. MR46 Datasheet - Cisco Meraki Documentation - https://documentation.meraki.com/MR/MR_Overview_and_Specifications/MR46_Datasheet (accessed 2026-10-27)
5. NVD - CVE-2018-0284 - https://nvd.nist.gov/vuln/detail/CVE-2018-0284 (accessed 2026-10-27)
6. NVD - CVE-2024-20430 - https://nvd.nist.gov/vuln/detail/CVE-2024-20430 (accessed 2026-10-27)
7. NVD - CVE-2024-20509 - https://nvd.nist.gov/vuln/detail/CVE-2024-20509 (accessed 2026-10-27)
