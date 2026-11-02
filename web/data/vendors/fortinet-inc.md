---
name: "Fortinet, Inc."
aliases: []
country: US [1][2]
parent: independent, public on Nasdaq as FTNT [2]
founded: 2000 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][3], switch [2]]
found_in: ["FortiGate firewalls and FortiWiFi firewalls with built-in Wi-Fi [2][3]", "FortiAP access points such as the FortiAP-221C [3]", "FortiSwitch switches [2]"]
radios: ["Wi-Fi 4/5 [3]"]
silicon: ["Qualcomm Atheros QCA9557 with a QCA9882 module in FortiAP-221C [3]", "Atheros AR9344 with AR9382 in FortiAP-221B [3]", "Marvell 88F6820 with an Atheros AR9382 module (EMP7618) in FortiWiFi-30E, 50E and 51E [3]", "Marvell 88F6820 with QCA9892 modules in FortiWiFi 50E-2R [3]"]
fcc_grantee: ["TVE, the prefix of the FortiAP-14C, 210B, 221C and FortiWiFi FCC IDs [3]"]
randomization: unknown
security_notes: ["CVE-2018-13379: FortiOS SSL VPN path traversal lets an unauthenticated attacker download system files [4]", "September 2021: almost 500,000 Fortinet VPN logins published, allegedly from CVE-2018-13379 devices; January 2025: configs and credentials of over 15,000 FortiGates leaked, reportedly via CVE-2022-40684 [2]", "2023: Microsoft and Five Eyes members reported a China-linked state-sponsored campaign targeting Fortinet devices [2]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Fortinet was founded in 2000 by the brothers Ken and Michael Xie, is headquartered in Sunnyvale, California, and trades on Nasdaq as FTNT; its first product, the FortiGate firewall, shipped in 2002, and in 2015 it bought the Wi-Fi hardware company Meru Networks [2]. The IEEE registry lists 26 MA-L blocks to "Fortinet, Inc." at 899 Kifer Road, Sunnyvale [1].

A MAC in a Fortinet block is most likely a FortiGate or FortiWiFi firewall, a FortiSwitch, or a FortiAP access point [2][3]. WikiDevi documents FortiAP silicon from the Atheros AR7240 with AR9285 in the FortiAP-112B to the Qualcomm Atheros QCA9557 with a QCA9882 802.11ac module in the FortiAP-221C, and FortiWiFi firewalls built on a Marvell 88F6820 with Atheros AR9382 or Qualcomm QCA9892 radio modules [3]. Most of those FCC IDs start with TVE, and the page lists 802.11 modes (b/g/n, a/n, ac) rather than bands in GHz, so no band is listed; the FortiAP-112B (A8J-ENS200) and FortiAP-221B (U2M-CAP4100AG) carry other prefixes, and the sources do not say whose [3].

CVE-2018-13379 is a FortiOS SSL VPN path traversal that lets an unauthenticated attacker download system files [4]. Wikipedia records almost 500,000 Fortinet VPN logins published in September 2021, allegedly taken from devices affected by that CVE, credentials and configuration files of over 15,000 FortiGates leaked in January 2025, reportedly via CVE-2022-40684, and a China-linked state-sponsored campaign against Fortinet devices reported in 2023 [2]. Randomization is unknown; the FCC ID databases refused the session that wrote this entry.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Fortinet - Wikipedia - https://en.wikipedia.org/wiki/Fortinet (accessed 2026-10-27)
3. Fortinet - WikiDevi - https://wikidevi.wi-cat.ru/Fortinet (accessed 2026-10-27)
4. CVE-2018-13379 record - CVE.org - https://cveawg.mitre.org/api/cve/CVE-2018-13379 (accessed 2026-10-27)
