---
name: Alarm.com
aliases: []
country: US [1][2]
parent: independent, listed on Nasdaq as ALRM [2]
founded: 2000 [2]
kind: brand [2]
device_classes: [smart-home [2], camera [3][4]]
found_in: ["Alarm.com ADC-V522IR camera [4][5]", "Alarm.com ADC-SG130 Smart Gateway, a Wi-Fi access point for Alarm.com cameras [3]"]
radios: ["Wi-Fi 4 (802.11b/g/n) [3]", "2.4 GHz [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2018-19588: incorrect access control in Alarm.com ADC-V522IR firmware 0100b9 [5]", "CVE-2019-9657: incorrect access control in Alarm.com ADC-V522IR firmware 0100b9, weak protection of the VPN certificates the camera uses to reach Alarm.com infrastructure [4]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Alarm.com was founded in 2000 as a spinoff from MicroStrategy by Jean-Paul Martin and Alison J. Slavin, is headquartered in Tysons, Virginia, and has traded on Nasdaq as ALRM since its June 2015 IPO [2]. It runs a cloud platform for interactive security, video monitoring, energy management and home automation, sold through service providers, and has bought OpenEye (cloud video, 2019), Shooter Detection Systems (2020), Noonlight (2022) and EBS, a Polish maker of alarm communicators (2023) [2]. The IEEE registry lists three MA-L blocks to Alarm.com, one at a Vienna, Virginia address and two in Tysons [1].

A MAC in an Alarm.com block is most likely an Alarm.com-branded camera, gateway or other device installed by a security dealer [2][3]. The ADC-SG130 Smart Gateway is a 2.4 GHz 802.11b/g/n access point that hangs off the customer's router by Ethernet and to which Alarm.com Wi-Fi cameras pair, so expect a small private 2.4 GHz network in such homes [3].

The ADC-V522IR camera on firmware 0100b9 has two incorrect-access-control CVEs, CVE-2018-19588 and CVE-2019-9657, the second tied to weak protection of the VPN certificates the camera uses to reach Alarm.com's infrastructure [4][5]. The FCC ID databases refused this session's requests, so no grantee code is listed; no teardown naming silicon was found, and no source documents MAC randomization.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Alarm.com - Wikipedia - https://en.wikipedia.org/wiki/Alarm.com (accessed 2026-10-27)
3. Alarm.com ADC-SG130 - Alarm Grid - https://www.alarmgrid.com/products/alarm-com-adc-sg130 (accessed 2026-10-27)
4. CVE-2019-9657 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-9657 (accessed 2026-10-27)
5. CVE-2018-19588 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2018-19588 (accessed 2026-10-27)
