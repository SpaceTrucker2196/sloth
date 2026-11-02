---
name: "Beijing InHand Networking Technology Co.,Ltd."
aliases: []
country: CN [1]
parent: unknown
founded: 2001 [3]
kind: network-equipment
device_classes: [ap/router, industrial, automotive-telematics, switch, iot-sensor]
found_in: ["InHand InRouter IR302, IR315, IR602, IR624, IR925 industrial cellular routers [2]", "InHand ER615/ER815/ER2000 enterprise routers, FWA12/CPE02 indoor CPE, ODU12/ODU302/ODU2002 outdoor units [2]", "InHand IG502/IG902/EC312 edge gateways, EC9xx/EC3xxx/EC5xxx AI edge computers [2]", "InHand VG710/VG814 vehicle gateways, VT200/VT310/VT320 telematics units, VR624 vehicle router [2]", "InHand ISE/ISM industrial Ethernet switches, EAP600 access point, LoRaWAN gateways (EC312-LoRaWAN, LT312), MG301 metering gateways [2]"]
radios: ["Wi-Fi 5/6/7 across product lines [2]", "LTE/5G (4G LTE, 5G and 5G RedCap WAN uplinks) [2]", "LoRa (LoRaWAN gateways) [2]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CISA ICSA-23-012-03 / CVE-2023-22597..22601 (InRouter 302 before IR302 V3.5.56, InRouter 615 before InRouter6XX-S-V2.3.0.r5542): cleartext transmission (6.5), OS command injection (7.2), predictable hash salt (7.0), improper access control to MQTT topics allowing config/reboot/firmware-push commands (CVSS 10.0), insufficient randomness (5.3); reported by Roni Gavrilov of OTORIO [4][5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
InHand Networks is a Beijing industrial-IoT vendor founded in 2001, with offices in Singapore, Chantilly (US), Richmond Hill (Canada) and Dusseldorf; it claims 5.4 million products deployed in 60+ countries [3]. Its IEEE block 00:18:05 (MA-L, registered 21 April 2006) is held under the older corporate name "Beijing InHand Networking Technology Co.,Ltd." at Qiming International Mansion, Beijing [1][6], while the website now trades as inhand.com from Ziyue Road, Chaoyang District [2]. A MAC in this block is almost certainly infrastructure, not a personal device: cellular industrial routers (IR3xx/IR6xx/IR9xx), enterprise routers and fixed-wireless CPE, edge gateways and AI edge computers, vehicle gateways and telematics units, industrial Ethernet switches, an access point, and LoRaWAN gear [2]. Radios span Wi-Fi 5 through Wi-Fi 7 plus 4G LTE, 5G and 5G RedCap WAN uplinks [2], so on the air expect an AP or a wired-side router MAC; the cellular side is invisible to sloth. No chipset is documented on a page reachable in this session and the FCC ID databases returned HTTP 403, so silicon and grantee code are left unknown rather than inferred; no parent-company filing was consulted, so parent is unknown too. Security-wise, CISA advisory ICSA-23-012-03 covers five CVEs in InRouter 302/615, headlined by CVE-2023-22600 (CVSS 10.0), an improper-access-control flaw letting an unauthenticated device on the same network subscribe to the router's MQTT topics and send configuration, reboot and firmware-update commands [4][5]; an InHand router seen on a monitored LAN deserves a firmware-version check.
## Sources
1. MAC prefix 00:18:05 - maclookup.app - https://maclookup.app/macaddress/001805 (accessed 2026-10-27)
2. InHand Networks home page (product families, radios, offices) - https://www.inhand.com/ (accessed 2026-10-27)
3. Who We Are - InHand Networks - https://www.inhand.com/en/company/who-we-are (accessed 2026-10-27)
4. ICS Advisory ICSA-23-012-03, InHand Networks InRouter - CISA - https://www.cisa.gov/news-events/ics-advisories/icsa-23-012-03 (accessed 2026-10-27)
5. CVE-2023-22600 record - MITRE CVE Services API - https://cveawg.mitre.org/api/cve/CVE-2023-22600 (accessed 2026-10-27)
6. Beijing InHand Networking Technology Co., Ltd. MAC address blocks - maclookup.app - https://maclookup.app/vendors/beijing-inhand-networking-technology-co-ltd (accessed 2026-10-27)
