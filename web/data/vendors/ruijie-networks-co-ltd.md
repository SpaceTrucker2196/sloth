---
name: "Ruijie Networks Co.,LTD"
aliases: []
country: CN [1]
parent: unknown
founded: 2000 [2]
kind: network-equipment [2][3]
device_classes: [ap/router [2][4], switch [2]]
found_in: ["Ruijie enterprise access points, switches and routers [2]", "Reyee small-business and home Wi-Fi routers and access points such as RG-E5, RG-E6, RG-EW1200G PRO and RG-RAP72PRO [4]"]
radios: ["Wi-Fi 5 [4]", "Wi-Fi 6 [2][4]", "Wi-Fi 7 [2]", "2.4 GHz [4]", "5 GHz [4]"]
silicon: ["MediaTek MT7986AV in RG-X60 PRO [4]", "MediaTek MT7621 with MT7615 radio in Reyee RG-EW1200G PRO v1.1 [4]", "MediaTek MT7622BV with MT7915AN radio in Reyee RG-EW3200GX PRO [4]", "MediaTek MT7988DV with MT7992AV, MT7975N and MT7977BN in Scorpio BE72 Pro [4]"]
fcc_grantee: ["2AX5J [4]"]
randomization: unknown
security_notes: ["Ten Reyee cloud and Reyee OS vulnerabilities (CVE-2024-42494, CVE-2024-45722, CVE-2024-46874, CVE-2024-47043, CVE-2024-47146, CVE-2024-47547, CVE-2024-47791, CVE-2024-48874, CVE-2024-51727, CVE-2024-52324) allowed code execution on about 50,000 cloud-connected devices; access points broadcast their serial number in Wi-Fi beacons, enabling a proximity attack; fixed in the cloud, Reyee OS before 2.260.0.1329 affected (Claroty Team82, December 2024) [3]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Ruijie Networks is a networking-equipment maker formally established in 2000, selling data-center, campus, industrial and cloud-managed switches, indoor, outdoor and wall-plate access points and controllers, routers, and the Reyee line, with Wi-Fi 6 and Wi-Fi 7 enterprise solutions [2]. Claroty describes it as serving enterprises, education, government and service providers in more than 90 countries with over 8,000 employees [3]. The IEEE registry lists 32 MA-L blocks to "Ruijie Networks Co.,LTD", all at addresses in Fuzhou, Fujian, China [1].

A MAC in a Ruijie block is most likely an enterprise or Reyee access point, router or switch [2][4]. TechInfoDepot lists Reyee and Ruijie routers under FCC grantee code 2AX5J, among them the RG-E5, RG-E6 and RG-RAP72PRO, and documents MediaTek silicon: an MT7986AV in the RG-X60 PRO, an MT7621 with an MT7615 radio in the RG-EW1200G PRO v1.1, an MT7622BV with an MT7915AN in the RG-EW3200GX PRO, and an MT7988DV with MT7992AV, MT7975N and MT7977BN in the Scorpio BE72 Pro [4].

In December 2024 Claroty's Team82 disclosed ten vulnerabilities in the Reyee cloud platform and Reyee OS devices before 2.260.0.1329 that could have let an attacker run code on about 50,000 cloud-connected devices; because the access points broadcast their serial number in Wi-Fi beacons, an attacker near one could take a shell on it without the Wi-Fi password, and Ruijie fixed the issues in its cloud [3]. No source consulted documents whether these devices randomise their addresses, so randomization is unknown. Wikipedia had no article at the expected title and the FCC ID databases refused automated access from this session, so parent company is unknown and the grantee code rests on TechInfoDepot.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About Ruijie Networks - Ruijie Networks - https://www.ruijie.com/en-global/about/news/8199 (accessed 2026-10-27)
3. The Insecure IoT Cloud Strikes Again: RCE on Ruijie Cloud-Connected Devices - Claroty Team82 - https://claroty.com/team82/research/the-insecure-iot-cloud-strikes-again-rce-on-ruijie-cloud-connected-devices (accessed 2026-10-27)
4. Ruijie - TechInfoDepot - https://techinfodepot.shoutwiki.com/wiki/Ruijie (accessed 2026-10-27)
