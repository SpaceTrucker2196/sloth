---
name: Ford Motor Company
aliases: []
affiliates: []
country: US [1][2]
parent: independent (public; Ford family holds ~2% equity and 40% voting power) [1]
founded: 1903 [1]
kind: automotive
device_classes: [automotive-infotainment, automotive-telematics]
found_in: ["Ford vehicles with SYNC infotainment (SYNC 2007, SYNC 3 announced December 2014, SYNC 4 announced October 2019, SYNC 5 2023) [3]", "Ford vehicles with the FordPass Connect 4G LTE mobile Wi-Fi hotspot (standard equipment on the 2020 Fusion alongside SYNC 3) [4]"]
radios: ["Wi-Fi (in-vehicle hotspot via FordPass Connect; generation and band not stated in sources used) [4]", "LTE (FordPass Connect 4G LTE) [4]"]
silicon: ["Broadcom BCM4325 / BCM4329 Wi-Fi chips in certain Ford products (per CVE-2012-2619) [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2012-2619: Broadcom BCM4325/BCM4329 Wi-Fi chips used in certain Ford (and Apple, Samsung, HTC, etc.) products allow remote denial of service; CVSS v2 7.8 [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Ford Motor Company, incorporated 16 June 1903 and headquartered in Dearborn, Michigan, is a public automaker controlled by the Ford family through a 40% voting stake [1]. It holds two IEEE MA-L blocks, 00:26:B4 and 00:76:B6, at its Dearborn address [2]. A MAC in these blocks is a vehicle: the SYNC infotainment head unit, which ran Windows Embedded Automotive from 2007, BlackBerry QNX from SYNC 3 (announced December 2014), gained over-the-air Power-Up updates with SYNC 4 (announced October 2019), and moved to Android Automotive OS with SYNC 5 in 2023 [3], or the FordPass Connect unit, a 4G LTE mobile Wi-Fi hotspot fitted as standard equipment from the 2020 Fusion onward [4]. On the air a Ford MAC can therefore appear as an access point (the hotspot) rather than a client. The only Ford-attributed NVD record is CVE-2012-2619, a remote denial of service in Broadcom BCM4325/BCM4329 Wi-Fi chips that NVD lists as used in certain Ford products [5]. Ford's FCC grantee code, the Wi-Fi generation of the hotspot, its carrier, the TCU supplier and any MAC-randomization behaviour were not confirmed from a fetchable primary source in this session (Ford support pages and the 2023 SYNC 3 Wi-Fi statement redirected or returned 404), so those fields are unknown.
## Sources
1. Ford Motor Company - Wikipedia - https://en.wikipedia.org/wiki/Ford_Motor_Company (accessed 2026-10-27)
2. IEEE MA-L (OUI) public listing - https://standards-oui.ieee.org/oui/oui.txt (accessed 2026-10-27)
3. Ford Sync - Wikipedia - https://en.wikipedia.org/wiki/Ford_Sync (accessed 2026-10-27)
4. FordPass (redirects to Ford Fusion (Americas)) - Wikipedia - https://en.wikipedia.org/wiki/FordPass (accessed 2026-10-27)
5. CVE-2012-2619 - NVD API keyword search "Ford Motor" - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Ford%20Motor&resultsPerPage=10 (accessed 2026-10-27)
