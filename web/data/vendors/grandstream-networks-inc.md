---
name: "Grandstream Networks, Inc."
aliases: [Grandstream Networks Inc]
country: US [1][2]
parent: independent, privately held [1][2]
founded: 2002 [1]
kind: network-equipment [2][3]
device_classes: [phone [3][4], ap/router [3][5], switch [3], camera [1]]
found_in: ["GXP, GRP and GHP desk IP phones, WP Wi-Fi and DECT cordless IP phones [3][4]", "HT analog telephone adaptors and UCM IP PBXs [3][7][8]", "GWN Wi-Fi access points, routers and switches [3][5]", "GDS door stations and GSC/GVC video and conferencing devices [3]"]
radios: ["Wi-Fi 6 in WP826, WP836 and WP856 cordless phones and GWN7062E router [3][4]", "Wi-Fi 7 in GWN7670 to GWN7674 access points [5]", "2.4 GHz [5]", "5 GHz [5]", "6 GHz in GWN7674 [5]", "BT Classic or BLE (version not stated) in WP-series phones [4]", "DECT cordless phones [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["GWN7000 before 1.0.6.32: authenticated command injection via the ubus API (CVE-2019-10656) [6]", "HT801 ATA before 1.0.29: buffer overflows in the limited configuration shell (CVE-2021-37748) [7]", "UCM series IP PBX before 1.0.20.52: parameter injection in the HTTP interface (CVE-2024-0840) [8]", "GXP2135 desk phone: OS command injection via CWMP (CVE-2024-32937) [9]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Grandstream Networks is a privately held maker of IP voice and video communications and surveillance equipment, founded in 2002 by David Li and headquartered in Boston, Massachusetts [1][2]. The IEEE registry lists three MA-L blocks to "Grandstream Networks, Inc." at a Brookline address and one to "Grandstream Networks Inc" at a Boston address [10]. Grandstream says its devices are used in over 150 countries and it has regional offices in the US, China, Venezuela, Morocco, Malaysia and Spain [2].

A MAC in a Grandstream block is most likely a VoIP device such as a desk or cordless IP phone, an analog telephone adaptor or an IP PBX, or a GWN access point, router or switch in a small or mid-size business [3]. Its WP cordless phones run dual-band Wi-Fi, Wi-Fi 6 on the WP826, WP836 and WP856, and most carry Bluetooth [4]. Its current GWN indoor access points include Wi-Fi 7 models, with the GWN7674 on 2.4, 5 and 6 GHz [5].

NVD records command injection in GWN7000 router firmware, buffer overflows in the HT801 ATA shell, parameter injection in UCM IP PBXs and command injection in a GXP desk phone [6][7][8][9]. Silicon and FCC grantee codes are not listed: the FCC ID databases refused requests from this session and no teardown was found, and nothing is filled in from memory. Randomization behaviour is not documented.

## Sources

1. Grandstream Networks - Wikipedia - https://en.wikipedia.org/wiki/Grandstream_Networks (accessed 2026-10-27)
2. About Grandstream - https://www.grandstream.com/about-us (accessed 2026-10-27)
3. Grandstream home page and product families - https://www.grandstream.com/ (accessed 2026-10-27)
4. Grandstream Wi-Fi cordless IP phones - https://www.grandstream.com/products/ip-voice-telephony/wifi-cordless (accessed 2026-10-27)
5. Grandstream GWN indoor Wi-Fi access points - https://www.grandstream.com/products/networking-solutions/indoor-wifi-access-points (accessed 2026-10-27)
6. NVD CVE-2019-10656 - https://nvd.nist.gov/vuln/detail/CVE-2019-10656 (accessed 2026-10-27)
7. NVD CVE-2021-37748 - https://nvd.nist.gov/vuln/detail/CVE-2021-37748 (accessed 2026-10-27)
8. NVD CVE-2024-0840 - https://nvd.nist.gov/vuln/detail/CVE-2024-0840 (accessed 2026-10-27)
9. NVD CVE-2024-32937 - https://nvd.nist.gov/vuln/detail/CVE-2024-32937 (accessed 2026-10-27)
10. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
