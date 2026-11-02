---
name: "Hangzhou Ezviz Software Co.,Ltd."
aliases: []
country: CN [1]
parent: Hikvision, which lists Ezviz among its brands [2]
founded: unknown
kind: brand [3]
device_classes: [camera [3][4], smart-home [3]]
found_in: ["EZVIZ Wi-Fi cameras such as the CS-C6N, CS-CV310, CS-CV248 and LC1C [4]", "EZVIZ CS-DB1C-A0-1E2W2FR, named among the camera models in CVE-2022-2471 [5]", "EZVIZ robot vacuums and smart fingerprint locks [3]"]
radios: ["Wi-Fi (indoor and outdoor Wi-Fi camera lines) [3]", "LTE/5G (4G security camera line) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2022-2471: stack buffer overflow in the motion-detection component of several EZVIZ cameras, remote code execution [5]", "CVE-2023-34552: unauthenticated stack overflows in the SADP multicast protocol parser, RCE from the same LAN [4]", "CVE-2023-34551: stack overflows in the SDK command server netClientSetWlanCfg, authenticated RCE from the LAN [6]", "CVE-2023-48121: authentication bypass in the Direct Connection Module of CS-C6N, CS-CV310, CS-C6CN and CS-C3N, disclosing sensitive information [7]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 14 MA-L blocks under "Hangzhou Ezviz Software Co.,Ltd." at No.188 Qizhi East Street, Binjiang District, Hangzhou, Zhejiang, China address [1]. Ezviz is one of the brands of Hikvision, the Hangzhou video-surveillance manufacturer, alongside Hilook and Hiwatch [2]. EZVIZ sells indoor, outdoor, wire-free, 4G and PoE security cameras plus smart-home products including smart locks, robot vacuums and home sensors, under the legal entity EZVIZ Inc. on its own site [3]. A MAC in an Ezviz block is therefore most likely a consumer Wi-Fi camera, such as the CS-C6N, CS-CV310, CS-CV248, LC1C or CS-DB1C models named in NVD records [4][5].

The cameras carry a run of LAN-reachable flaws: a motion-detection stack overflow allowing remote code execution (CVE-2022-2471) [5], unauthenticated overflows in the SADP multicast discovery parser (CVE-2023-34552) [4], overflows in the SDK command server (CVE-2023-34551) [6] and an authentication bypass in the Direct Connection Module that discloses sensitive information (CVE-2023-48121) [7]. Founding year, the silicon inside EZVIZ cameras and FCC grantee codes are not listed: the FCC ID databases and teardown wikis refused automated access from the session that wrote this entry, EZVIZ's about page gave no corporate history, and nothing is filled in from memory. Randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Hikvision - Wikipedia - https://en.wikipedia.org/wiki/Hikvision (accessed 2026-10-27)
3. EZVIZ - Creating Easy Smart Homes (about us) - https://www.ezviz.com/about-us (accessed 2026-10-27)
4. NVD - CVE-2023-34552 - https://nvd.nist.gov/vuln/detail/CVE-2023-34552 (accessed 2026-10-27)
5. NVD - CVE-2022-2471 - https://nvd.nist.gov/vuln/detail/CVE-2022-2471 (accessed 2026-10-27)
6. NVD - CVE-2023-34551 - https://nvd.nist.gov/vuln/detail/CVE-2023-34551 (accessed 2026-10-27)
7. NVD - CVE-2023-48121 - https://nvd.nist.gov/vuln/detail/CVE-2023-48121 (accessed 2026-10-27)
