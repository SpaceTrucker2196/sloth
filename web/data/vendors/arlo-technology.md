---
name: Arlo Technology
aliases: []
affiliates: []
country: US [1][2]
parent: unknown
founded: 2014 [2]
kind: brand [2]
device_classes: [camera [2][3], smart-home [3]]
found_in: ["Arlo Video Doorbell AVD1001 [3]", "original battery-powered Arlo HD camera (announced January 2015) [4]", "Arlo Base Station [5][6]", "Arlo Q Plus [7]"]
radios: ["Wi-Fi [4]", "2.4 GHz [3]"]
silicon: ["SigmaStar camera SoC, MediaTek Wi-Fi SoC and Skyworks 2.4 GHz front-end module in Arlo Video Doorbell AVD1001 [3]", "OmniVision OV788 video processor and OV9712 image sensor in the original Arlo camera [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-3949: Arlo Base Station firmware 1.12.0.1_27940 and prior, network misconfiguration exposing restricted interfaces, arbitrary file upload/download [5]", "CVE-2019-3950: Arlo Base Station hard-coded root credentials on the onboard serial interface [6]", "CVE-2021-31505: Arlo Q Plus 1.9.0.3_278 hard-coded SSH credentials in a special boot mode, physical access [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Arlo is an American maker of wireless surveillance cameras, headquartered in San Jose, California; it began in 2014 as a division of Netgear and became an independent company in 2018, with Netgear issuing less than 20 percent of the common stock in the August 2018 NYSE IPO and retaining majority control after it [2]. The IEEE registry lists three MA-L blocks under Arlo Technology, at San Jose and Milpitas addresses [1]. A MAC in an Arlo block is most likely an Arlo camera, video doorbell or base station on the home network [2][3][5].

TechInsights' teardown of the Arlo Video Doorbell AVD1001 found a SigmaStar camera SoC, a MediaTek Wi-Fi SoC and a Skyworks 2.4 GHz Wi-Fi front-end module [3]. The original battery-powered Arlo camera, announced in January 2015, used OmniVision's OV788 ultra-low-power video processor and OV9712 sensor and streamed 720p over Wi-Fi [4]. The cameras use a low-power standby mode to save energy, so expect bursty rather than continuous traffic [2].

The Arlo Base Station had a network misconfiguration allowing file upload and download through restricted interfaces (CVE-2019-3949) and hard-coded root credentials on its serial port (CVE-2019-3950) [5][6]; the Arlo Q Plus accepted hard-coded SSH credentials in a special boot mode (CVE-2021-31505) [7]. Netgear's present stake is not stated in the source, so the parent is left unknown. Arlo's FCC grantee code is not listed because the FCC ID databases (fccid.io, fcc.report, apps.fcc.gov) refused this session's requests, and no source in hand documents MAC randomization either way, so it is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Arlo Technologies - Wikipedia - https://en.wikipedia.org/wiki/Arlo_Technologies (accessed 2026-10-27)
3. Arlo Video Doorbell AVD1001 teardown - TechInsights - https://www.techinsights.com/ja/node/31307 (accessed 2026-10-27)
4. OMNIVISION Brings Battery-Powered HD Video to Arlo, NETGEAR's Wireless Security Camera - OmniVision - https://www.ovt.com/press-releases/omnivision-brings-battery-powered-hd-video-to-arlo-netgears-wireless-security-camera/ (accessed 2026-10-27)
5. CVE-2019-3949 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-3949 (accessed 2026-10-27)
6. CVE-2019-3950 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-3950 (accessed 2026-10-27)
7. CVE-2021-31505 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2021-31505 (accessed 2026-10-27)
