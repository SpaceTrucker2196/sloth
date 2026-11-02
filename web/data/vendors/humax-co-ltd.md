---
name: "HUMAX Co., Ltd."
aliases: []
country: KR [1][2]
parent: unknown
founded: 1989 [2]
kind: brand [2]
device_classes: [tv [2], ap/router [3][4]]
found_in: ["YouView set-top boxes for BT and Plusnet [2]", "products for Google Fiber, Spectrum, DirecTV, AT&T Fiber, NET Brazil and TrueVisions [2]", "HUMAX E2 dual-band AC router [4]", "Humax HG100R Wi-Fi router [5]"]
radios: ["Wi-Fi 5 (AC router) [4]", "2.4 GHz [4]", "5 GHz [4]", "Wi-Fi 6E tri-band in a DOCSIS 3.1 gateway under development in 2020 [3]"]
silicon: ["MediaTek MT7620A SoC with MT7610E 5 GHz radio in the HUMAX E2 router [4]", "Broadcom platform in the Humax IP Box set-top box (2020) [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2017-11435: authentication bypass in Humax HG100R firmware 2.0.6 exposing IP addresses, SSIDs and Wi-Fi passwords when the management console is exposed [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

HUMAX was founded in South Korea in February 1989 as Conin System by Dae Gyu Byun and is headquartered in Seongnam; it makes set-top boxes, video gateways, broadband gateways and digital video recorders and is listed on KOSDAQ [2]. It has made YouView set-top boxes for BT and Plusnet and products for Google Fiber, Spectrum, DirecTV, AT&T Fiber, NET in Brazil and TrueVisions in Thailand [2]. The IEEE registry lists many MA-L blocks to HUMAX Co., Ltd. at its Seongnam addresses; a separate HUMAX NETWORKS entry is a different registrant and is not merged here [1].

A MAC in a HUMAX block is most likely an operator-supplied set-top box or broadband gateway in a living room, often branded by the operator [2]. In October 2020 HUMAX said it was developing a DOCSIS 3.1 Wi-Fi 6E tri-band gateway and extender, and showed a market-ready IP Box set-top integrated with a Broadcom solution [3]. The HUMAX E2, a 2.4/5 GHz AC router, uses a MediaTek MT7620A SoC with a MediaTek MT7610E 5 GHz radio [4].

The Humax HG100R Wi-Fi router on firmware 2.0.6 has an authentication bypass, CVE-2017-11435, that exposes IP addresses, SSIDs and Wi-Fi passwords when its management console is reachable [5]. The FCC ID databases refused this session's requests, so no grantee code is listed, and no source documents MAC randomization.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Humax - Wikipedia - https://en.wikipedia.org/wiki/Humax (accessed 2026-10-27)
3. Humax unveils Voice Assistant STB and Wi-Fi 6E gateway - Advanced Television - https://www.advanced-television.com/2020/10/27/humax-unveils-voice-assistant-stb-wi-fi-6e-gateway/ (accessed 2026-10-27)
4. ramips: add support for HUMAX E2 - OpenWrt git - https://git.openwrt.org/6041c693dd4660f1585322c182e83479afb3c381 (accessed 2026-10-27)
5. CVE-2017-11435 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2017-11435 (accessed 2026-10-27)
