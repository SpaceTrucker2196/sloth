---
name: YAMAHA CORPORATION
aliases: []
affiliates: []
country: JP [1][3]
parent: unknown
founded: 1887 [1]
kind: brand [1]
device_classes: [speaker [1], ap/router [2]]
found_in: ["Yamaha AV receivers and audio equipment [1]", "Yamaha RTX VPN routers, NVR VoIP routers and WLX wireless LAN access points [2]"]
radios: ["Wi-Fi (WLX access points and the NWR100 wireless LAN router) [2]", "LTE/3G (built-in wireless WAN on the NVR700W) [2]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2024-22366: active debug code in WLX222, WLX413, WLX212, WLX313 and WLX202 access points [4]", "CVE-2011-1323: crafted IP header option reboots RTX, RT, SRT, RTV, RTW and RTA series routers [5]", "CVE-2013-7310: OSPF LSA handling flaw in RTX and other Yamaha routers [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Yamaha Corporation is the Japanese musical instrument and audio
equipment maker founded in 1887 by Torakusu Yamaha as a reed organ
manufacturer (as Nippon Gakki), renamed in 1987 and headquartered at
10-1 Nakazawa-cho, Naka-ku, Hamamatsu [1]. Yamaha Motor began as its
motorcycle division and has been spun off as an independent company,
with its own registry entry under "YAMAHA MOTOR CO.,LTD" [1][3]. The
IEEE registry lists three MA-L blocks to "YAMAHA CORPORATION" at the
Hamamatsu head office [3].

Two kinds of device plausibly carry these blocks: audio equipment such
as AV receivers [1], and Yamaha's network line, which sells RTX VPN
routers, NVR VoIP routers (the NVR700W with built-in LTE/3G wireless
WAN), WLX wireless LAN access points and the NWR100 wireless LAN router
[2]. The sources do not say which line uses which
block, so found_in is marked inferred [2][3]. Yamaha's routers and
access points have a long CVE record, from a 2011 IP option reboot bug
across the RT and RTX series to active debug code found in WLX access
points in 2024 [4][5]. The FCC ID databases and Yamaha's
MusicCast page refused the session that wrote this entry, so no grantee
code, silicon or consumer Wi-Fi detail is listed.

## Sources
1. Yamaha Corporation - Wikipedia - https://en.wikipedia.org/wiki/Yamaha_Corporation (accessed 2026-10-27)
2. Routers and wireless LAN access points - Yamaha Network Products - https://network.yamaha.com/products/routers (accessed 2026-10-27)
3. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
4. NVD CVE API, keyword search Yamaha WLX (CVE-2024-22366) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Yamaha%20WLX (accessed 2026-10-27)
5. NVD CVE API, keyword search Yamaha router - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Yamaha%20router (accessed 2026-10-27)
