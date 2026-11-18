---
name: BUFFALO.INC
aliases: []
affiliates: []
country: JP [1][2]
parent: Melco Holdings Inc. [1]
founded: unknown
kind: brand [1]
device_classes: [ap/router [1][3]]
found_in: ["Buffalo AirStation Wi-Fi routers [1]", "Buffalo LinkStation and TeraStation NAS [1]", "Buffalo WHR-300HP2, WZR-1750DHP, WSR-1166DHP and WMR-433 routers [3]", "Buffalo WSR-2533DHPL2 and WSR-2533DHP3 routers [4]"]
radios: ["Wi-Fi 4/5 [3]"]
silicon: ["MediaTek MT7620A in the WHR-300HP2 [3]", "Broadcom BCM4708A0 in the WZR-1750DHP [3]", "MediaTek MT7621AT in the WSR-1166DHP [3]", "Realtek RTL8881AM in the WMR-433 [3]"]
fcc_grantee: ["FDI [3]"]
randomization: unknown
security_notes: ["CVE-2021-20090: path traversal in the web interface of the WSR-2533DHPL2 (firmware 1.02 and earlier) and WSR-2533DHP3 (1.24 and earlier) letting unauthenticated remote attackers bypass login [4]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Buffalo is the best-known brand of Melco Holdings, a Japanese family business founded by Makoto Maki in 1975 and headquartered in Nagoya [1]. The IEEE registry lists 35 MA-L blocks to "BUFFALO.INC", nearly all at the Akamondori building in Naka-ku, Nagoya [2]. Its lines include AirStation routers and LinkStation and TeraStation network-attached storage [1], so a MAC in a Buffalo block is most likely a home router or a NAS.

DeviWiki records FCC grantee code FDI for Buffalo and the silicon in several routers: MediaTek MT7620A in the WHR-300HP2, Broadcom BCM4708A0 in the WZR-1750DHP, MediaTek MT7621AT in the WSR-1166DHP and Realtek RTL8881AM in the WMR-433 [3]. CVE-2021-20090 is a path traversal in the web interface of the WSR-2533DHPL2 and WSR-2533DHP3 that lets an unauthenticated remote attacker bypass the login [4]. Buffalo's own founding year is not given by the sources consulted (the 1975 date is Melco's), address randomization is not documented either, and nothing is filled in from memory.

## Sources
1. Buffalo Inc. - Wikipedia - https://en.wikipedia.org/wiki/Buffalo_Inc. (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Buffalo - DeviWiki - https://deviwiki.com/wiki/Buffalo (accessed 2026-10-27)
4. CVE-2021-20090 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2021-20090 (accessed 2026-10-27)
