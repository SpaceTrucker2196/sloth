---
name: "Cisco-Linksys, LLC"
aliases: ["The Linksys Group, Inc.", "Linksys USA, Inc"]
country: US [1][2]
parent: Fortinet, which made Linksys wholly owned in January 2025 (earlier Cisco 2003, Belkin 2013, Foxconn 2018) [1]
founded: 1988 [1]
kind: brand [1]
device_classes: [ap/router [1][3]]
found_in: ["Linksys WRT54G and WRT54GL Wireless-G routers [1][4][5]", "Linksys E-series routers (E900 to E4200), named by SANS as possibly vulnerable to TheMoon [6]", "Linksys Velop tri-band mesh systems [1][3]", "Linksys range extenders and USB adapters [3]"]
radios: ["802.11b/g (WRT54G, WRT54GL) [4][5]", "tri-band Wi-Fi with three radios (Velop) [1]"]
silicon: ["Broadcom BCM4702 SoC with a BroMax WM606-BF Mini PCI module carrying Broadcom BCM4306 and BCM2050 in the WRT54G v1.0 [4]", "Broadcom BCM5352E in the WRT54GL v1.1, built by CyberTAN [5]"]
fcc_grantee: ["Q87 [3][5]", "K7S (Belkin) [3]", "2AYRA (Linksys USA) [3]"]
randomization: unknown
security_notes: ["February 2014: TheMoon worm spread among Linksys E-series routers through an unauthenticated CGI script after identifying the model over HNAP [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Linksys was founded in 1988 by Janie and Victor Tsao as DEW International in their Irvine, California garage; Cisco acquired it in 2003, sold it to Belkin in 2013, Foxconn bought Belkin and Linksys in 2018, and Fortinet, an investor since 2021, made it wholly owned in January 2025 [1]. Linksys is operationally headquartered in Irvine with a legal headquarters in Milton Keynes, England [1]. The IEEE registry lists 25 MA-L blocks to "Cisco-Linksys, LLC" and one to "Linksys USA, Inc", nearly all at 121 Theory Drive, Irvine, and two to "The Linksys Group, Inc." at an earlier Irvine address [2].

A MAC in these blocks is most likely a home router, range extender, USB adapter or Velop mesh node [1][3]. The WRT54G v1.0 ran a Broadcom BCM4702 with a BroMax WM606-BF Mini PCI module carrying Broadcom BCM4306 and BCM2050 (802.11b/g), and the Linux-based WRT54GL v1.1, built by CyberTAN, runs a Broadcom BCM5352E [4][5]. WikiDevi lists the FCC grantee codes Q87 for Linksys, K7S for Belkin and 2AYRA for Linksys USA [3].

In February 2014 the SANS Internet Storm Center described TheMoon, a worm spreading among Linksys routers that read the router model over HNAP and then exploited a CGI script needing no authentication; SANS listed the E900 to E4200 as possibly vulnerable depending on firmware [6]. Randomization behaviour is not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources

1. Linksys - Wikipedia - https://en.wikipedia.org/wiki/Linksys (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Linksys - WikiDevi - https://wikidevi.wi-cat.ru/Linksys (accessed 2026-10-27)
4. Linksys WRT54G v1.0 - WikiDevi - https://wikidevi.wi-cat.ru/Linksys_WRT54G_v1.0 (accessed 2026-10-27)
5. Linksys WRT54GL v1.1 - WikiDevi - https://wikidevi.wi-cat.ru/Linksys_WRT54GL_v1.1 (accessed 2026-10-27)
6. Linksys Worm "TheMoon" Summary: What we know so far - SANS Internet Storm Center - https://isc.sans.edu/diary/17633 (accessed 2026-10-27)
