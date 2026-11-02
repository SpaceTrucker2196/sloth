---
name: InPro Comm
aliases: []
affiliates: []
country: TW [1][2]
parent: MediaTek (acquired early 2005) [2]
founded: 2002 [2]
kind: chip-vendor [2]
device_classes: [ap/router [2], laptop [2], module-in-other-brands [2]]
found_in: ["D-Link DI-624M router (IPN2220) [2]", "Linksys WMP11 version 4 PCI card (IPN2120) [2]", "Linksys mini-PCI cards with IPN2220 in Acer TravelMate 2300 and Aspire 1520 laptops [2]", "Packard Bell EasyNote A5560 laptop [2]", "Buffalo and Toshiba products [2]"]
radios: ["Wi-Fi 802.11b/g [2][3]", "802.11a/g [2][3]"]
silicon: ["Inprocomm IPN2220 in D-Link DI-624M [2]", "Inprocomm IPN2120 in Linksys WMP11 v4 [2]", "Inprocomm IPN5320 AirConn access-point chip [3]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The single MA-L block registered as InPro Comm carries a Shuei-Yuan Street address in Taiwan [1]. This entry takes it to be Inprocomm (formerly Integrated Programmable Communications, Inc.), a Hsinchu wireless semiconductor design firm founded in 2002 per Wikipedia's infobox (its categories say 2003) that MediaTek acquired in early 2005 [2]; the match rests on the name and the Taiwanese address, not on a source that ties the block to the company, so treat it as inferred.

Inprocomm made IEEE 802.11b, g and a/g chips with reference designs for PCI, mini-PCI and CardBus, of which the IPN2120 and IPN2220 were the most common [2]. Its 2003 AirConn line paired the IPN2220 client chip, which carried an on-chip UART for WLAN plus GPRS combos, with the IPN5320 access-point chip, and supported WEP, TKIP and hardware AES [3]. D-Link's DI-624M router used the IPN2220, Linksys used the IPN2120 in the WMP11 v4 and IPN2220 mini-PCI cards in 2004 Acer and Packard Bell laptops, and Buffalo and Toshiba products used the chips too [2].

If the identification holds, a MAC from this block is most likely a mid-2000s 802.11b/g card or router built on an Inprocomm reference design [2]. Such hardware predates MAC randomization, but no source in hand states its behaviour, so the field is unknown. No FCC grantee code or security advisory was found for the company.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Inprocomm - Wikipedia - https://en.wikipedia.org/wiki/Inprocomm (accessed 2026-10-27)
3. Taiwan's InProcomm readies 802.11g, .11a/g chips - Design and Reuse (EE Times) - https://us.design-reuse.com/news/5901/taiwan-inprocomm-readies-802-11g-11a-g-chips.html (accessed 2026-10-27)
