---
name: Cisco SPVTG
aliases: []
country: US [1]
parent: Cisco Systems, inferred from the registry name and from Cisco's 2006 purchase of Lawrenceville-based Scientific Atlanta [1][2]
founded: unknown
kind: network-equipment [2][3]
device_classes: [tv [3], ap/router [4][5]]
found_in: ["Cisco DPC3848 DOCSIS gateway, whose presumed OUI 10:5F:49 is a Cisco SPVTG block [1][5]", "other Cisco DPC gateways such as the DPC3939 and DPC3941 (link to this OUI inferred) [4]", "set-top boxes from the Scientific Atlanta line (link to this OUI inferred) [2][3]"]
radios: ["Wi-Fi 4/5 [4][5]"]
silicon: ["Intel Puma DHCE2652 with Atheros AR9580 and AR9381 Wi-Fi in Cisco DPC3848, built by Pegatron [5]", "Broadcom BCM3383Z with BCM4360 and BCM4331 Wi-Fi in Cisco DPC3929CAD [4]", "Intel Puma DHCE2652 with Qualcomm Atheros QCA9880 and AR9381 in Cisco DPC3941 [4]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 41 MA-L blocks to "Cisco SPVTG" at 5030 Sugarloaf Parkway, Lawrenceville, Georgia [1]. Lawrenceville was the headquarters of Scientific Atlanta, a supplier of broadband transmission networks, set-top boxes and cable modems that Cisco agreed to buy in November 2005 and completed buying in February 2006 [2]. None of the sources consulted expands the SPVTG name or states that these blocks belong to the former Scientific Atlanta business, so that link is inferred from the address and the timing.

Cisco sold its television set-top box and cable modem business to Technicolor for 600 million dollars, closing on 20 November 2015, so devices in these blocks are likely older than that [3]. A MAC here is most likely a cable operator's set-top box or a Cisco-branded DOCSIS gateway; WikiDevi documents such gateways, for example the DPC3848 (Intel Puma DHCE2652, Atheros AR9580 for 802.11a/n and AR9381 for 802.11b/g/n, built by Pegatron, FCC ID VUIDPC3848), the DPC3929CAD (Broadcom BCM3383Z with BCM4360 and BCM4331) and the DPC3941 (Intel Puma with Qualcomm Atheros QCA9880) [4][5]. WikiDevi gives the DPC3848 a presumed OUI of 10:5F:49, which the registry lists to Cisco SPVTG, so that gateway is a likely occupant of these blocks [1][5]; for the other gateways the OUI is not stated, so silicon, radios and found_in stay marked inferred. The sources name 802.11 modes but no band in GHz, so no band is listed [4][5].

WikiDevi lists LDK, UDX and PKW as Cisco's FCC grantee codes and VUI prefixes on the DPC gateways, but none is tied to this block by a source, so no grantee code is listed [4]. No security advisory naming SPVTG was found, and randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Scientific Atlanta - Wikipedia - https://en.wikipedia.org/wiki/Scientific_Atlanta (accessed 2026-10-27)
3. Technicolor SA - Wikipedia - https://en.wikipedia.org/wiki/Technicolor_SA (accessed 2026-10-27)
4. Cisco - WikiDevi - https://wikidevi.wi-cat.ru/Cisco (accessed 2026-10-27)
5. Cisco DPC3848 - WikiDevi - https://wikidevi.wi-cat.ru/Cisco_DPC3848 (accessed 2026-10-27)
