---
name: AVM Audiovisuelles Marketing und Computersysteme GmbH
aliases: ["AVM GmbH"]
affiliates: []
country: DE [1][2]
parent: unknown
founded: 1986 [1]
kind: network-equipment [1]
device_classes: [ap/router [1][3], smart-home [1]]
found_in: ["FRITZ!Box home gateways (DSL, cable, FTTH and LTE) [1][3]", "FRITZ!WLAN range extenders and USB sticks [1]", "FRITZ!DECT smart-home devices [1]", "FRITZ!Fon telephony [1]", "FRITZ!Box 7590, 7530 and 4040 and FRITZ!Repeater 1200 [4][5]"]
radios: ["Wi-Fi 4/5 [3][5]", "2.4 GHz [3][5]", "5 GHz [3][5]", "DECT [3][5]"]
silicon: ["Lantiq (Intel) GRX550 PXB4583 SoC, Qualcomm QCA9985 (2.4 GHz) and QCA9984 (5 GHz) Wi-Fi and Dialog SC14446 DECT in the FRITZ!Box 7590 [5][4]", "Qualcomm IPQ4019 in the FRITZ!Box 7530 and FRITZ!Repeater 1200 [4]", "Qualcomm IPQ4018 in the FRITZ!Box 4040 [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2014-8886: FRITZ!OS before 6.30 unpacked firmware images before checking their signature, allowing code execution via a crafted image (tested on the FRITZ!Box 7490) [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

AVM is the Berlin maker of the FRITZ!Box home gateway, founded in 1986 by four university students; in July 2025 it changed its corporate name to Fritz! (Fritz! GmbH) to match its product line [1]. The IEEE registry lists 32 MA-L blocks under "AVM Audiovisuelles Marketing und Computersysteme GmbH" and 13 under "AVM GmbH", all at Alt-Moabit 95, Berlin [2]. Its products are FRITZ!Box gateways for DSL, cable, FTTH and LTE, FRITZ!Fon handsets, FRITZ!WLAN repeaters and USB sticks, FRITZ!DECT smart-home devices and FRITZ!Powerline adapters [1], so a MAC in an AVM block is most likely a FRITZ!Box or a FRITZ! repeater on a home network, typically in German-speaking Europe.

FRITZ!Box models carry an 802.11b/g/n radio at 2.4 GHz and in newer models 802.11a/n/ac at 5 GHz, and the 7xxx series includes a DECT base station for cordless handsets; they run FRITZ!OS, a Linux distribution [3]. The FRITZ!Box 7590 pairs a dual-core Lantiq (Intel) GRX550 PXB4583 SoC with a Qualcomm QCA9985 4x4 2.4 GHz radio, a QCA9984 4x4 5 GHz radio and a Dialog SC14446 DECT SoC [5]; DeviWiki gives the same PXB4583 SoC and QCA9985/QCA9984 radios for the 7590, and lists Qualcomm IPQ4019 in the FRITZ!Box 7530 and FRITZ!Repeater 1200 and IPQ4018 in the FRITZ!Box 4040 [4].

RedTeam Pentesting showed (CVE-2014-8886) that FRITZ!OS before 6.30 extracted a firmware image before verifying its signature, so a crafted image could run code; 6.30 fixed it [6]. Parent ownership, FCC grantee codes and address randomization are not documented by the sources consulted: the FCC ID databases and AVM's security-notice page were not reachable from this session, and nothing is filled in from memory.

## Sources
1. Fritz (company) - Wikipedia - https://en.wikipedia.org/wiki/Fritz_(company) (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Fritz!Box - Wikipedia - https://en.wikipedia.org/wiki/Fritz!Box (accessed 2026-10-27)
4. AVM - DeviWiki - https://deviwiki.com/wiki/AVM (accessed 2026-10-27)
5. FRITZ!Box 7590 Modem Router Review - MBReviews - https://www.mbreviews.com/fritzbox-7590-review/ (accessed 2026-10-27)
6. RT-SA-2014-014 AVM FRITZ!Box: Arbitrary Code Execution Through Manipulated Firmware Images - RedTeam Pentesting - https://www.redteam-pentesting.de/en/advisories/rt-sa-2014-014/ (accessed 2026-10-27)
