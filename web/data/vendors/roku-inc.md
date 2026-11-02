---
name: "Roku, Inc."
aliases: ["Roku, Inc"]
country: US [1][2]
parent: independent, listed on Nasdaq since 2017 [2]; Fox Corporation agreed in June 2026 to acquire it [3]
founded: 2002 [2]
kind: brand [3]
device_classes: [tv [3][4], speaker [4], camera [6]]
found_in: ["Roku streaming players and Streaming Sticks [3][4]", "Roku TV smart TVs made by TCL, Hisense, LG, Westinghouse, Panasonic, Philips, Haier, Hitachi and Toshiba [3]", "Roku Smart Soundbar and Streambar [4]", "Roku Indoor Camera SE [6]"]
radios: ["Wi-Fi 4 [4]", "Wi-Fi 5 (Premiere+, Ultra, Streaming Stick 4K) [4]", "2.4 GHz [4]", "5 GHz [4]"]
silicon: ["Broadcom BCM43236B Wi-Fi in Roku 2 (2720R), Roku 3 and early Streaming Sticks [4]", "Broadcom BCM43569 Wi-Fi in Premiere (4620X) and Ultra (4640X) [4]", "Realtek RTL8812BU Wi-Fi in Ultra (4660X2, 4670X) [4]", "Realtek RTD1315 SoC in Express 4K and Streaming Stick 4K [4]", "MStar MSO9380 SoC in Premiere, Ultra and Smart Soundbar [4]"]
fcc_grantee: ["TC2 (FCC IDs TC2-R1006, TC2-R1013, TC2-R1042 and others) [4]"]
randomization: unknown
security_notes: ["CVE-2018-11314: External Control API reachable by DNS rebinding, remote device control and network information disclosure [5]", "CVE-2022-27152: arbitrary file modification on Roku OS 9.4.0 and earlier with a Realtek Wi-Fi chip [7]", "CVE-2023-6322: stack overflow in the Roku Indoor Camera SE message parser [6]", "April 2024 credential-stuffing attack compromised 576,000 Roku accounts; two-factor authentication rolled out afterwards [2]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Roku is a US streaming-platform company founded in October 2002 by Anthony Wood, headquartered in San Jose, California, and listed on the Nasdaq Global Select Market since its September 2017 IPO [2]. The IEEE registry lists 10 MA-L blocks under "Roku, Inc." at Saratoga and Palo Alto addresses and 20 under "Roku, Inc" at San Jose addresses [1]. A MAC in these blocks is most likely a Roku streaming player or stick, or a Roku TV, which is a smart TV built by partners such as TCL, Hisense, LG or Philips with the Roku interface inside [3]; Fox Corporation agreed on 15 June 2026 to acquire Roku for 22 billion dollars [3].

The FCC IDs of Roku players carry the grantee code TC2, and the documented Wi-Fi silicon runs from Broadcom BCM43236B and BCM43569 in earlier players to Realtek RTL8812BU in later Ultras, with MStar MSO9380 and Realtek RTD1315 SoCs; Wi-Fi is 802.11b/g/n on Express models and 802.11ac dual-band on Premiere+, Ultra and Streaming Stick 4K [4]. The External Control API was reachable through DNS rebinding (CVE-2018-11314) [5], Roku OS 9.4.0 and earlier with a Realtek Wi-Fi chip allowed arbitrary file modification (CVE-2022-27152) [7], the Roku Indoor Camera SE had a stack overflow in message parsing (CVE-2023-6322) [6], and a credential-stuffing attack in April 2024 compromised 576,000 accounts [2]. Randomization is unknown: no consulted source documents it.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Roku, Inc. - Wikipedia - https://en.wikipedia.org/wiki/Roku,_Inc. (accessed 2026-10-27)
3. Roku - Wikipedia - https://en.wikipedia.org/wiki/Roku (accessed 2026-10-27)
4. Roku - TechInfoDepot - https://techinfodepot.shoutwiki.com/wiki/Roku (accessed 2026-10-27)
5. NVD - CVE-2018-11314 - https://nvd.nist.gov/vuln/detail/CVE-2018-11314 (accessed 2026-10-27)
6. NVD - CVE-2023-6322 - https://nvd.nist.gov/vuln/detail/CVE-2023-6322 (accessed 2026-10-27)
7. NVD - CVE-2022-27152 - https://nvd.nist.gov/vuln/detail/CVE-2022-27152 (accessed 2026-10-27)
