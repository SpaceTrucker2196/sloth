---
name: "Epigram, Inc."
aliases: []
country: US [1]
parent: "Broadcom Corporation (acquired April 1999 for $316M in stock); the block is now used by Broadcom [2]"
founded: unknown
kind: chip-vendor
device_classes: [ap/router, module-in-other-brands, laptop]
found_in: ["Broadcom BCM943217HM4L reference-design Mini PCIe card: '00:90:4C:0B:3 is for a BCM943217hm4l reference design (2.4GHz side)'; the same board shipped as Gemtek WPEB-135N, Pegatron UPWL6017, CastleNet WL9217E, Tenda W322E [4]", "Arris SBG6700-AC cable modem/router (Broadcom BCM4360 + BCM43217T) uses 00:90:4C on both 802.11 and Ethernet [5]", "Gemtek WMDB-150AC and an unbranded 3G router listed with OUI 00:90:4C [3]"]
radios: ["Wi-Fi 4 (802.11b/g/n, BCM43217T 2x2:2) in BCM943217HM4L reference design [4]", "Wi-Fi 5 (802.11ac, BCM4360 3x3:3) in Arris SBG6700-AC [5]", "2.4 GHz [4]", "5 GHz [5]"]
silicon: ["Broadcom BCM43217T in BCM943217HM4L and its OEM clones [4]", "Broadcom BCM4360 and BCM43217T (on a Broadcom BCM3383G host) in Arris SBG6700-AC [5]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Epigram, Inc. was a Sunnyvale, California home-networking chip company best known for developing HomePNA 2.0 (phone-line networking, approved by the ITU as G.9951-G.9953) [1][6]; Broadcom bought it in April 1999 for $316 million in stock [2], before the 00:90:4C MA-L block was registered on 9 November 2000 under the Epigram name at 870 West Maude Ave., Sunnyvale [1][7]. In practice 00:90:4C is a Broadcom block: DeviWiki documents it as the MAC written into Broadcom Wi-Fi reference designs, e.g. "00:90:4C:0B:3 is for a BCM943217hm4l reference design (2.4GHz side)" [4], and it shows up on shipping products from several OEMs that reused those designs (Gemtek, Pegatron, CastleNet, Tenda cards; Gemtek WMDB-150AC; an Arris SBG6700-AC cable gateway that uses it on both its radio and Ethernet interfaces) [3][4][5]. A MAC in this block therefore usually means a Broadcom-based radio or router whose manufacturer never burned in its own OUI, often an older 802.11n/ac access point, cable gateway or a Broadcom Mini PCIe card in a laptop, and the same prefix can be seen as a BSSID and as a wired station MAC on the same box [5]. Because the prefix identifies the silicon vendor's reference firmware rather than a product, treat it as "Broadcom-based, brand unknown" and look to the SSID, hostname or DHCP fingerprint for the brand. No current registrant activity, FCC grantee code or security advisories are tied to Epigram itself; Epigram's founding year was not found on a reachable page and is recorded as unknown.
## Sources
1. MAC prefix 00:90:4C - maclookup.app - https://maclookup.app/macaddress/00904C (accessed 2026-10-27)
2. Broadcom Corporation (acquisitions table, Epigram, April 1999) - Wikipedia - https://en.wikipedia.org/wiki/Broadcom_Corporation (accessed 2026-10-27)
3. DeviWiki search for 00:90:4C - https://deviwiki.com/wiki/Special:Search?search=00:90:4C (accessed 2026-10-27)
4. Broadcom BCM943217HM4L - DeviWiki - https://deviwiki.com/wiki/Broadcom_BCM943217HM4L (accessed 2026-10-27)
5. Arris SBG6700-AC - DeviWiki - https://deviwiki.com/wiki/Arris_SBG6700-AC (accessed 2026-10-27)
6. HomePNA - Wikipedia - https://en.wikipedia.org/wiki/HomePNA (accessed 2026-10-27)
7. Epigram, Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/epigram-inc (accessed 2026-10-27)
