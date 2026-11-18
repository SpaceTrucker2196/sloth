---
name: NETGEAR
aliases: []
affiliates: []
country: US [1]
parent: "independent (Arlo camera business spun out as a separate company August 2018) [1]"
founded: 1996 [1]
kind: network-equipment
device_classes: [ap/router, switch]
found_in: ["Nighthawk R7000 router [3]", "Nighthawk RAX120 (AX12) router [4]", "Orbi mesh Wi-Fi systems [1]", "ProSAFE business switches [1]", "Mobile WiFi hotspots and ProAV switching [2]"]
radios: ["Wi-Fi 5 (802.11ac) 3x3, R7000 [3]", "Wi-Fi 6 (802.11ax) 4x4 2.4 GHz / 8-stream 5 GHz, RAX120 [4]", "2.4 GHz [3][4]", "5 GHz [3][4]"]
silicon: ["Broadcom BCM4709A0 SoC + BCM4360 3x3 radios in Nighthawk R7000 [3]", "Qualcomm IPQ8074 SoC + QCN5054 (5 GHz) and QCN5024 (2.4 GHz) in Nighthawk RAX120 [4]"]
fcc_grantee: ["PY3 (e.g. FCC ID PY313200233, PY317300397) [3][4][5]"]
randomization: unknown
security_notes: ["Backdoor in SerComm-manufactured NETGEAR products allowing unauthenticated remote access (2014) [1]", "Router exploit giving third-party access to the router and internal network (2017) [1]", "Authentication bypass in the admin interface of many home Wi-Fi routers (2020) [1]", "Vendor runs a bug bounty and publishes advisories plus monthly security patch summaries [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
NETGEAR is a San Jose, California networking-equipment company founded by Patrick Lo in 1996 [1]; it sells home Wi-Fi (Nighthawk routers, Orbi mesh), ProSAFE and ProAV switches, enterprise gear and mobile hotspots [1][2], and its former Arlo camera line has been a separate company since August 2018 [1], so cameras are no longer the expected device here. It holds 77 MA-L blocks [6], and a MAC in one of them is almost always infrastructure: a router or mesh node's LAN/WAN port or BSSID, or a switch. Documented silicon is Broadcom in the Wi-Fi 5 generation (BCM4709A0 + BCM4360 in the R7000, OUIs 04:A1:51 and 44:94:FC [3]) and Qualcomm in Wi-Fi 6 (IPQ8074 + QCN5054/QCN5024 in the RAX120 [4]); the FCC grantee code is PY3, with 335 devices in DeviWiki's database under it [5]. Because NETGEAR is a brand rather than a manufacturer, the 2014 backdoor found in NETGEAR units built by ODM SerComm [1] is the cautionary example: the OUI tells you who sold the box, not who built the firmware. Later incidents include a 2017 remote-access exploit and a 2020 admin-interface authentication bypass across many home routers [1]; the vendor now runs a bug bounty and publishes advisories and monthly patch roll-ups [7]. Nothing on MAC randomization applies to or is documented for these products, so that field is unknown. An operator seeing a NETGEAR OUI on a client address rather than a BSSID should suspect a hotspot, extender or a router in bridge mode.
## Sources
1. Netgear - Wikipedia - https://en.wikipedia.org/wiki/Netgear (accessed 2026-10-27)
2. About NETGEAR - NETGEAR - https://www.netgear.com/about/ (accessed 2026-10-27)
3. Netgear R7000 - DeviWiki - https://deviwiki.com/wiki/Netgear_R7000 (accessed 2026-10-27)
4. Netgear RAX120 - DeviWiki - https://deviwiki.com/wiki/Netgear_RAX120 (accessed 2026-10-27)
5. Netgear - DeviWiki (vendor page, FCC grantee PY3) - https://deviwiki.com/wiki/Netgear (accessed 2026-10-27)
6. NETGEAR MAC address blocks - maclookup.app - https://maclookup.app/vendors/netgear (accessed 2026-10-27)
7. Security at NETGEAR - NETGEAR - https://www.netgear.com/about/security/ (accessed 2026-10-27)
