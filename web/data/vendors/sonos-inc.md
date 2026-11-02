---
name: "Sonos, Inc."
aliases: ["Sonos Inc."]
country: US [1][2]
parent: independent, listed on Nasdaq since 2018 [2]
founded: 2002 [2]
kind: brand [2]
device_classes: [speaker [2]]
found_in: ["Sonos speakers: Play:1, Play:3, Play:5, One, Five, Era 100, Era 300, Move, Roam [2]", "Sonos soundbars: Playbar, Beam, Arc, Arc Ultra [2]", "Sonos Ace headphones [2]", "Sonos Amp [5]"]
radios: ["Wi-Fi 4 (SonosNet 2.0 MIMO on 802.11n hardware) [2]", "2.4 GHz [3]", "5 GHz [3]", "BLE 4.x/5.x (Sonos One second generation) [2]"]
silicon: ["Qualcomm Atheros AR9380 Wi-Fi with a Skyworks SE2595L front end in Play:3 [3]", "MediaTek MT7615-family Wi-Fi, by the mt_7615.ko driver named in CVE-2023-50809, in Amp, Arc, Beam and Five [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2018-11316: UPnP HTTP server reachable by DNS rebinding [4]", "CVE-2023-50809: kernel stack overflow in the mt_7615.ko Wi-Fi driver during the WPA2 four-way handshake, fixed in S1 11.12 and S2 15.9 [5]", "CVE-2024-5267 and related: SMB2 handling flaws in Era 100 allowing network-adjacent code execution [6]", "CVE-2022-24046: unauthenticated network-adjacent code execution on Sonos One [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sonos is a US wireless-audio company founded in 2002 as Rincon Audio by John MacFarlane, Craig Shelburne, Tom Cullen and Trung Mai, renamed Sonos in 2004, headquartered in Santa Barbara, California, and public on Nasdaq since its August 2018 IPO [2]. The IEEE registry lists 13 MA-L blocks under "Sonos, Inc." (12 at the Goleta, California address, one at a Santa Barbara address) and one under "Sonos Inc." at Goleta [1]; the separate "SONOS Co., Ltd." block is a Korean registrant and not this company [1]. A MAC in these blocks is a Sonos speaker, soundbar or headphone; the speakers join the home Wi-Fi or form SonosNet, a proprietary AES-encrypted peer-to-peer mesh whose 2.0 version uses MIMO on 802.11n hardware, and the second-generation Sonos One added Bluetooth LE [2].

The Play:3 teardown shows a Qualcomm Atheros AR9380, a 2.4/5 GHz 802.11a/b/g/n chip, behind a Skyworks SE2595L dual-band front end [3], and CVE-2023-50809 names the mt_7615.ko Wi-Fi driver in the Amp, Arc, Beam and Five, where a malformed element in the WPA2 handshake overflowed a kernel stack buffer [5]. Other records include DNS rebinding of the UPnP server (CVE-2018-11316) [4], network-adjacent code execution on the Sonos One (CVE-2022-24046) [7] and SMB2 flaws in the Era 100 (CVE-2024-5267) [6]. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry, and randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Sonos - Wikipedia - https://en.wikipedia.org/wiki/Sonos (accessed 2026-10-27)
3. Sonos Play:3 Teardown - iFixit - https://www.ifixit.com/Teardown/Sonos+Play:3+Teardown/12475 (accessed 2026-10-27)
4. NVD - CVE-2018-11316 - https://nvd.nist.gov/vuln/detail/CVE-2018-11316 (accessed 2026-10-27)
5. NVD - CVE-2023-50809 - https://nvd.nist.gov/vuln/detail/CVE-2023-50809 (accessed 2026-10-27)
6. NVD - CVE-2024-5267 - https://nvd.nist.gov/vuln/detail/CVE-2024-5267 (accessed 2026-10-27)
7. NVD - CVE-2022-24046 - https://nvd.nist.gov/vuln/detail/CVE-2022-24046 (accessed 2026-10-27)
