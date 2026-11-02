---
name: Xiaomi Communications Co Ltd
aliases: []
country: CN [2]
parent: unknown
founded: unknown
kind: brand
device_classes: [ap/router [3][4][5]]
found_in: ["Xiaomi MiWiFi Mini (R1CM) router, OUI 64:09:80 [3]", "Xiaomi MiWiFi (R1D) router, OUI 8C:BE:BE [4]"]
radios: ["Wi-Fi 4/5 [3][4][5]", "2.4 GHz [3]", "5 GHz [3]"]
silicon: ["MediaTek MT7620A with MT7612E in MiWiFi Mini (R1CM) [3]", "Broadcom BCM4709A0 with BCM43217 and BCM4352 in MiWiFi (R1D) [4]", "MediaTek MT7628DAN with MT7612EN in MiWiFi 4A (R4AC) [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-14094: injection in the connection service of the Xiaomi R3600 router web interface before ROM 1.0.20, leading to stack overflow or remote code execution [6]", "CVE-2018-13023: command injection in wifi_access on Xiaomi Mi Router 3 2.22.15 via the timeout parameter [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 232 MA-L blocks to "Xiaomi Communications Co Ltd" at 33 Xi'erqi Middle Road and at the China Resources Rainbow City, 68 Qinghe Middle Street, both in Haidian District, Beijing; another Xiaomi entity, "Beijing Xiaomi Mobile Software Co., Ltd", holds 70 more and has its own entry [2]. The group, Xiaomi Corporation, was founded in Beijing in April 2010 by Lei Jun and others and sells smartphones under the Xiaomi, Redmi and POCO brands along with IoT and smart home devices, wearables, TVs and electric vehicles [1]. The legal relationship of this registrant to Xiaomi Corporation and its founding year were not found in any source consulted.

WikiDevi ties two Xiaomi routers to blocks in this registrant's name: the MiWiFi Mini (R1CM), a MediaTek MT7620A with an MT7612E for 802.11ac, at OUI 64:09:80 [3], and the MiWiFi R1D, a Broadcom BCM4709A0 with BCM43217 and BCM4352 radios, at OUI 8C:BE:BE [4]. The MiWiFi 4A (R4AC), a MediaTek MT7628DAN (802.11b/g/n) with an MT7612EN (802.11a/n/ac), carries FCC ID 2AFZZR4AC, though WikiDevi gives no OUI for it [5]. So a MAC here can be a Xiaomi router, and given the group's range most likely also a Xiaomi phone or smart home device, though no consulted source ties those to a block [1].

NVD lists command-injection and remote-code-execution flaws in Xiaomi routers, among them CVE-2020-14094 on the R3600 [6] and CVE-2018-13023 on the Mi Router 3 [7]. Randomization is not documented for this registrant. No grantee code is listed: the FCC ID databases refused requests from the session that wrote this entry, and no source consulted names the grantee behind the MiWiFi 4A's FCC ID.

## Sources

1. Xiaomi - Wikipedia - https://en.wikipedia.org/wiki/Xiaomi (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Xiaomi MiWiFi Mini (R1CM) - WikiDevi - https://wikidevi.wi-cat.ru/Xiaomi_MiWiFi_Mini_(R1CM) (accessed 2026-10-27)
4. Xiaomi MiWiFi (R1D) - WikiDevi - https://wikidevi.wi-cat.ru/Xiaomi_MiWiFi_(R1D) (accessed 2026-10-27)
5. Xiaomi MiWiFi 4A (R4AC) - WikiDevi - https://wikidevi.wi-cat.ru/Xiaomi_MiWiFi_4A_(R4AC) (accessed 2026-10-27)
6. CVE-2020-14094 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2020-14094 (accessed 2026-10-27)
7. CVE-2018-13023 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2018-13023 (accessed 2026-10-27)
