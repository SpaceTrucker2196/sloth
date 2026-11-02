---
name: Juniper Networks
aliases: []
affiliates: []
country: US [1][2]
parent: Hewlett Packard Enterprise, whose acquisition closed on 2 July 2025 [2]
founded: 1996 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][3][4], switch [2]]
found_in: ["Juniper MX, PTX and ACX routers and EX and QFX switches [2]", "SRX Series security gateways [2]", "Mist AP41, AP43 and AP61 Wi-Fi access points [2][3]", "Juniper WLA532 access point, built by Accton [4]"]
radios: ["Wi-Fi 4/5/6 [3][4]", "2.4 GHz [3]", "5 GHz [3][4]", "BLE 4.x/5.x [3]"]
silicon: ["Broadcom BCM4908 SoC with three Broadcom BCM43694 Wi-Fi chips and a Nordic nRF52832 BLE chip in Mist AP43 [3]", "Atheros Wi-Fi (models not listed) in WLA532 [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["ScreenOS backdoor (December 2015): unauthorized code gave a root password and altered Dual_EC_DRBG so VPN traffic could be decrypted; CVE-2015-7755 [2][5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Juniper Networks is an American networking company founded on 6 February 1996 by Pradeep Sindhu and headquartered in Sunnyvale, California; Hewlett Packard Enterprise agreed to buy it in January 2024 for about 14 billion dollars and the acquisition closed on 2 July 2025 [2]. The IEEE registry lists 207 MA-L blocks to "Juniper Networks", almost all at 1133 Innovation Way, Sunnyvale; the single "Juniper Systems" block in Logan, Utah, is a different company and not an alias [1].

A MAC in a Juniper block is most likely infrastructure: MX, PTX or ACX routers, EX or QFX switches, SRX security gateways, or Juniper Mist access points such as the AP41, AP43 and AP61 [2]. WikiDevi documents the Mist AP43 as a Broadcom BCM4908 SoC with three Broadcom BCM43694 chips (4x4 plus 2x2, 802.11a/b/g/n/ac/ax, on 2.4 and 5 GHz) and a Nordic nRF52832 for Bluetooth 5.0 Low Energy, so expect BLE as well as Wi-Fi from it [3]. The older Juniper WLA532 was built by Accton on Atheros radios, 802.11b/g/n plus 802.11a/n, under FCC ID QZEWLA532 [4]; the AP43's FCC ID is 2AHBN-AP43 under the Mist name [3], and no source consulted states a grantee code held by Juniper itself, so none is listed.

In December 2015 Juniper issued an emergency patch after finding unauthorized code in ScreenOS: a root password backdoor and a change to the Dual_EC_DRBG generator that could let an attacker decrypt traffic [2]. CVE-2015-7755 records the administrative-access half of it [5]. Randomization is unknown; the FCC ID databases refused the session that wrote this entry.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Juniper Networks - Wikipedia - https://en.wikipedia.org/wiki/Juniper_Networks (accessed 2026-10-27)
3. Mist Systems AP43 - WikiDevi - https://wikidevi.wi-cat.ru/Mist_Systems_AP43 (accessed 2026-10-27)
4. Juniper Networks WLA532 - WikiDevi - https://wikidevi.wi-cat.ru/Juniper_Networks_WLA532 (accessed 2026-10-27)
5. CVE-2015-7755 record - CVE.org - https://cveawg.mitre.org/api/cve/CVE-2015-7755 (accessed 2026-10-27)
