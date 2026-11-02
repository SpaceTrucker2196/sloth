---
name: "Nintendo Co.,Ltd"
aliases: ["Nintendo Co., Ltd."]
country: JP [1][2]
parent: unknown
founded: 1889 [2]
kind: brand [2]
device_classes: [console [2]]
found_in: ["Nintendo Switch (2017) and Switch 2 (2025) consoles [2][6]", "Nintendo DS, Wii and 3DS consoles [2][5]", "Joy-Con controllers [4]"]
radios: ["Wi-Fi 5 [3][4][7]", "Wi-Fi 6 (Switch 2) [6]", "2.4 GHz [7]", "5 GHz [7]", "Bluetooth 4.1 [3][4]"]
silicon: ["Broadcom BCM4356 802.11ac 2x2 Wi-Fi with Bluetooth 4.1 in the Nintendo Switch [3][4]", "NVIDIA Tegra T210 (Tegra X1) SoC in the Nintendo Switch [3]", "Broadcom BCM20734 Bluetooth 4.1 transceiver in the Joy-Con [4]", "Atheros AR6014G-AL1C Wi-Fi SoC in the Mitsumi DWM-W028 module of the Nintendo 3DS [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Fusee Gelee: unpatchable Tegra X1 boot ROM USB recovery-mode bug on shipped Switch consoles (2018) [8]", "CVE-2018-6242: NVIDIA Tegra boot ROM recovery-mode buffer overflow, physical USB access [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Nintendo is a Japanese video game company headquartered in Minami-ku, Kyoto, founded as Nintendo Koppai on 23 September 1889 and publicly traded in Tokyo; its consoles include the Nintendo DS (2004), Wii (2006), Nintendo 3DS (2011), Nintendo Switch (2017) and Nintendo Switch 2 (2025) [2]. The IEEE registry lists 62 MA-L blocks under "Nintendo Co.,Ltd" and 47 under "Nintendo Co., Ltd.", all at the Kyoto address [1]. A MAC in these blocks is most likely a Nintendo console or controller.

The original Switch carries a Broadcom BCM4356 802.11ac 2x2 Wi-Fi chip with Bluetooth 4.1 next to an NVIDIA Tegra T210 SoC, according to TechInsights and iFixit, and its Joy-Con controllers use a Broadcom BCM20734 Bluetooth 4.1 transceiver [3][4]. Coverage of its FCC filing reports 2.4 and 5 GHz support and 802.11ac MIMO [7]. The Switch 2 FCC listing shows an upgraded Wi-Fi 6 chip, not Wi-Fi 6E or Wi-Fi 7, and NFC in the right Joy-Con [6]. On the 3DS, DeviWiki lists an Atheros AR6014G-AL1C Wi-Fi SoC in a Mitsumi DWM-W028 module [5].

The Switch's Tegra X1 boot ROM has a USB recovery-mode bug (Fusee Gelee, 2018) that cannot be patched on consoles already shipped [8]; CVE-2018-6242 records the boot ROM recovery-mode buffer overflow in pre-2016 Tegra processors [9]. Whether consoles randomise their Wi-Fi MAC is not documented by the sources consulted. The FCC grantee code is not listed because the FCC ID databases refused fetches from this session; and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Nintendo - Wikipedia - https://en.wikipedia.org/wiki/Nintendo (accessed 2026-10-27)
3. Nintendo Switch Teardown - TechInsights - https://techinsights.com/ko/node/16553 (accessed 2026-10-27)
4. Nintendo Switch Teardown - iFixit - https://www.ifixit.com/Teardown/Nintendo+Switch+Teardown/78263 (accessed 2026-10-27)
5. Nintendo - DeviWiki - https://deviwiki.com/wiki/Nintendo (accessed 2026-10-27)
6. FCC listing reveals Nintendo Switch 2 will have NFC, upgraded Wi-Fi and more - Notebookcheck - https://www.notebookcheck.net/FCC-listing-reveals-Nintendo-Switch-2-will-have-NFC-upgraded-Wi-Fi-and-more.974673.0.html (accessed 2026-10-27)
7. FCC filing reveals network and power details for Nintendo Switch - Vooks - https://vooks.net/fcc-filing-reveals-network-power-details-nintendo-switch (accessed 2026-10-27)
8. Hackers find an unpatchable way to breach the Nintendo Switch - Engadget - https://www.engadget.com/2018-04-24-nintendo-switch-tegra-bootrom-vulnerability.html (accessed 2026-10-27)
9. CVE-2018-6242 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2018-6242 (accessed 2026-10-27)
