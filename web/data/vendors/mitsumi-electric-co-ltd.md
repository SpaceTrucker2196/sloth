---
name: "MITSUMI ELECTRIC CO.,LTD."
aliases: []
affiliates: []
country: JP [1]
parent: MinebeaMitsumi Inc. (since 2017-01-27) [1]
founded: 1954 [1]
kind: module-maker
device_classes: [console, automotive-infotainment, module-in-other-brands]
found_in: ["Nintendo Wii (DWM-W004 module) [2]", "Nintendo DSi (DWM-W015) and DSi XL/LL (DWM-W024) [3][5]", "Nintendo 3DS / 3DS XL (DWM-W028, built by ODM Foxconn J27H023) [4]", "Nintendo DS Wi-Fi subcircuitry [1]", "Summit SDC-MSD30AG, Silex SX-SDCAG and Canon WM222 adapters (reported as Mitsumi modules) [5]", "Mitsumi-branded Wavit11 Wi-Fi and WMX-U01/U02/U03 WiMAX USB dongles [5]", "Automotive and industrial hosts using the MinebeaMitsumi 802.11ac + Bluetooth wireless LAN module [7]"]
radios: ["Wi-Fi 4 [2]", "Wi-Fi 5 [7]", "2.4 GHz [2][7]", "5 GHz [7]", "BT Classic [7]", "WiMAX [5]"]
silicon: ["Broadcom BCM4318E in DWM-W004 (Wii, 802.11b/g) [2]", "Atheros AR9001 / AR6002 in DWM-W015 (DSi, 802.11b/g) [3]", "Atheros AR6014G Wi-Fi chip on the AR9001 chipset in DWM-W028 (3DS, 802.11b/g) [4]"]
fcc_grantee: ["EW4 [2][3][4]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Mitsumi Electric, founded in 1954 and based in Tama, Tokyo, is an OEM maker of peripherals, input devices and drives and has been a MinebeaMitsumi subsidiary since January 2017 [1]; its seven MA-L blocks (00:6F:F2, 00:A0:96, 78:61:7C, BC:82:5D, C4:49:BB, F0:AB:54, F8:3C:80) are all registered at the Tama headquarters [10]. Its best-documented radios are the DWM-W series Wi-Fi modules inside Nintendo consoles: DWM-W004 (Broadcom BCM4318E) in the Wii, DWM-W015 (Atheros AR9001/AR6002) in the DSi, DWM-W024 in the DSi XL and DWM-W028 (Atheros AR6014G on AR9001) in the 3DS, all 802.11b/g on 2.4 GHz and listed under FCC grantee EW4 [2][3][4][5]; DWM-W028 was built for Mitsumi by ODM Foxconn J27H023 and also carries Foxconn FCC IDs MCLJ27H023 and MCLJ27H02301 [4]; Mitsumi also supplied the DS's Wi-Fi circuitry and manufactured official Nintendo, PlayStation and original Xbox controllers [1]. Nintendo's own hardware pages confirm the b/g radios but name no supplier, and the module pages list no OUI, so whether a console's MAC falls in Mitsumi's blocks or Nintendo's is not documented here [8][9]. Today MinebeaMitsumi sells the wireless side under "automotive devices": a shielded 802.11ac (2.4/5 GHz) plus Bluetooth (GFSK/pi/4-DQPSK/8DPSK, UART/PCM/I2S) module rated -40 to +85 C for automotive and industrial use, alongside shark-fin, GNSS and TCU antennas [6][7]. So a MAC in a Mitsumi block today is most likely an in-vehicle Wi-Fi/Bluetooth module, with older game-console and third-party adapters (Summit, Silex, Canon) as the legacy case [5][7]. Chipset of the current automotive module and MAC randomization behaviour are not documented; no vendor-specific advisories were looked up.
## Sources
1. Wikipedia: Mitsumi Electric - https://en.wikipedia.org/wiki/Mitsumi_Electric (accessed 2026-10-27)
2. DeviWiki: Mitsumi Electric DWM-W004 - https://deviwiki.com/wiki/Mitsumi_Electric_DWM-W004 (accessed 2026-10-27)
3. DeviWiki: Mitsumi Electric DWM-W015 - https://deviwiki.com/wiki/Mitsumi_Electric_DWM-W015 (accessed 2026-10-27)
4. DeviWiki: Mitsumi Electric DWM-W028 - https://deviwiki.com/wiki/Mitsumi_Electric_DWM-W028 (accessed 2026-10-27)
5. DeviWiki search "Mitsumi" - https://deviwiki.com/w/index.php?search=Mitsumi&title=Special:Search&fulltext=1 (accessed 2026-10-27)
6. MinebeaMitsumi product database: High-Frequency Devices - https://product.minebeamitsumi.com/en/product/category/hifreq/index.html (accessed 2026-10-27)
7. MinebeaMitsumi product database: Wireless LAN / Bluetooth module (automotive devices) - https://product.minebeamitsumi.com/en/product/category/hifreq/automotive-devices/wirelesslan_bluetooth/index.html (accessed 2026-10-27)
8. Wikipedia: Wii (hardware: 802.11b/g Wi-Fi and Bluetooth modules) - https://en.wikipedia.org/wiki/Wii (accessed 2026-10-27)
9. Wikipedia: Nintendo 3DS (2.4 GHz 802.11 b/g) - https://en.wikipedia.org/wiki/Nintendo_3DS (accessed 2026-10-27)
10. IEEE Registration Authority MA-L registry, the copy committed in sloth as web/data/oui.csv (Debian ieee-data 20260625) - https://github.com/SpaceTrucker2196/sloth/blob/main/web/data/oui.csv (accessed 2026-11-02)
