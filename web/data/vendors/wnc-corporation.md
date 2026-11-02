---
name: WNC Corporation
aliases: []
country: TW [2][3]
parent: Wistron Corporation [3]
founded: 1996 [3]
kind: odm/ems
device_classes: [ap/router, module-in-other-brands, automotive-telematics]
found_in: ["Google Wifi mesh systems [4]", "Linksys EA / WRT routers and Velop mesh [4]", "Netgear access points and media streamers [4]", "Aruba Networks enterprise access points [4]", "Aerohive access points [4]", "MikroTik RouterBOARD systems [4]", "Verizon LTE routers and 5G home routers [4]"]
radios: ["Wi-Fi 4 (802.11a/b/g/n) [3][5][6]", "Wi-Fi 5 (802.11ac) [3][5][6]", "2.4 GHz [5][6]", "5 GHz [5][6]", "BLE 4.x (CSR Bluetooth LE in Google Wifi and Linksys Velop) [5][6]", "LTE/5G (Verizon LTE and 5G home routers; 3G/4G devices) [3][4]"]
silicon: ["Qualcomm IPQ4019 Wi-Fi SoC in Google Wifi AC-1304 [4][5]", "CSR1021 Bluetooth in Google Wifi AC-1304 [5]", "Qualcomm IPQ4019 + QCA9886 in Linksys Velop WHW03 [4][6]", "CSR Bluetooth 4.0 LE SoC (CSR1021/CSR8510, part marked uncertain by DeviWiki) in Linksys Velop WHW03 [6]", "Broadcom, Qualcomm Atheros, Marvell, MediaTek, Ralink across WNC-built devices [4]"]
fcc_grantee: ["NKR [4]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
WNC (Wistron NeWeb Corporation, TWSE 6285) is a Taiwanese wireless ODM founded 7 December 1996, headquartered in the Hsinchu Science Park, and a subsidiary of Wistron, itself a 2001 Acer spin-off [3][7]; the IEEE registrant for the 52 MA-L blocks maclookup.app lists is "WNC Corporation" (the registry carries no "Wistron NeWeb" spelling) at a Hsinchu Science-based Industrial Park address, with the oldest block 00:0B:6B dating from 14 October 2002 [1][2]. Its product lines are satellite receivers and LNBFs, 802.11a/b/g/n/ac network equipment, 3G/4G mobile devices, set-top boxes, automotive electronics, RFID/NFC and antennas [3]. A MAC in a WNC block is therefore most often a router, access point or mesh node that another brand sells: DeviWiki records WNC as the manufacturer behind Google Wifi, Linksys EA/WRT/Velop, Netgear, Aruba, Aerohive, MikroTik and Verizon LTE/5G home routers, built on Broadcom, Qualcomm Atheros, Marvell, MediaTek and Ralink silicon [4]. Two documented examples are Google Wifi AC-1304 (Qualcomm IPQ4019, CSR1021 Bluetooth, 2x2 802.11bgn + 802.11an/ac, FCC approval 14 April 2017) [5] and Linksys Velop WHW03 (IPQ4019 plus a QCA9886 second 5 GHz radio, CSR Bluetooth 4.0 LE, FCC approval 21 November 2016) [6]. Note for the operator: those two products carry the brand's own FCC grantee (A4R for Google, Q87 for Linksys), not WNC's NKR [4][5][6], so an FCC ID on the label will usually name the brand while the MAC names WNC. The automotive line is documented only as "automotive electronics" [3]; the specific telematics products and their radios were not found in the sources reached. No MAC-randomization behaviour and no vendor security advisories were found for WNC-built devices in this research; the wnc.com.tw site and the FCC ID mirrors were not consulted.
## Sources
1. maclookup.app - WNC Corporation vendor page - https://maclookup.app/vendors/wistron-neweb-corporation (accessed 2026-10-27)
2. maclookup.app - OUI 00:0B:6B registration - https://maclookup.app/macaddress/000B6B (accessed 2026-10-27)
3. Wikipedia (zh) - WNC (Qi Ji Ke Ji) - https://zh.wikipedia.org/wiki/啟碁科技 (accessed 2026-10-27)
4. DeviWiki - Wistron NeWeb - https://deviwiki.com/wiki/Wistron_NeWeb (accessed 2026-10-27)
5. DeviWiki - Google Wifi (AC-1304) - https://deviwiki.com/wiki/Google_Wifi_(AC-1304) (accessed 2026-10-27)
6. DeviWiki - Linksys Velop (WHW03) - https://deviwiki.com/wiki/Linksys_Velop_(WHW03) (accessed 2026-10-27)
7. Wikipedia - Wistron - https://en.wikipedia.org/wiki/Wistron (accessed 2026-10-27)
