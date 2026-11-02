---
name: "AMPAK Technology,Inc."
aliases: ["AMPAK Technology, Inc.", "AMPAK Technology Inc."]
country: TW [1]
parent: independent (listed, stock symbol 6546) [1]
founded: 2000 [1]
kind: module-maker
device_classes: [module-in-other-brands, tablet, tv, speaker, camera, smart-home, pos, laptop]
found_in: ["Banana Pi BPI Pro (AP6181) and BPI M2 Ultra (AP6212) [7]", "Khadas VIM (AP6212), VIM Pro (AP6255), VIM2 Basic/Lite (AP6356), VIM2 Max/Pro (AP6359SA) [7]", "Orange Pi 3 (AP6256) [7]", "Cubietech Cubietruck, Ugoos UG007B (AP6210), Ugoos UG802B (AP6330) [7]", "GPD Win / GPD Pocket handheld PCs (AP6356) [7]", "Onda V80 Plus, Jumper EZpad mini 3 tablets (AP6212), Meegopad T08 (AP6234A) [7]", "Vendor-stated target markets: OTT/set-top boxes, smart speakers, IP cameras, e-readers, POS, smart home, VoIP, home healthcare, industrial, automotive [2][4][5][6]"]
radios: ["Wi-Fi 4 [7]", "Wi-Fi 5 [7]", "Wi-Fi 6 [4]", "Wi-Fi 6E [3]", "Wi-Fi 7 [5][6]", "2.4 GHz [4]", "5 GHz [4]", "6 GHz [5]", "BT Classic [7]", "BLE 4.x/5.x [4][7]", "Bluetooth 6.0 [5][6]", "Thread/Zigbee (802.15.4) [6]"]
silicon: ["Broadcom BCM43362 in AP6181/AP6210 [7]", "Broadcom BCM43430 in AP6212, BCM43438 in AP6212A [7]", "Broadcom BCM43340 in AP6234A, BCM43436 in AP6236 [7]", "Broadcom BCM43455 in AP6255, BCM43456 in AP6256 [7]", "Broadcom BCM4330 in AP6330, BCM4339/4335 in AP6335 [7]", "Broadcom BCM4356A2 in AP6356, BCM4359 in AP6359SA [7]", "Synaptics SYN43752 in AP6275SDSR (Wi-Fi 6, BT 5.3) [4]", "Synaptics SYN4390 in AP6690P (Wi-Fi 7 tri-band, BT 6.0) [5]", "Synaptics SRW15XX in AP72312 (Wi-Fi 7 1x1 + BT 6.0 + 802.15.4) [6]", "Synaptics SYN4390/SYN4384 (Wi-Fi 7), SYN4382/4381/4612/43711/43756 (6E), SYN43752/4611/4375/43598 (6), SYN43456/430132 (5), SYN43436S (4), SYN20708 (BT) across the current line [3]"]
fcc_grantee: ["ZQ6 [7]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
AMPAK Technology was established in December 2000 in Hsinchu, Taiwan, is publicly listed (symbol 6546) and makes Wi-Fi/Bluetooth SiP modules, SOMs, 5G and GNSS modules [1][2]. Its modules historically packaged Broadcom combo chips - BCM43362, BCM43430/43438, BCM43455/43456, BCM4356, BCM4359 and others - and today use the same silicon line under Synaptics branding (SYN43752, SYN4390, SRW15XX and more) through a declared strategic partnership [3][4][5][7]. The IEEE lists 42 MA-L blocks under three spellings of the name (9C:B8:B4, 50:41:1C, B8:2D:28, 08:FB:EA, 70:4A:0E, 70:F7:54, 8C:F7:10, 10:D0:7A, CC:B8:A8 and 44:2C:05 among them), most at the Hsinchu Industrial Park in Hukou, a few at Zhubei and one at Jhongli, Taoyuan [8]; Wikidata records 16 MA-L assignments against the company (Q47519437), overlapping that list [9]; FCC grants carry grantee code ZQ6 and the modules enumerate on USB/SDIO with Broadcom's vendor ID 02d0 [7]. A MAC in an AMPAK block is therefore a module inside another brand's product: documented hosts are single-board computers (Banana Pi, Khadas VIM, Orange Pi, Cubietruck), Android TV boxes (Ugoos, Meegopad), budget tablets and GPD handheld PCs [7], and the vendor targets OTT boxes, smart speakers, IP cameras, e-readers, POS terminals, smart-home and automotive [2][4][5][6]. Expect 2.4/5 GHz Wi-Fi 4/5 on legacy hosts and 2.4/5/6 GHz Wi-Fi 6/6E/7 with Bluetooth 5.3-6.0 on current ones; the AP72312 also radios 802.15.4 for Matter over Thread [4][5][6]. MAC randomization is a property of the host OS and is not documented for these modules; no vendor-specific security advisories were found in the sources reached.
## Sources
1. AMPAK: About AMPAK - https://www.ampak.com.tw/about/about-ampak (accessed 2026-10-27)
2. AMPAK: home page - https://www.ampak.com.tw/ (accessed 2026-10-27)
3. AMPAK: Strategic Partnership with Synaptics - https://www.ampak.com.tw/about/StrategicPartnershipWithSynaptics (accessed 2026-10-27)
4. AMPAK: AP6275SDSR product page - https://www.ampak.com.tw/product/WiFi-Bluetooth/M2-1216/AP6275SDSR (accessed 2026-10-27)
5. AMPAK: AP6690P product page - https://www.ampak.com.tw/product/WiFi-Bluetooth/Stamp-Type-2T2R/AP6690P (accessed 2026-10-27)
6. AMPAK: AP72312 product page - https://www.ampak.com.tw/product/WiFi-Bluetooth/LGA-Type1T1R/AP72312 (accessed 2026-10-27)
7. DeviWiki: AMPAK - https://deviwiki.com/wiki/AMPAK (accessed 2026-10-27)
8. IEEE Registration Authority MA-L registry (local export web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
9. Wikidata: AMPAK Technology (Q47519437) - https://www.wikidata.org/wiki/Q47519437 (accessed 2026-10-27)
