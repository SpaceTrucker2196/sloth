---
name: FN-LINK TECHNOLOGY Ltd.
aliases: ["FN-LINK TECHNOLOGY LIMITED"]
affiliates: []
country: CN [1][2]
parent: independent [1]
founded: 2015 [1]
kind: module-maker
device_classes: [module-in-other-brands, tv, smart-home, camera, console, tablet, laptop]
found_in: ["Walmart WMBR-1 smart-home bridge (Fn-Link 6222B-SRC module) [6]", "Beelink GS1 TV box (Fn-Link 6222B-PRB module) [7]", "Customers named by FN-Link: Huawei, Haier, Xiaomi, Midea, Hisense, Gree, Hikvision, Skyworth, Ecovacs, DingTalk [1]", "Target products named by FN-Link: tablets, laptops, smart TVs, set-top boxes, surveillance cameras, car recorders, AI speakers, game consoles, toys, refrigerators, air conditioners, washing machines [1]"]
radios: ["Wi-Fi 4/5/6 (IEEE 802.11 a/b/g/n/ac/ax) [1]", "2.4 GHz [1][5]", "5 GHz [1][3]", "BT Classic / BLE 4.1 (6222B-PRB, 6222D-UUD) [3][4]", "BLE 5.0 (6222B-SRC in Walmart WMBR-1) [6]", "LTE Cat.1bis modules [1]", "Zigbee (802.15.4) and Sub-1 GHz modules [1]", "PLC and millimetre-wave listed by vendor [1]"]
silicon: ["Realtek RTL8822BS (DeviWiki spells it \"RTL8222BS\") in Fn-Link 6222B-PRB, SDIO, 2x2 802.11ac + BT 4.1 [3]", "Realtek RTL8822BU in Fn-Link 6222D-UUD, USB, 2x2 802.11ac + BT 4.1 [4]", "Realtek RTL8189ES in Fn-Link FN-8900M, SDIO, 1x1 802.11 b/g/n [5]", "Realtek RTL8822CS in Fn-Link 6222B-SRC (Walmart WMBR-1), 2x2 802.11ac + BT 5.0 [6]"]
fcc_grantee: ["2AATL (FCC ID 2AATL-F89ESSM23 on the Fn-Link FN-8900M module, granted 26 March 2014 - predates the 2015 founding date the company states, so the registrant may be a predecessor or related entity) [5][1]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
FN-LINK TECHNOLOGY LIMITED is a Chinese wireless-module maker founded in 2015, headquartered in Bao'an District, Shenzhen, producing Wi-Fi/Bluetooth, Wi-Fi 6, AIoT, Bluetooth, LTE Cat.1bis and antenna products for consumer electronics, home appliances and smart-city customers, and naming Huawei, Haier, Xiaomi, Midea, Hisense, Gree, Hikvision, Skyworth, Ecovacs and DingTalk as customers [1]. The IEEE registry holds 54 MA-L blocks across the three spellings above, at addresses in Changsha, Hunan and Bao'an, Shenzhen [2]. A MAC in these blocks is therefore a solder-down module inside somebody else's product - a smart TV, set-top box, camera, appliance or tablet - not an FN-Link-branded device [1]. Every module documented in teardowns uses Realtek silicon: RTL8822BS/BU and RTL8822CS 2x2 dual-band 802.11ac combos with Bluetooth 4.1 or 5.0 [3][4][6], and the older single-stream 2.4 GHz RTL8189ES [5]. Documented hosts include the Walmart WMBR-1 smart-home bridge (Rockchip RK3308 + 6222B-SRC) [6] and the Beelink GS1 TV box (6222B-PRB) [7]. Expect dual-band Wi-Fi 5 with Bluetooth from most devices; Wi-Fi 6 modules are in the catalogue [1]. The only FCC ID found on a fetchable source is 2AATL-F89ESSM23 on the FN-8900M module [5]; no MAC-randomization behaviour or vendor security advisories were found for the modules themselves.
## Sources
1. FN-LINK TECHNOLOGY LIMITED - company site - https://www.fn-link.com/ (accessed 2026-10-27)
2. IEEE MA-L (OUI) public listing - https://standards-oui.ieee.org/oui/oui.txt (accessed 2026-10-27)
3. Fn-Link 6222B-PRB - DeviWiki - https://deviwiki.com/wiki/Fn-Link_6222B-PRB (accessed 2026-10-27)
4. Fn-Link 6222D-UUD - DeviWiki - https://deviwiki.com/wiki/Fn-Link_6222D-UUD (accessed 2026-10-27)
5. Fn-Link FN-8900M - DeviWiki - https://deviwiki.com/wiki/Fn-Link_FN-8900M (accessed 2026-10-27)
6. Walmart WMBR-1 - DeviWiki - https://deviwiki.com/wiki/Walmart_WMBR-1 (accessed 2026-10-27)
7. DeviWiki search "Fn-Link" - https://deviwiki.com/w/index.php?search=Fn-Link&title=Special%3ASearch&fulltext=1 (accessed 2026-10-27)
