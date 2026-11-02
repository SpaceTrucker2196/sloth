---
name: "shenzhen trolink  Technology Co.,Ltd"
aliases: ["Shenzhen Trolink Technology CO, LTD", "Shenzhen Trolink Technology Co.,LTD"]
country: CN [1]
parent: unknown
founded: 2010 [1][2]
kind: module-maker
device_classes: [module-in-other-brands, camera, tv, smart-home, pos, iot-sensor]
found_in: ["Modules targeted at IP cameras, NVRs, surveillance kits, OTT boxes, DVB set-top boxes, smart home, smart toys, advertising displays, POS terminals, dashcams, action cameras, projectors, image transmission and aerial-photography links (vendor's stated application list) [2]", "Vendor claims long-term supply relationships with Samsung, Jiuzhou (九洲电气) and BYD [1]"]
radios: ["Wi-Fi 4 (802.11b/g/n, 2.4 GHz) [5]", "Wi-Fi 5 (802.11ac, 2.4 + 5 GHz) [10]", "Wi-Fi 6 (802.11ax) [4]", "2.4 GHz [5]", "5 GHz (802.11ac/ax parts) [9][10]", "BLE 5.2 [4]", "BT 5.2 (RTL8733BS) [6]", "BT 5.4 (AIC8800D80) [9]", "Zigbee (802.15.4) listed as a module line [1]"]
silicon: ["Realtek RTL8852BU in TL8852BUUB (USB, 802.11b/g/n/ax + BLE 5.2) [4]", "Realtek RTL8189FTV in TL8189FCA (SDIO, 802.11b/g/n) [5]", "Realtek RTL8733BS in TL8733BSSC (SDIO + UART, 802.11b/g/n + BT 5.2) [6]", "AIC (爱科微) AIC8800DW in TL8800DWUA (USB, 802.11b/g/n/ax) [7]", "AIC8800D in TL8800D0UA (USB, 802.11b/g/n/ax + BLE 5.2) [8]", "AIC8800D80 in TL8800D8SC (SDIO, 802.11b/g/n/ac/ax + BT 5.4) [9]", "MediaTek MT7628AN + MT7612EN in TR7628A5G router module [10]", "MediaTek MT7621AT + MT7612EN + MT7603EN in TR7621A5G router module [11]", "Qualcomm QCA9531 in TR9531A router module [12]", "Product menus also list HiSilicon (海思) and South Silicon Valley (南方硅谷) Wi-Fi lines [1]"]
fcc_grantee: []
randomization: unknown
security_notes: ["No CVE in NVD matches the keyword 'Trolink' as of 2026-10-27 [18]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Shenzhen Trolink Technology (深圳市创凌智联科技有限公司, brand 创凌) is a Shenzhen Bao'an module house founded in 2010 that designs and manufactures Wi-Fi, Bluetooth and Zigbee modules, router modules and IoT modules on an OEM/ODM basis, and says it ships about 30 million modules a year [1][2]. Its catalogue is built on Realtek, AIC (爱科微), MediaTek and Qualcomm silicon: USB/SDIO station modules such as the RTL8852BU-based TL8852BUUB and the AIC8800D-based TL8800Dx series, and MT7628/MT7621/QCA9531 router SoMs [4][7][10][11][12]. Trolink holds nine IEEE OUI blocks under three spellings of its name [17], and its Realtek category alone lists some sixteen TL81xx/TL87xx/TL88xx station modules [3]. A MAC in a Trolink block is therefore almost never a Trolink-branded product; the vendor names IP cameras, NVRs, OTT and DVB set-top boxes, projectors, dashcams, POS terminals, advertising displays, toys and aerial image links as its target hosts [2]. Expect 2.4 GHz 802.11n-only clients from the older RTL8189/RTL8188 lines and 802.11ax with BLE 5.x from the newer RTL8852/AIC8800 parts [4][5][8]. The fccid.io grantee, company and search pages, which would give Trolink's own FCC grantee codes and certified end products, refused automated access in this session, so the FCC grantee field is left empty rather than recalled. MAC randomization behaviour is host-OS dependent and not documented for these modules. No CVE in NVD names the company [18].
## Sources
1. 创凌 (Trolink) company home page - http://www.trolink.cn/ (accessed 2026-10-27)
2. 关于创凌 (About Trolink) - http://www.trolink.cn/about/ (accessed 2026-10-27)
3. Trolink Realtek Wi-Fi module category - http://www.trolink.cn/product_2/ (accessed 2026-10-27)
4. TL8852BUUB product page - http://www.trolink.cn/product_2/244.html (accessed 2026-10-27)
5. TL8189FCA product page - http://www.trolink.cn/product_2/262.html (accessed 2026-10-27)
6. TL8733BSSC product page - http://www.trolink.cn/product_2/2.html (accessed 2026-10-27)
7. TL8800DWUA product page - http://www.trolink.cn/product_3/241.html (accessed 2026-10-27)
8. TL8800D0UA product page - http://www.trolink.cn/product_3/242.html (accessed 2026-10-27)
9. TL8800D8SC product page - http://www.trolink.cn/product_3/94.html (accessed 2026-10-27)
10. TR7628A5G router module page - http://www.trolink.cn/product_27/237.html (accessed 2026-10-27)
11. TR7621A5G router module page - http://www.trolink.cn/product_27/238.html (accessed 2026-10-27)
12. Trolink Qualcomm router module category (TR9531A, QCA9531 dev boards) - http://www.trolink.cn/product_28/ (accessed 2026-10-27)
13. FCC grantee 2AYHW - Shenzhen Trolink Technology Co., Ltd. (not reachable 2026-10-27: HTTP 403) - https://fccid.io/2AYHW (accessed 2026-10-27)
14. FCC grantee 2BHX3 - Shenzhen Trolink Technology Co., Ltd (not reachable 2026-10-27: HTTP 403) - https://fccid.io/2BHX3 (accessed 2026-10-27)
15. fccid.io company profile - Shenzhen Trolink Technology Co., Ltd. (not reachable 2026-10-27: HTTP 403) - https://fccid.io/company/Shenzhen-Trolink-Technology-Co-Ltd (accessed 2026-10-27)
16. FCC ID 2AYHW-TL8811C (TL8811CUB1-R) (not reachable 2026-10-27: HTTP 403) - https://fccid.io/2AYHW-TL8811C (accessed 2026-10-27)
17. Wireshark manuf OUI database (blocks 30:4A:26, 48:8F:4C, 4C:A3:8F, 68:B9:D3, 74:5E:A5, 94:A4:08, CC:C4:B2, DC:84:03, F0:A8:82) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
18. NVD CVE API keyword search "Trolink" (0 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Trolink (accessed 2026-10-27)
19. fccid.io search "Trolink" (not reachable 2026-10-27: HTTP 403) - https://fccid.io/search/?q=Trolink (accessed 2026-10-27)
