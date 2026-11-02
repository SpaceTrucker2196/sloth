---
name: SHENZHEN BILIAN ELECTRONIC CO.，LTD
aliases: []
affiliates: []
country: CN [2]
parent: unknown
founded: 1997 [2]
kind: module-maker
device_classes: [module-in-other-brands, ap/router, laptop, camera, smart-home, iot-sensor]
found_in: ["LB-LINK branded routers, USB and PCIe Wi-Fi adapters (Bilian's own consumer brand) [1][2]", "China Mobile router CMIoTalb-W2-1, contract-manufactured by Bilian and shown at MWC 2019 [2]", "Designated supplier to Sichuan Telecom (2017) and products launched with Hunan Telecom (2018) [2]", "LB-LINK BL-R8812RD3 USB adapter (Realtek RTL8812AU) [4]", "LB-LINK BL-AX5400P Wi-Fi 6 router and BL-P8852 AX1800 Wi-Fi 6 + BT 5.1 PCIe adapter [7][8]", "SDIO/USB/PCIe Wi-Fi and Wi-Fi + Bluetooth modules sold to OEMs (the BL-M and BL-R module lines) [3]"]
radios: ["Wi-Fi 4 (802.11b/g/n, 2.4 GHz) [3]", "Wi-Fi 5 (802.11ac, 2.4 + 5 GHz) [3]", "Wi-Fi 6 (802.11ax, 2.4 + 5 GHz) [3]", "Wi-Fi 7 (802.11be, BL-M8922AP1) [3]", "2.4 GHz [3]", "5 GHz (dual-band ac/ax/be modules) [3]", "Bluetooth 4.0 to 5.4 (BT/BLE on the combo modules) [3]", "LTE Cat.1bis modules [1]", "Zigbee (802.15.4), Sub-1 GHz, PLC and mmWave module lines [1]"]
silicon: ["Realtek RTL8922AE in BL-M8922AP1 (Wi-Fi 7 + BT 5.4) [3]", "Realtek RTL8852CU / RTL8852BE / RTL8852CE in BL-M8852CU1 / BL-M8852BP6 / BL-M8852CP1 (Wi-Fi 6 + BT 5.2/5.3) [3]", "Realtek RTL8822EU / RTL8822CS in BL-M8822EU2 / BL-M8822CS1-S [3]", "Realtek RTL8821CU in BL-M8821CU9 [3]", "Realtek RTL8723CS / RTL8723DE / RTL8723BU in BL-M8723CS1 / BL-M8723DP2 / BL-R8723BT1 [3]", "Realtek RTL8188EUS / RTL8192FC / RTL8812EU in BL-R8188EU8 / BL-M8192FU4 / BL-M8812EU2 [3]", "AIC8800MC / M40B / D40L / D40 / D80 in BL-M8800xx modules (Wi-Fi 6 + BT) [3]", "MediaTek MT7920TUN in BL-M7920XU1, MT7601UN in BL-R7601MU5 [3]", "HiSilicon Hi3881 in BL-M3881NT1 [3]", "iComm SV6555M / SV6318 in BL-M6555XU1-M / BL-M6318XS1 [3]", "Realtek RTL8812AU in LB-LINK BL-R8812RD3 [4]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Shenzhen Bilian Electronic (深圳市必联电子有限公司) is a Shenzhen (Guangming) IoT module and networking maker founded in 1997, with a 100,000 m2 factory in Ganzhou, Jiangxi, more than 1,000 staff, ISO 9001/14001 and automotive TS16949 certification, and the consumer networking brand LB-LINK [2]. Its product set spans 802.11 a/b/g/n/ac/ax/be Wi-Fi and Bluetooth modules, LTE Cat.1bis, PLC, mmWave, Sub-1 GHz and Zigbee modules, plus finished routers and USB/PCIe adapters [1][3]. The vendor's own module catalogue names the silicon per part: Realtek RTL8188/8192/8723/8821/8822/8852/8922, AIC8800 variants, MediaTek MT7601/MT7920, HiSilicon Hi3881 and iComm SV6555/SV6318, with 1T1R 802.11b/g/n parts at the bottom and 2T2R 802.11be + BT 5.4 at the top [3]. Under the LB-LINK name it also sells finished goods such as the BL-AX5400P Wi-Fi 6 router and the BL-P8852 AX1800 Wi-Fi 6 + BT 5.1 PCIe adapter [8][7], and DeviWiki records the BL-R8812RD3 USB adapter as a Realtek RTL8812AU 2x2 802.11ac design certified under FCC ID 2AL6KBL-R8812RD3 in 2019 [4]. Bilian holds forty-three IEEE OUI blocks [5], so a MAC in its blocks is most often a third-party product with a Bilian module inside (IP cameras, set-top boxes, smart-home devices, SBCs) or an LB-LINK adapter/router; Bilian also contract-builds operator CPE such as a China Mobile router [2]. On the air expect anything from 2.4 GHz 1T1R 802.11n (RTL8188/RTL8723 class) to dual-band 802.11ax/be with BLE 5.x [3]. The fccid.io grantee and search pages (which would give the grantee codes and the per-filing frequency ranges) refused automated access in this session, so the FCC grantee field is left empty rather than recalled. Randomization is host-OS dependent and undocumented for the modules. No CVE in NVD names the company [6].
## Sources
1. 必联 (LB-LINK) official site home - https://www.b-link.net.cn/ (accessed 2026-10-27)
2. 关于必联 (About Bilian: company profile and 1997-2022 milestones) - https://www.b-link.net.cn/about/8.html (accessed 2026-10-27)
3. B-LINK wireless module product list (model and chipset per module) - https://www.b-link.net.cn/products_10_module.html (accessed 2026-10-27)
4. DeviWiki - LB-LINK BL-R8812RD3 - https://deviwiki.com/wiki/LB-LINK_BL-R8812RD3 (accessed 2026-10-27)
5. Wireshark manuf OUI database (43 blocks under "Shenzhen Bilian Electronic Co.，Ltd") - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
6. NVD CVE API keyword search "Bilian" (0 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Bilian (accessed 2026-10-27)
7. LB-LINK BL-P8852 AX1800 PCIe adapter page - https://www.b-link.net.cn/product_32_171.html.html (accessed 2026-10-27)
8. LB-LINK BL-AX5400P Wi-Fi 6 router page - https://www.b-link.net.cn/product_28_158.html.html (accessed 2026-10-27)
