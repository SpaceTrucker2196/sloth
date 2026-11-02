---
name: AzureWave Technology Inc.
aliases: []
country: TW [1]
parent: unknown
founded: unknown
kind: module-maker
device_classes: [module-in-other-brands, laptop]
found_in: ["Radxa Rock Pi 4C+ and Rock Pi CM3 single-board computers (AW-CM256SM) [3]", "ASUS PCE-AX1800 Wi-Fi 6 adapter (AW-XB468NF) [4]", "AI-LINK WF-M921E-MPA1 and LinkStar-H68K (AW-XB468NF) [4]", "HP, Fujitsu, Lenovo, Lite-On and Huawei laptops/devices (AW-CB375NF) [5]", "NXP i.MX8M system-on-module (AW-CM390SM) [6]"]
radios: ["Wi-Fi 5 (802.11ac) 2.4/5 GHz 1x1, AW-CM256SM and AW-CM390SM (CYW43455) [3][6]", "Wi-Fi 5 (802.11ac) 2x2 Wave 2, AW-CB375NF (RTL8822CE) [5]", "Wi-Fi 6 (802.11ax) 2x2, AW-XB468NF (MT7921L), AW-XB473NF (RTL8852AE) and AW-XM458 (88W9098) [4][7]", "Wi-Fi 6 (802.11ax) 1x1 tri-radio with BT 5.3 and 802.15.4, AW-XM549 (IW612) [7]", "2.4 GHz [3][5]", "5 GHz [3][5]", "BLE 4.x (Bluetooth 4.2), AW-CM256SM [3]", "BLE 5.x (Bluetooth 5.0), AW-CM390SM, AW-CB375NF, AW-XB468NF, AW-XM458 [4][5][6][7]", "Thread/Zigbee (802.15.4), AW-XM549 [7]"]
silicon: ["Cypress/Infineon CYW43455 in AW-CM256SM and AW-CM390SM [3][6]", "MediaTek MT7921L in AW-XB468NF [4]", "Realtek RTL8822CE in AW-CB375NF [5]", "Realtek RTL8852AE in AW-XB473NF [7]", "Marvell/NXP 88W9098 in AW-XM458 [7]", "NXP IW612 in AW-XM549 [7]"]
fcc_grantee: ["TLZ (e.g. FCC ID TLZ-CM390SM) [6][7]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
AzureWave Technology Inc. is a Taiwanese wireless-module maker whose IEEE blocks are registered to Baozhong Road, Xindian, Taipei [1]; it holds 81 MA-L blocks, the first assigned in September 2005 [8]. Its corporate history (founding year, listing, shareholders) could not be read from a reachable primary page in this session - the company site's about pages and its NXP/Cypress module catalogue page returned 404 and there is no English Wikipedia article - so those fields are unknown. What is well documented is the product: M.2 and SiP/SMD Wi-Fi + Bluetooth modules built on other vendors' silicon, Cypress/Infineon CYW43455 for 1x1 dual-band Wi-Fi 5 embedded parts [3][6], Realtek RTL8822CE and RTL8852AE and MediaTek MT7921L for Wi-Fi 5/6 laptop and adapter cards [4][5][7], and Marvell/NXP 88W9098 and the tri-radio NXP IW612 at the top end [7]. A MAC in an AzureWave block is therefore some other brand's device: documented hosts include Radxa Rock Pi single-board computers [3], the ASUS PCE-AX1800 adapter [4], HP, Fujitsu, Lenovo and Huawei laptops [5], and NXP i.MX8M system-on-modules [6], so expect a laptop, SBC or embedded gateway rather than a phone. Two FCC facts matter for identification: AzureWave's own grantee code is TLZ (e.g. TLZ-CM390SM) [6][7], but several of its modules are certified under the chip vendor's code instead - RAS-MT7921 for the MediaTek part and TX2-RTL8822CE for the Realtek part [4][5] - so an FCC ID on the label will not always say AzureWave. No AzureWave statement on MAC randomization and no AzureWave-specific security advisories were found; CVE exposure follows the host OS and the chipset driver, not the module brand.
## Sources
1. MAC prefix 00:15:AF - maclookup.app - https://maclookup.app/macaddress/0015AF (accessed 2026-10-27)
2. Wireless Modules - NXP/Cypress - AzureWave - https://www.azurewave.com/wireless-modules-nxp.html (accessed 2026-10-27) (not reachable 2026-10-27: HTTP 404)
3. AzureWave AW-CM256SM - WikiDevi mirror - https://wikidevi.wi-cat.ru/AzureWave_AW-CM256SM (accessed 2026-10-27)
4. AzureWave AW-XB468NF - WikiDevi mirror - https://wikidevi.wi-cat.ru/AzureWave_AW-XB468NF (accessed 2026-10-27)
5. AzureWave AW-CB375NF - WikiDevi mirror - https://wikidevi.wi-cat.ru/AzureWave_AW-CB375NF (accessed 2026-10-27)
6. AzureWave AW-CM390SM - WikiDevi mirror - https://wikidevi.wi-cat.ru/AzureWave_AW-CM390SM (accessed 2026-10-27)
7. AzureWave - WikiDevi mirror (vendor page, FCC grantee TLZ, module list) - https://wikidevi.wi-cat.ru/AzureWave (accessed 2026-10-27)
8. AzureWave Technology Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/azurewave-technology-inc (accessed 2026-10-27)
