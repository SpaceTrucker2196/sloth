---
name: "Tesla,Inc."
aliases: ["Tesla Inc"]
affiliates: []
country: US [1]
parent: "none (publicly traded, Nasdaq: TSLA) [1]"
founded: 2003 [1]
kind: automotive
device_classes: [automotive-telematics, automotive-infotainment, smart-home]
found_in: ["Tesla vehicles: Model 3, Model Y, Cybertruck, Semi (current) and Model S, Model X, first-generation Roadster (discontinued) [1]", "Tesla Energy products: Powerwall, Megapack, Solar Roof [1]", "Tesla Motors QCA6234 Wi-Fi + Bluetooth module (SiP) [2]", "Model X key fobs and Model 3 Phone Key over BLE (named in CVE-2020-29438..29440 and CVE-2022-37709) [3]"]
radios: ["Wi-Fi 4 (802.11a/b/g/n, 2x2:2) in the QCA6234 module [2]", "Wi-Fi in Model S/X via Marvell 88W8688 (generation not stated) [3]", "BLE (Model 3 Phone Key; Model X key fob Bluetooth wake-up) [3]", "Cellular via the Iris modem in Model S (generation not stated) [3]"]
silicon: ["Qualcomm Atheros QCA6234 SiP with Atheros AR6004 and AR3002 (FCC IDs 2AEIM-QCA6234 and PPD-QCA6234) [2]", "Marvell 88W8688 Wi-Fi firmware as used on Model S/X [3]", "Wi-Fi driven by bcmdhd (Broadcom's dongle-host driver) in Model 3 [3]", "Iris modem in Model S, running QCMAP_ConnectionManager [3]"]
fcc_grantee: ["2AEIM (attested by FCC ID 2AEIM-QCA6234) [2]"]
randomization: unknown
security_notes: ["CVE-2019-13581/13582: heap and stack overflow in Marvell 88W8688 Wi-Fi firmware before p52 as used on Model S/X, via malformed Wi-Fi packets [3]", "CVE-2022-37709: Model 3 Phone Key authentication vulnerable to man-in-the-middle in the BLE channel [3]", "CVE-2023-32155/32156/32157: Model 3 bcmdhd out-of-bounds write LPE, Gateway firmware signature validation bypass, bsa_server BIP heap overflow [3]", "CVE-2024-6029 and CVE-2024-13943: Model S Iris modem race-condition firewall bypass and QCMAP_ConnectionManager sandbox escape [3]", "CVE-2020-29438..29440: Model X key fob firmware unsigned, five-VIN-digit authentication for Bluetooth wake-up, no certificate validation on fob pairing (before 2020-11-23) [3]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Tesla, Inc. is the Austin, Texas electric-vehicle and energy company founded on 1 July 2003 and traded on Nasdaq as TSLA; its current vehicles are the Model 3, Model Y, Cybertruck and Semi (Model S, Model X and the original Roadster discontinued), alongside Powerwall, Megapack, Solar Roof and the Supercharger network [1]. A MAC in a Tesla block is most likely a car's on-board computer or one of its wireless modules, or a Tesla Energy product on the LAN; that mapping is inferred from the product line, since the per-block sources could not be read in this session. The one module documented here is the Tesla Motors QCA6234, a Qualcomm Atheros 2x2 802.11a/b/g/n + Bluetooth SiP built from AR6004 and AR3002, listed under FCC IDs 2AEIM-QCA6234 and PPD-QCA6234 [2], which also attests Tesla's grantee code 2AEIM. Published CVEs name further radios: Marvell 88W8688 Wi-Fi firmware on Model S/X, the bcmdhd Wi-Fi driver on Model 3, the Iris cellular modem on Model S, the BLE Phone Key on Model 3 and Bluetooth wake-up on Model X key fobs [3]. Security-relevant history is long: Wi-Fi firmware overflows (CVE-2019-13581/13582), BLE phone-key man-in-the-middle (CVE-2022-37709), Model 3 bcmdhd, Gateway and bsa_server bugs (CVE-2023-32155..32157), Iris modem firewall and sandbox escapes (CVE-2024-6029, CVE-2024-13943) and Model X key-fob flaws (CVE-2020-29438..29440) [3]. Tesla's randomization behaviour for in-car Wi-Fi is not publicly documented.
## Sources
1. Wikipedia - Tesla, Inc. - https://en.wikipedia.org/wiki/Tesla,_Inc. (accessed 2026-10-27)
2. DeviWiki - Tesla Motors QCA6234 - https://deviwiki.com/wiki/Tesla_Motors_QCA6234 (accessed 2026-10-27)
3. NVD CVE API keyword search "Tesla" (40 results incl. CVE-2016-9337, CVE-2020-10558, CVE-2020-15912, CVE-2020-29438..29440) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Tesla (accessed 2026-10-27)
