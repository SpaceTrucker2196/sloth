---
name: "SparkLAN Communications, Inc."
aliases: []
country: TW [2]
parent: unknown
founded: unknown
kind: module-maker
device_classes: [module-in-other-brands, industrial]
found_in: ["Embedded/industrial systems using SparkLAN Mini PCIe, M.2/NGFF and USB Wi-Fi cards (114 FCC-certified devices catalogued; hosts not named) [1]"]
radios: ["Wi-Fi 4 [1]", "Wi-Fi 5 [1]", "2.4 GHz [1]", "5 GHz [1]", "BLE 4.x/5.x (Bluetooth 4.0 LE on the combo cards) [1]"]
silicon: ["Qualcomm Atheros QCA9880 (WPEA-351AC), QCA9882 (WPEQ-257ACN), QCA9890 (WPEQ-353ACNI), QCA6174 (WNFQ-255ACN(BT)) in Mini PCIe/M.2 cards [1]", "Qualcomm Atheros AR9462 (WPEA-251N(BT)) and QCA9377 (WNFQ-158ACN(BT)) in Wi-Fi + Bluetooth 4.0 LE combo modules [1]", "MediaTek MT7610E (WPER-176AC), MT7612U (WUBM-273ACN USB 2x2 ac) [1]", "Realtek RTL8812AE (WPET-232ACN) [1]"]
fcc_grantee: ["RYK [1]"]
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
SparkLAN Communications is a Taiwanese maker of embedded Wi-Fi modules; its single IEEE block 00:0E:8E is registered at Neihu Road, Neihu, Taipei [2]. DeviWiki catalogues 114 SparkLAN devices under FCC grantee code RYK - mostly Mini PCIe and M.2/NGFF cards plus USB modules - built on Qualcomm Atheros (QCA9880/9882/9890, QCA6174, AR9462, QCA9377), MediaTek (MT7610E, MT7612U) and Realtek (RTL8812AE) silicon, spanning 802.11n and 802.11ac with 1T1R to 3T3R MIMO and Bluetooth 4.0 LE on the combo parts [1]. A MAC in 00:0E:8E is therefore a radio card inside an industrial PC, gateway, kiosk or other embedded host rather than a SparkLAN-branded consumer device [1]; which host brands embed them is not documented in the sources reached, so found_in is inferred from the product form factors. The vendor's own site and the distributor pages tried (DigiKey, Mouser, Arrow) could not be fetched, so founding year, ownership and whether current products reach Wi-Fi 6/6E/7 are not documented here; the chipsets DeviWiki lists top out at Wi-Fi 5 [1]. MAC randomization is a host-OS property and is not documented for these cards. No vendor-specific advisories were looked up.
## Sources
1. DeviWiki: SparkLAN - https://deviwiki.com/wiki/SparkLAN (accessed 2026-10-27)
2. IEEE Registration Authority MA-L registry (read from the copy shipped in sloth web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
