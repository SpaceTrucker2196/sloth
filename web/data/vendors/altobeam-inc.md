---
name: AltoBeam Inc.
aliases: []
affiliates: []
country: CN [1]
parent: unknown
founded: 2007 [1][2]
kind: chip-vendor
device_classes: [smart-home, camera, iot-sensor, tv, module-in-other-brands]
found_in: ["Vendor-stated targets: IPTV / OTT set-top boxes, IP cameras, smart doorbells, smart lighting, smart sockets, smart appliances, projectors, office equipment, robot vacuums [1][2]", "DVB demodulator chips adopted by mainstream domestic and overseas television and set-top-box makers (unnamed by the vendor) [1]", "Renesas RA MCU ecosystem partner (2020); strategic cooperation with 360 Smart Life Group (2021) [2]"]
radios: ["Wi-Fi 4 2.4 GHz (802.11b/g/n 1T1R) in ATBM602x [2]", "Wi-Fi 6 single-band 2.4 GHz + BLE 5.4 in ATBM6062D [1][2]", "Wi-Fi 6 dual-band 2.4 / 5 GHz: ATBM6365 (2T2R, tri-mode with Bluetooth) and ATBM6463 (ultra-low-power) [2]", "2.4 GHz [2]", "5 GHz [2]", "BLE 5.x (BLE 5.4) [1][2]", "BT Classic (Wi-Fi + BLE + BT tri-mode parts) [1]", "Vendor claims Wi-Fi 4/5/6/7 transmission chips [1]"]
silicon: ["AltoBeam's own ATBM602x / ATBM603x / ATBM643x / ATBM6162 / ATBM6165 / ATBM6365 / ATBM6062D / ATBM6463 Wi-Fi SoCs [2]", "ATBM20xx silicon TV tuners and ATBM88xx / ATBM78xx DTMB / DVB demodulators (non-radio-LAN) [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
AltoBeam Inc. (Gaotuo Xunda, 高拓讯达) is a fabless chip company founded in 2007 and headquartered in Beijing's Tsinghua Science Park, with branches in Shenzhen, Hangzhou, Chengdu, Xiamen and San Jose; it makes Wi-Fi SoCs, dual- and tri-mode Wi-Fi/Bluetooth chips, low-power IoT controllers, and silicon TV tuners and DTMB/DVB demodulators [1][2]. The IEEE registrant holds 58 MA-L blocks [3], and because AltoBeam sells chips rather than finished products, a MAC in one of them is an unbranded endpoint built on its silicon: the vendor names IPTV/OTT boxes, IP cameras, doorbells, lighting, sockets, appliances, projectors and robot vacuums as the targets and calls itself the largest Wi-Fi chip supplier to wireless surveillance cameras as of 2025 [1][2], but no end brand is named in any source reached, so found_in is marked inferred. On the air the installed base is 2.4 GHz-only Wi-Fi 4: ATBM602x is 802.11b/g/n 1T1R [2]; newer parts add Wi-Fi 6 at 2.4 GHz with BLE 5.4 (ATBM6062D) and dual-band 2.4/5 GHz Wi-Fi 6 (ATBM6365 2T2R tri-mode, ATBM6463 ultra-low-power) [1][2]. The FCC ID database pages for the company's grantee codes could not be read in this session (fccid.io returned 403), so no grantee code and no certified-module list is recorded. No MAC-randomization statement and no published security advisories or CVEs were found for the company (the CIRCL vendor listing for "altobeam" is empty) [4], so both fields are left empty rather than guessed.
## Sources
1. AltoBeam home page (Chinese) - https://www.altobeam.com/ (accessed 2026-10-27)
2. AltoBeam English site - https://www.altobeam.com/en (accessed 2026-10-27)
3. AltoBeam Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/altobeam-inc (accessed 2026-10-27)
4. CVE browse altobeam (empty product list) - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/browse/altobeam (accessed 2026-10-27)
