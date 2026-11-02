---
name: "Shenzhen iComm Semiconductor CO.,LTD"
aliases: []
country: CN [1]
parent: unknown
founded: 2018 [2]
kind: chip-vendor
device_classes: [smart-home, camera, iot-sensor, tv, drone, module-in-other-brands]
found_in: ["Smart home appliances, smart security (IPC cameras), OTT/ITV boxes, AIoT and drone data-link products built on iComm's Wi-Fi/BLE SoCs (vendor-stated application areas; no specific brand documented) [2]"]
radios: ["Wi-Fi 4 (802.11b/g/n 1T1R, HT20/HT40) on SV6158, SV6155P, SV32WB01-H [2]", "Wi-Fi 4 dual-band (802.11a/b/g/n 1T1R, 2.4/5 GHz) on SV6256P [2]", "Wi-Fi 6 (vendor states Wi-Fi 6 chipsets; part numbers not given on the reachable page) [2]", "2.4 GHz [2]", "5 GHz (SV6256P) [2]", "BLE 5.0 (SV6158, SV32WB01-H); vendor also states BLE 5.1 products [2]"]
silicon: ["SV6158 SDIO pass-through Wi-Fi 4 + BLE 5.0 [2]", "SV6256P SDIO/USB dual-band pass-through Wi-Fi 4 [2]", "SV6155P USB pass-through Wi-Fi 4 [2]", "SV32WB01-H IoT Wi-Fi 4 + BLE 5.0 combo SoC with integrated MCU [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
Shenzhen iComm Semiconductor (Chinese name 深圳市南方硅谷半导体股份有限公司, "South Silicon Valley Semiconductor") is a fabless Wi-Fi/BLE SoC designer founded in 2018 in Nanshan District, Shenzhen, at No. 13 Langshan Road [2], the scientific research building of Tsinghua Hi-Tech Park that the IEEE holds as the address of its first block 84:EA:97 (10 September 2019) [1]. It has since grown to 31 MA-L blocks, about 520 million addresses, registered between September 2019 and December 2025 [3], which signals high-volume shipments. Its catalogue splits into "pass-through" chips (SV6158: SDIO, 2.4 GHz 1T1R 802.11b/g/n HT20/40 with BLE 5.0, 22 nm; SV6256P: SDIO/USB dual-band 802.11a/b/g/n, 40 nm; SV6155P: USB 2.4 GHz, 40 nm) and "IoT" SoCs such as the SV32WB01-H Wi-Fi 4 + BLE 5.0 combo with integrated MCU and flash, with Wi-Fi 6 and BLE 5.1 parts also stated [2]. The vendor names IoT, smart home, smart city, security, OTT/ITV, IP cameras and drone data transmission as targets [2], so a MAC in an iComm block is most likely a low-cost IoT endpoint or IP camera from a Chinese brand that left the chip vendor's OUI in place: expect a 2.4 GHz-only, single-stream 802.11n client, often chatty on BLE as well, with a fixed MAC. No end-product brand, FCC grantee code or security advisory could be tied to iComm from the pages reachable in this session (the FCC ID databases returned HTTP 403 and DeviWiki has no entry), so found_in is an inference from the vendor's own application list and the rest is left empty.
## Sources
1. MAC prefix 84:EA:97 - maclookup.app - https://maclookup.app/macaddress/84EA97 (accessed 2026-10-27)
2. 深圳市南方硅谷半导体股份有限公司 (iComm Semiconductor) home page - https://www.icomm-semi.com/ (accessed 2026-10-27)
3. Shenzhen iComm Semiconductor CO.,LTD MAC address blocks - maclookup.app - https://maclookup.app/vendors/shenzhen-icomm-semiconductor-co-ltd (accessed 2026-10-27)
