---
name: Shenzhen Phaten Tech. LTD
aliases: []
affiliates: []
country: CN [1]
parent: unknown
founded: unknown
kind: module-maker
device_classes: [module-in-other-brands, smart-home, speaker, iot-sensor]
found_in: ["Wi-Fi / Bluetooth modules sold to OEMs with public FCC manuals: T102 V1.1 Wi-Fi module (FCC ID 2AU7O-T102V11) and CB2L Wi-Fi + Bluetooth IoT module (FCC ID 2BP8R-CB2L) [2][3]", "Wireless audio modules, 5.1 wireless home-theatre solutions and IoT modules with built-in MCU (company's stated specialism) [1]"]
radios: ["Wi-Fi 4 (802.11b/g/n, 2.4 GHz, channels 1-14 on the T102) [2][3]", "2.4 GHz [2][3]", "BLE 5.2 (CB2L module, Bluetooth Core Specification v5.2) [2]"]
silicon: ["Realtek RTL8710BN (ARM Cortex-M4, 2 MB flash, 256 KB SRAM) in the T102 V1.1 Wi-Fi module [3]", "RF chip marked only 'T1' (32-bit MCU at 160 MHz, 2 MB flash, 288 KB RAM, Wi-Fi 4 + Bluetooth 5.2) in the CB2L IoT module; vendor of the die not named in the manual [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Shenzhen Phaten Technology (深圳市飞腾云科技有限公司, phaten.com) is a Shenzhen maker of RF modules for wireless audio, wireless internet and IoT, with its own "飞腾云" IoT cloud platform bridged to Alibaba Cloud, AWS, Azure, Tuya and Tencent Cloud, ISO 9001 certification, a core team it describes as having seven years' experience and 3,000+ customers served; its web site leads with 5.1 wireless home-audio solutions and modules with a built-in MCU [1]. Its founding year and ownership are not published on the site [1]. A MAC in one of its nine IEEE blocks [4] is most likely a third-party product with a Phaten module inside. The two modules with public manuals are a 2.4 GHz 802.11b/g/n station built on a Realtek RTL8710BN with an ARM Cortex-M4, 2 MB flash and 256 KB SRAM (T102 V1.1, FCC ID 2AU7O-T102V11) and the CB2L Wi-Fi and Bluetooth dual-mode IoT module (FCC ID 2BP8R-CB2L), whose radio chip is identified only as "T1" with a 160 MHz 32-bit MCU, 2 MB flash, 288 KB RAM and Bluetooth 5.2 [2][3]. Expect low-power 2.4 GHz 802.11n clients (often soft-AP during provisioning, since the T102 supports STA/AP/STA+AP and SmartConfig and the CB2L supports dual-role AP and STA) and BLE advertisers [3][2]. The fccid.io grantee, company and search pages, which would list the grantee codes (2AU7O and 2BP8R appear in the two manuals' FCC IDs) and the rest of the certified products, refused automated access in this session, so the FCC grantee field and the finished-goods list are left out rather than recalled. No CVE names the company [5].
## Sources
1. 深圳市飞腾云科技有限公司 (Shenzhen Phaten Technology) home page - https://www.phaten.com/ (accessed 2026-10-27)
2. CB2L IoT Module user manual (FCC ID 2BP8R-CB2L) - https://fccid.io/2BP8R-CB2L/User-Manual/User-manual-8408477.pdf (accessed 2026-10-27)
3. T102 V1.1 Wi-Fi Module datasheet / user manual (FCC ID 2AU7O-T102V11) - https://fccid.io/2AU7O-T102V11/User-Manual/User-Manual-4540736.pdf (accessed 2026-10-27)
4. Wireshark manuf OUI database (Shenzhen Phaten Tech. LTD blocks 04:4A:69, 0C:C1:19, 10:B0:6E, 2C:05:47, 34:A6:EF, 8C:BD:37, B0:FC:4B, BC:FD:0C, CC:B8:5E) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
5. NVD CVE API keyword search "Phaten" (0 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Phaten (accessed 2026-10-27)
