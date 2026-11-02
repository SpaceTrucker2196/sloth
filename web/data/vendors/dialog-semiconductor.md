---
name: Dialog Semiconductor
aliases: []
country: GB [2]
parent: Renesas Electronics, since 2021 [2]
founded: 1985 [2]
kind: chip-vendor [2]
device_classes: [module-in-other-brands [2][4], smart-home [4][6], iot-sensor [4]]
found_in: ["August Smart Lock (DA1468x Bluetooth Low Energy SoC) [6]", "Apple iPhone, iPad and Watch power management ICs (not a radio) [2]"]
radios: ["BLE 4.x/5.x [5][6]", "Wi-Fi 4 (802.11b/g/n, DA16200) [4]"]
silicon: ["DA14580/1/2/3 Bluetooth Low Energy SoCs [5]", "DA1468x Bluetooth Low Energy SoC in the August Smart Lock [6]", "DA16200 ultra-low-power Wi-Fi SoC [4]", "FC9000 ultra-low-power Wi-Fi SoC from the acquired FCI line [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-17517: Dialog SDK through 5.0.4 for DA14580/1/2/3 does not restrict the L2CAP payload length, so a crafted Link Layer packet in radio range overflows a buffer [5]", "CVE-2019-17518: Dialog SDK through 1.0.14.1081 for DA1468x overflows on an oversized link layer payload, affecting for example the August Smart Lock [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists one MA-L block to "Dialog Semiconductor" at an address in Pangyo, Seongnam-si, Gyeonggi-do, South Korea [1]. Dialog Semiconductor was created in May 1985, is an Anglo-German company headquartered in Reading in the UK, makes mixed-signal ICs for smartphones, IoT and smart home devices, has supplied power management ICs for Apple's iPhone, iPad and Watch since 2007, and has been a subsidiary of Renesas Electronics since 2021 [2]. Its Korean presence came with the 2019 purchase of FCI, Silicon Motion's mobile communications line, which added roughly 100 engineers in South Korea, a group based near Seoul whose products included the FC9000 ultra-low-power Wi-Fi SoC [2][3]; that the Korean block belongs to this acquired Wi-Fi line is inferred from the address, not stated by a source [1][3].

A MAC in this block is most likely a battery-powered IoT device built on a Dialog connectivity chip, so the brand on the device is someone else's [1][4]. Dialog's DA16200 Wi-Fi SoC has an 802.11b/g/n radio and targets connected door locks, thermostats and security video cameras [4]. Its Bluetooth Low Energy SoCs carry two CVEs published in February 2020: CVE-2019-17517 in the DA14580/1/2/3 SDK and CVE-2019-17518 in the DA1468x SDK, the latter affecting for example the August Smart Lock, both letting an attacker in radio range cause a buffer overflow with a crafted packet [5][6].

FCC grantee codes and randomization are not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Dialog Semiconductor - Wikipedia - https://en.wikipedia.org/wiki/Dialog_Semiconductor (accessed 2026-10-27)
3. Dialog to Acquire FCI, Silicon Motion's Mobile Communications Business - Microwave Journal - https://microwavejournal.com/articles/31921-dialog-to-acquire-fci-silicon-motions-mobile-communications-business (accessed 2026-10-27)
4. Dialog Semiconductor Extends IoT Connectivity Portfolio with New Ultra Low Power Wi-Fi SoC - Microwave Journal - https://www.microwavejournal.com/articles/33897-dialog-semiconductor-extends-iot-connectivity-portfolio-with-new-ultra-low-power-wi-fi-soc (accessed 2026-10-27)
5. CVE-2019-17517 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-17517 (accessed 2026-10-27)
6. CVE-2019-17518 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2019-17518 (accessed 2026-10-27)
