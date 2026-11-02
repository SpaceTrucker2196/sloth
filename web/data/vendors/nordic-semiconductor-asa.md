---
name: Nordic Semiconductor ASA
aliases: []
country: NO [1][2]
parent: independent, public on the Oslo Stock Exchange as NOD [1]
founded: 1983 [1]
kind: chip-vendor [1]
device_classes: [unknown]
found_in: []
radios: ["BLE 4.x/5.x [1][3]", "Thread/Zigbee (802.15.4) [1][3]", "2.4 GHz [3]", "Wi-Fi 6 [4]", "5 GHz [4]", "LTE (LTE-M, NB-IoT) [1]"]
silicon: ["nRF52840 Cortex-M4 multiprotocol SoC (Bluetooth LE 5.4, Thread, Zigbee, ANT) [3]", "nRF7002 dual-band Wi-Fi 6 companion IC for nRF52, nRF53 and nRF91 hosts [4]", "nRF9160 cellular IoT SiP [1]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-27211: nRF52840 flash read-out protection (APPROTECT) can be bypassed by fault injection during boot, exposing flash; classed as a physical side-channel weakness [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

Nordic Semiconductor is a fabless Norwegian chip company founded in
1983 as Nordic VLSI by four post-graduates of the Norwegian University
of Science and Technology, headquartered in Trondheim and listed on the
Oslo Stock Exchange since 1996 [1]. The IEEE registry lists a single
MA-L block to it at Otto Nielsens veg 12, Trondheim [2]. Its product
lines are the nRF51 and nRF52 Bluetooth LE SoCs, the dual-core nRF53,
the nRF91 cellular SiPs for LTE-M and NB-IoT, and the nRF70 Wi-Fi 6
companion chips [1].

Nordic is a fabless chip company [1]; its parts normally sit inside
other brands' products under their OUIs, and no source consulted names
a device carrying Nordic's own block, so found_in is empty. The nRF52840 is a 64 MHz
Cortex-M4 SoC supporting Bluetooth LE 5.4, Bluetooth mesh, Thread,
Zigbee, 802.15.4, ANT and 2.4 GHz proprietary protocols concurrently
[3]; the nRF7002 adds dual-band 2.4 and 5 GHz Wi-Fi 6 to nRF52, nRF53
and nRF91 hosts [4]. CVE-2020-27211 records that the nRF52840's flash
read-out protection (APPROTECT) can be bypassed by injecting a fault
during boot, exposing the flash contents; the record classes it as a physical side-channel weakness [5].

Randomization is unknown, and FCC grantee codes are not listed because
the FCC ID databases refused the session that wrote this entry.

## Sources

1. Nordic Semiconductor - Wikipedia - https://en.wikipedia.org/wiki/Nordic_Semiconductor (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. nRF52840 product page - Nordic Semiconductor - https://www.nordicsemi.com/Products/nRF52840 (accessed 2026-10-27)
4. nRF7002 product page - Nordic Semiconductor - https://www.nordicsemi.com/Products/nRF7002 (accessed 2026-10-27)
5. CVE-2020-27211 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2020-27211 (accessed 2026-10-27)
