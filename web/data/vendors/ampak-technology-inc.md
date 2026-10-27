---
name: "AMPAK Technology,Inc."
aliases: ["AMPAK Technology, Inc.", "AMPAK Technology Inc."]
country: TW [1]
parent: unknown
founded: unknown
kind: module-maker [2]
device_classes: [module-in-other-brands [2][3]]
found_in: ["Pine64 Pinebook Pro laptop (AP6256 module) [2]", "Pine64 ROCKPro64 single-board computer (AP6359SA, later AP6256 module) [3]"]
radios: ["Wi-Fi 5 [2][3]", "2.4 GHz [2]", "5 GHz [2]", "BLE 4.x/5.x [2][3]"]
silicon: ["Broadcom BCM43456 (believed, per the board's documentation) in AP6256 [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: inferred, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

AMPAK Technology is a Taiwanese maker of Wi-Fi/Bluetooth
system-in-package modules; the IEEE registry gives Hsinchu, Taiwan, as
the address of its 42 MA-L blocks, registered under three spellings of
the name [1]. A MAC in an AMPAK block is the module inside someone
else's product, typically a single-board computer, a set-top box or an
IoT board, so the device's brand is not AMPAK: Pine64's Pinebook Pro
carries an AMPAK AP6256 module whose Broadcom transceiver the board's
documentation believes to be the BCM43456, giving 802.11ac on 2.4 and
5 GHz at one spatial stream (about 433 Mbit/s, roughly +15 dBm) and
Bluetooth 5.0, over SDIO for Wi-Fi and UART/PCM for Bluetooth [2]. The
ROCKPro64 shipped the 2x2 MIMO dual-band 802.11ac plus Bluetooth 4.2
AP6359SA module and later the same AP6256 [3].

Expect such a device to keep a fixed hardware MAC on the air unless
its operating system randomises; no source in hand documents either
way, so randomization is unknown. Parent company, founding year and
FCC grantee codes are not listed: AMPAK's own site and the FCC ID
databases were not reachable from the session that wrote this entry,
and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Pinebook Pro - PINE64 wiki - https://wiki.pine64.org/wiki/Pinebook_Pro (accessed 2026-10-27)
3. ROCKPro64 - PINE64 wiki - https://wiki.pine64.org/wiki/ROCKPro64 (accessed 2026-10-27)
