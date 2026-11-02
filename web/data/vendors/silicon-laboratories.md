---
name: Silicon Laboratories
aliases: []
affiliates: []
country: US [1]
parent: independent, listed on Nasdaq [1]
founded: 1996 [1]
kind: chip-vendor
device_classes: []
found_in: []
radios: ["Bluetooth LE [1][3]", "BT Classic (WT32i under iWRAP) [3]", "Thread/Zigbee (802.15.4) [1]", "Z-Wave (sub-GHz) [1]", "Wi-Fi [1]", "Wi-SUN and proprietary sub-GHz and 2.4 GHz [1]"]
silicon: ["EFR32 wireless SoCs running the Silicon Labs Bluetooth LE stack [3]", "WT32i module running iWRAP [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-15531 and CVE-2020-15532 over-the-air buffer overflow in the Bluetooth LE SDK before 2.13.3 on EFR32 in Central or Observer role [3]", "CVE-2021-31609 oversized LMP packets crash the WT32i under iWRAP 6.3.0 and earlier [3]", "CVE-2024-0240 memory leak halts Bluetooth on EFR32 when notifying multiple clients [3]", "CVE-2023-41093 use-after-free in the Bluetooth SDK through 8.0.0 [3]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

Silicon Labs is a fabless semiconductor company headquartered in Austin, Texas, founded in 1996 by Crystal Semiconductor alumni and listed on Nasdaq [1]. It sells wireless SoCs, modules and microcontrollers for Bluetooth, Zigbee, Thread, Z-Wave, Wi-Fi, Wi-SUN, Amazon Sidewalk and proprietary sub-GHz and 2.4 GHz protocols, built up through the acquisitions of Ember in 2012, Zentri in 2017, Z-Wave from Sigma Designs in 2018 and Redpine Signals' connectivity business in 2020, and it sold its infrastructure and automotive business to Skyworks in 2021 [1].

The registry holds 146 MA-L blocks as Silicon Laboratories, all at US addresses [2]. A MAC in one of them is most likely a low-power IoT radio built on a Silicon Labs SoC or module inside another brand's sensor, light or smart-home product; the OUI names the chip vendor, not the device, and which brands embed it is not documented in the sources consulted [1].

NVD records over-the-air buffer overflows in the Bluetooth LE SDK before 2.13.3 on EFR32 SoCs and modules in the Central or Observer role, allowing code execution or denial of service, a memory leak in the EFR32 Bluetooth stack that halts all Bluetooth operations when notifying several clients, a use-after-free in the Bluetooth SDK through 8.0.0 that can let a precisely timed attacker intercept a few packets, and an oversized-LMP crash of the WT32i module in the Bluetooth Classic stack of iWRAP 6.3.0 and earlier [3]. silabs.com and the FCC ID databases refused the session that wrote this entry, so specific part numbers beyond those and FCC grantee codes are not listed and nothing is filled in from memory. Randomization is the firmware's or host's behaviour and is unknown here.

## Sources
1. Silicon Labs - Wikipedia - https://en.wikipedia.org/wiki/Silicon_Labs (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. NVD CVE API, keyword Silicon Labs Bluetooth - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Silicon%20Labs%20Bluetooth&resultsPerPage=20 (accessed 2026-10-27)
