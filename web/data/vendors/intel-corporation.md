---
name: Intel Corporation
aliases: []
affiliates: []
country: US [1]
parent: independent, listed on Nasdaq [1]
founded: 1968 [1]
kind: chip-vendor
device_classes: []
found_in: []
radios: ["Wi-Fi 6E (802.11ax) [3]", "Wi-Fi 7 [4]", "2.4 GHz [3][4]", "5 GHz [3][4]", "6 GHz [3][4]", "Bluetooth 5.4 [3][4]"]
silicon: ["Intel Wi-Fi 6E AX210 (M.2 2230 and 1216 module) [3]", "Intel Wi-Fi 7 BE200 (M.2 2230 and 1216 module) [4]", "Wi-Fi 6 AX201, AX200 and Wireless-AC 9560, 9260, 8265 families named in INTEL-SA-00473 [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["INTEL-SA-00473 (2021): CVE-2020-24586, CVE-2020-24587, CVE-2020-24588 fragment cache, mixed key and aggregation attacks in PROSet/Wireless, vPro CSME and Killer Wi-Fi [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

Intel is an American technology company headquartered in Santa Clara, California, founded in 1968 by Gordon Moore and Robert Noyce with investor Arthur Rock and listed on Nasdaq; besides processors it makes chipsets and network interface controllers [1]. The registry holds 16 MA-L blocks as Intel Corporation at US addresses and 661 MA-L blocks plus one MA-S as Intel Corporate at Lot 8, Jalan Hi-Tech 2/3, Kulim, Malaysia, the spelling that covers most Intel blocks [2][6].

Intel manufactures network interface controllers [1] and sells its client Wi-Fi as M.2 modules [3][4], so a MAC in an Intel block is most likely an Intel Wi-Fi or Ethernet controller, and the OUI names the network-chip vendor, not the device. Intel's current client Wi-Fi parts are M.2 modules: the Wi-Fi 6E AX210 covers 2.4, 5 and 6 GHz with 160 MHz channels and Bluetooth 5.4 [3], and the Wi-Fi 7 BE200 covers the same three bands with Bluetooth 5.4 [4].

INTEL-SA-00473 of May 2021 covers CVE-2020-24586, -24587 and -24588, the fragment cache, mixed key and frame aggregation attacks, across the AX210, AX201, AX200, 9560, 9260, 8265 and older PROSet/Wireless parts and the Killer AX1675, AX1650 and 1550 [5]. FCC grantee codes are not listed because the FCC ID databases refused the session that wrote this entry, and which laptop brands carry Intel modules is not stated in the sources consulted; nothing is filled in from memory. Randomization is the host operating system's behaviour and is unknown here.

## Sources
1. Intel - Wikipedia - https://en.wikipedia.org/wiki/Intel (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Intel Wi-Fi 6E AX210 (Gig+) specifications - https://www.intel.com/content/www/us/en/products/sku/204836/intel-wifi-6e-ax210-gig/specifications.html (accessed 2026-10-27)
4. Intel Wi-Fi 7 BE200 specifications - https://www.intel.com/content/www/us/en/products/sku/230078/intel-wifi-7-be200/specifications.html (accessed 2026-10-27)
5. INTEL-SA-00473 Intel PROSet/Wireless WiFi, Intel vPro CSME WiFi and Killer WiFi Advisory - https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00473.html (accessed 2026-10-27)
6. IEEE Registration Authority, MA-S assignments (oui36.csv) - https://standards-oui.ieee.org/oui36/oui36.csv (accessed 2026-10-27)
