---
name: ecobee inc
aliases: []
affiliates: []
country: CA [1][2]
parent: Generac Holdings (acquisition agreed November 2021, closed December 2021) [2]
founded: 2007 [2]
kind: brand [2]
device_classes: [smart-home [2], iot-sensor [2], camera [2]]
found_in: ["ecobee smart thermostats, from the first in 2008 to the Smart Thermostat Premium [2][3]", "ecobee room and occupancy sensors and SmartSensor contact sensors [2]", "ecobee Switch+ light switch, SmartCamera and Smart Doorbell camera [2]"]
radios: ["2.4 GHz (Smart Thermostat Premium) [3]", "5 GHz (Smart Thermostat Premium) [3]", "BLE 4.x/5.x (Bluetooth 5.0 LE, Smart Thermostat Premium) [3]", "915 MHz radio (Smart Thermostat Premium) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2018-6402: ecobee4 4.2.0.171 can be forced off WPA2 onto an unencrypted network with the same SSID (evil twin) [4]", "CVE-2021-27952: hardcoded default root credentials on the ecobee3 lite 4.5.81.200 bootloader serial console [5]", "CVE-2021-27953 and CVE-2021-27954: NULL pointer dereference and heap overflow in the ecobee3 lite HomeKit Wireless Access Control setup [6][7]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

ecobee is a Toronto home automation company founded in 2007 by Stuart Lombard, Mark Malchiondo and John Metselaar; it released its first smart thermostat in 2008, and Generac Holdings agreed to buy it for 770 million dollars in November 2021, closing in December 2021 [2]. Its products include smart thermostats, room and occupancy sensors, the Switch+ light switch, the SmartCamera, SmartSensor contact sensors and a Smart Doorbell camera [2]. The IEEE registry lists one MA-L block to "ecobee inc" at 333 Adelaide St W, Toronto [1].

A MAC in this block is most likely an ecobee thermostat, sensor or camera on the home Wi-Fi [2]. A dealer specification for the Smart Thermostat Premium lists dual-band Wi-Fi (802.11 b/g/n at 2.4 GHz, a/n/ac at 5 GHz), Bluetooth 5.0 with LE, WPA3 support and a 915 MHz radio [3].

NVD records an evil-twin downgrade in the ecobee4 that pulls it off WPA2 onto an unencrypted network with the same SSID [4], and three 2021 flaws in the ecobee3 lite: hardcoded bootloader root credentials and two bugs in its HomeKit Wireless Access Control setup, one forcing a reboot and one able to force it onto an attacker's SSID [5][6][7]. No teardown naming the silicon and no randomization documentation was found, and the FCC ID databases could not be consulted, so no grantee code is listed [2][3].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Ecobee - Wikipedia - https://en.wikipedia.org/wiki/Ecobee (accessed 2026-10-27)
3. ecobee Smart Thermostat Premium EB-STATE6P-01 - Snap One - https://snapav.com/shop/en/snapav/eb-state6p-01 (accessed 2026-10-27)
4. CVE-2018-6402 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2018-6402 (accessed 2026-10-27)
5. CVE-2021-27952 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-27952 (accessed 2026-10-27)
6. CVE-2021-27953 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-27953 (accessed 2026-10-27)
7. CVE-2021-27954 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2021-27954 (accessed 2026-10-27)
