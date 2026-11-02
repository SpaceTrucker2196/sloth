---
name: Wyze Labs Inc
aliases: []
country: US [1][2]
parent: independent (privately held; no parent or acquisition recorded) [1]
founded: 2017 [1]
kind: brand
device_classes: [camera, smart-home, iot-sensor]
found_in: ["Wyze Cam v2 (model WYZEC1-JZ) [10]", "Wyze Cam v3 (model WYZE_CAKP2JFUS) [10]", "Wyze Cam Pan v2 (HL_PAN2) [4][10]", "Wyze Cam V4 Pro [4]", "Wyze Video Doorbell v2 (T31X) [6]", "Roku Indoor Camera SE (shares the Wyze Cam v3 flaw CVE-2023-6322) [4]", "wyze-cam in a university IoT lab inventory on 7C:78:B2 [11]"]
radios: ["Wi-Fi (Realtek Wi-Fi kernel module in Cam v3) [5]", "Bluetooth (setup channel on Cam V4 Pro, CVE-2024-37066) [4]"]
silicon: ["Ingenic T31 (T31X) in Wyze Video Doorbell v2 [6]", "Ingenic T20/T31 across the Wyze cameras supported by wz_mini_hacks (Cam v2, Cam v3, Cam Pan v2) [9][10]", "Realtek Wi-Fi (kernel driver) in Wyze Cam v3 [5]"]
fcc_grantee: []
randomization: fixed (inferred: Wyze cloud used the device MAC as a sole credential, CVE-2024-6248) [7]
security_notes: ["Dec 2019 server leak exposing ~2.4M customers' details [1]", "Sept 2023 and Feb 2024 incidents showing users other customers' camera feeds (~13,000 affected in 2024) [1]", "CVE-2019-9564 auth bypass and CVE-2019-12266 stack overflow in Cam v1/v2/v3; v1 discontinued unpatched (Bitdefender, 2022) [4][8]", "CVE-2024-6246 Realtek Wi-Fi driver heap overflow, CVE-2024-6247 QR-code SSID command injection, CVE-2024-6248 MAC-as-credential cloud auth bypass, CVE-2024-6249 TUTK P2P stack overflow in Cam v3 [4][5][7]", "CVE-2024-37066 Bluetooth command injection during Cam V4 Pro setup [4]", "CVE-2026-50720 Ingenic T31 boot-ROM signature check weakness demonstrated on Video Doorbell v2 [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Wyze Labs is a Kirkland, Washington consumer smart-home brand incorporated in Seattle on 19 July 2017 by Yun Zhang, Dongsheng Song, Dave Crosby and Elana Fishman, privately held, selling security cameras, video doorbells, bulbs, plugs, sensors, locks, thermostats and robot vacuums [1][2]. It holds five MA-L blocks plus one MA-M block in the IEEE registry copy shipped with sloth, all under the single name "Wyze Labs Inc" at Kirkland and Bothell, Washington [12][13]. A MAC in these blocks is most likely a Wyze camera or doorbell; the camera line is built on Ingenic T20/T31 MIPS SoCs, and the Cam v3 uses a Realtek Wi-Fi chip whose kernel driver carried a heap-overflow RCE reachable by a network-adjacent attacker (CVE-2024-6246) [5][6][9]. Expect a fixed MAC: Wyze's own cloud used the camera MAC as the sole authentication credential (CVE-2024-6248), which only works for a stable address [7]. The security record is long and operator-relevant: two feed-mixup incidents (2023, 2024), a 2019 data leak, the still-unpatched Cam v1, and a 2024 batch of Cam v3 flaws, so isolating these cameras on their own segment is reasonable [1][4][8]. Wyze's own Wi-Fi band and the FCC grantee code are not documented in the sources reachable for this entry (the FCC ID databases refused automated access), so fcc_grantee is left empty rather than recalled; the Wireshark manuf fetch came back truncated, so the block count is read from the registry copy in the repository.
## Sources
1. Wyze Labs - Wikipedia - https://en.wikipedia.org/wiki/Wyze_Labs (accessed 2026-10-27)
2. maclookup.app 2C:AA:8E registrant record - https://maclookup.app/macaddress/2CAA8E (accessed 2026-10-27)
3. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27) (does not support the claim: the fetch returned a truncated file with no Wyze lines; sources 12-13 carry the blocks)
4. NVD CVE API, keyword "wyze" (9 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=wyze&resultsPerPage=20 (accessed 2026-10-27)
5. NVD CVE-2024-6246 (Wyze Cam v3 Realtek Wi-Fi driver heap overflow) - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6246 (accessed 2026-10-27)
6. NVD CVE-2026-50720 (Ingenic T31 boot ROM, Wyze Video Doorbell v2 T31X) - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-50720 (accessed 2026-10-27)
7. NVD CVE-2024-6248 (Wyze Cam v3 MAC address as sole credential) - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-6248 (accessed 2026-10-27)
8. Bitdefender Labs, "Vulnerabilities Identified in Wyze Cam IoT Device" - https://www.bitdefender.com/blog/labs/vulnerabilities-identified-in-wyze-cam-iot-device/ (accessed 2026-10-27)
9. wz_mini_hacks README ("Ingenic based T20/T31 based devices only") - https://github.com/gtxaspec/wz_mini_hacks (accessed 2026-10-27)
10. wz_mini_hacks wiki, Firmware Support table - https://github.com/gtxaspec/wz_mini_hacks/wiki/Firmware-Support (accessed 2026-10-27)
11. NEU-SNS iot-ipv6 lab device list (7c:78:b2 wyze-cam) - https://github.com/NEU-SNS/iot-ipv6/blob/main/dest-analysis/devices-ipv6-mac.txt (accessed 2026-10-27)
12. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
13. IEEE Registration Authority MA-M public listing (mam.csv; read from the copy shipped in sloth web/data/mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
