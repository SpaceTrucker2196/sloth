---
name: Pittasoft
aliases: []
country: KR [1][4]
parent: unknown
founded: 2007 [3][4]
kind: brand [4]
device_classes: [camera [4], automotive-telematics [4]]
found_in: ["BlackVue dashcams, including the DR500GW-HD, DR900X and ELITE 9 series [3][5][6]"]
radios: ["Wi-Fi 5 [5][6]", "2.4 GHz [6]", "5 GHz [6]", "BT Classic (V2.1+EDR) [5][6]", "Bluetooth 4.2 (DR900X) and 5.3 (ELITE 9) [5][6]", "LTE (optional external module) [5][6]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2025-7075: unauthenticated file upload at /upload.cgi on BlackVue Dashcam 590X up to firmware 20250624, reachable from the dashcam's local network [2][7]", "CVE-2025-7076: unauthenticated configuration change on BlackVue Dashcam 590X up to 20250624 [7][8]", "CVE-2025-2355: hard-coded secrets in the BlackVue v3.65 Android app; CVE-2025-2356: user token sent as a GET parameter to the BlackVue API [7]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Pittasoft is the South Korean maker of BlackVue dashboard cameras, headquartered in Seoul and established in 2007 [4]; its own 2013 release dates the dashcam business to July 2007 [3]. The IEEE registry gives Pittasoft one MA-L block, 00-25-42, at a Geumcheon-gu, Seoul address [1]. A MAC in this block is most likely a BlackVue dashcam, which pairs with a phone app over Wi-Fi and, on Internet-connected models, reports to the BlackVue cloud service [3][4].

Current models carry 802.11a/b/g/n/ac Wi-Fi on 2.4 and 5 GHz and Bluetooth (V2.1+EDR with 4.2 on the DR900X, 5.3 on the ELITE 9), with LTE only through an optional external module [5][6]. The DR900X-1CH and ELITE 9 specifications list GPS and GLONASS as well [5][6].

In 2025 a researcher published unauthenticated file upload (CVE-2025-7075) and unauthenticated configuration change (CVE-2025-7076) flaws in the BlackVue Dashcam 590X, both requiring access to the dashcam's own network, plus two flaws in the BlackVue app and its API [2][7][8]. Silicon, randomization and FCC grantee codes are not listed: no teardown was found, and the FCC ID databases refused fetches from this session.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. CVE-2025-7075 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2025-7075 (accessed 2026-10-27)
3. Pittasoft Launched Full HD Wi-Fi Dashboard Camera BlackVue Wi-Fi DR500GW-HD - 24-7 Press Release - https://www.24-7pressrelease.com/press-release/335128/pittasoft-launched-full-hd-wi-fi-dashboard-camera-blackvue-wi-fi-dr500gw-hd (accessed 2026-10-27)
4. Pittasoft press release - Business Wire China - https://www.businesswirechina.com/en/news/30074.html (accessed 2026-10-27)
5. DR900X-1CH product specifications - BlackVue manual - https://manual.blackvue.com/docs/dr900x-1ch/product-specifications/product-specifications-dr900x-1ch/ (accessed 2026-10-27)
6. ELITE 9 product specifications - BlackVue manual - https://manual.blackvue.com/docs/elite-9-series/technical-specifications/product-specifications-3/ (accessed 2026-10-27)
7. geo-chen/BlackVue vulnerability write-up - GitHub - https://github.com/geo-chen/BlackVue (accessed 2026-10-27)
8. CVE-2025-7076 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2025-7076 (accessed 2026-10-27)
