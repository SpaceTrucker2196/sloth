---
name: "Panasonic Automotive Systems Co.,Ltd"
aliases: [Panasonic Automotive Systems]
affiliates: ["Panasonic Automotive Systems Asia Pacific(Thailand)Co.,Ltd. [8]", "PANASONIC AUTOMOTIVE SYSTEM MALAYSIA [8]"]
country: JP [1][3]
parent: Apollo Global Management funds (80%) with Panasonic Holdings (20%), since the 2024 share transfer [3]
founded: 2022 [1][3]
kind: automotive
device_classes: [automotive-infotainment [4]]
found_in: ["2026 Toyota RAV4 in-vehicle infotainment (Arene-integrated IVI with wireless Apple CarPlay / Android Auto, Bluetooth audio and OTA updates) [4]", "All-new Mazda CX-5 cockpit domain controller (three synchronized displays, OTA orchestrator) [5]", "Nissan all-new Elgrand (Japan, X and G grades) integrated active noise control in the standard audio system [7]"]
radios: ["Bluetooth (audio in the Toyota RAV4 IVI; version and Classic/BLE not stated) [4]", "Wi-Fi, generation and bands not stated (implied by the RAV4 IVI's wireless Apple CarPlay / Android Auto) [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Panasonic Automotive Systems Co., Ltd. (PAS) is the Yokohama-based automotive Tier 1 that was carved out of Panasonic in April 2022 when Panasonic Holdings moved to a holding structure; on 29 March 2024 Panasonic Holdings agreed to sell 80% to funds advised by Apollo, keeping 20%, and the company will rename itself Mobitera Inc. on 1 April 2027 [1][3][10]. Its business is in-vehicle cockpit systems, ADAS-related systems and devices, and xEV-related systems and devices; the lineage goes back to Panasonic car radios in 1939, the first car radios delivered to an automaker (Isuzu) in 1954, the first navigation unit supplied to an automaker in 1992 and the Nissan Leaf's in-vehicle charging system in 2012 [1][2]. The IEEE registry lists MA-L blocks to the parent (54:5B:86, 74:D7:CA, B0:D8:88, CC:57:63) and further blocks to its America, Thailand and Malaysia subsidiaries [8]; given the business, a MAC in one of them is a vehicle head unit or cockpit module, which is an inference from the product line [1], not a documented mapping. Recent sourced wins are the 2026 Toyota RAV4 IVI (wireless CarPlay/Android Auto, Bluetooth audio, OTA updates through Toyota's Arene platform), the Mazda CX-5 cockpit domain controller and Nissan's Elgrand integrated noise control [4][5][7]. On the air the RAV4 IVI pairs phones over Bluetooth and, by implication of its wireless phone projection, carries Wi-Fi, but no source reached states the Wi-Fi generation, bands, chipset or FCC grantee: every fccid.io page cited for this entry (grantees WUQ, 2BS75, 2BW23, 2BW7I and the Japan Giteki record for a Murata-module multimedia unit) returned HTTP 403 on verification, so those claims were removed rather than kept on recollection [4]. PAS is an Automotive Grade Linux board member and leads its SDV expert group, with Honda, Mazda, Nissan, Toyota, AWS, Qualcomm and Telechips among the endorsers of its VirtIO standardisation push [6]. PAS runs an "Automotive Cyber Security" programme [10], and no CVE names the company [9].
## Sources
1. Panasonic Automotive Systems - Corporate Profile - https://automotive.panasonic.com/en/corporate/about/overview (accessed 2026-10-27)
2. Panasonic Automotive Systems - Our History - https://automotive.panasonic.com/en/corporate/about/history (accessed 2026-10-27)
3. Japanese Wikipedia - パナソニック オートモーティブシステムズ (establishment 2022-04-01; Apollo 80% share transfer agreed 2024-03-29; Mobitera rename) - https://ja.wikipedia.org/wiki/%E3%83%91%E3%83%8A%E3%82%BD%E3%83%8B%E3%83%83%E3%82%AF%E3%82%AA%E3%83%BC%E3%83%88%E3%83%A2%E3%83%BC%E3%83%86%E3%82%A3%E3%83%96%E3%82%B7%E3%82%B9%E3%83%86%E3%83%A0%E3%82%BA (accessed 2026-10-27)
4. Panasonic Newsroom - Toyota Motor Corporation adopts Panasonic Automotive Systems' in-vehicle infotainment system in its new RAV4 - https://news.panasonic.com/global/press/en260319-4 (accessed 2026-10-27)
5. Panasonic Newsroom - Mazda Selects Panasonic Automotive Systems' Cockpit Domain Controller for All-New CX-5 - https://news.panasonic.com/global/press/en260707-2 (accessed 2026-10-27)
6. Panasonic Newsroom - Panasonic Automotive Systems secures industry-wide endorsement for VirtIO standardization - https://news.panasonic.com/global/press/en260224-2 (accessed 2026-10-27)
7. PAS Newsroom - integrated ANC system first adopted in Nissan's all-new Elgrand - https://automotive.panasonic.com/en/newsroom/20260918-1 (accessed 2026-10-27)
8. Wireshark manuf OUI database (Panasonic Automotive Systems blocks) (the fetch on 2026-10-27 returned a truncated file; the blocks were checked against the IEEE listing shipped in sloth web/data/oui.csv) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
9. NVD CVE API keyword search "Panasonic Automotive" (0 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Panasonic%20Automotive (accessed 2026-10-27)
10. Panasonic Automotive Systems home page (Mobitera rename notice; Automotive Cyber Security section) - https://automotive.panasonic.com/en (accessed 2026-10-27)
