---
name: "Realme Chongqing Mobile Telecommunications Corp.,Ltd."
aliases: ["Realme Chongqing MobileTelecommunications Corp Ltd"]
affiliates: []
country: CN [1][2]
parent: Oppo, itself a BBK Electronics subsidiary [1]
founded: 2018 [1]
kind: brand
device_classes: [phone [1][3], tablet [1][3], wearable [1][3], laptop [1][3], tv [1][3]]
found_in: ["realme GT 7 Pro smartphone (Snapdragon 8 Elite) [4]", "realme Pad tablets, Book laptop, watches, earbuds and smart TVs [3]"]
radios: ["Wi-Fi 7 [4]", "2.4 GHz [4]", "5 GHz [4]", "BLE 4.x/5.x [4]", "LTE/5G [4]"]
silicon: ["Qualcomm Snapdragon 8 Elite in realme GT 7 Pro [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2023-38297: a preinstalled com.factory.mmigroup app on the Realme C25Y let zero-permission apps factory-reset the phone, leak its IMEI and serial number and enable Wi-Fi, Bluetooth and GPS [5]", "CVE-2025-25370: realme GT 2 (RMX3311) on realme UI 5.0 let a physically proximate attacker obtain sensitive information via the show app only setting [5]", "CVE-2025-57452: improper URI scheme handling in the realme BackupRestore app allowed local attackers a crash and potential XSS via crafted ADB intents [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

realme was founded on 4 May 2018 by Sky Li, who left Oppo to set it up as an independent brand; it is headquartered in Shenzhen and backed by Oppo, itself a BBK Electronics subsidiary, and in January 2026 announced it would be integrated into Oppo as a sub-brand [1]. It sells smartphones, tablets, earphones, smartwatches, laptops and smart TVs [1][3]. The IEEE registry lists 56 MA-L blocks to "Realme Chongqing Mobile Telecommunications Corp.,Ltd." and 6 more to "Realme Chongqing MobileTelecommunications Corp Ltd", all at Yubei District, Chongqing addresses [2].

A MAC in a realme block is most likely a realme phone [1][2]. The realme GT 7 Pro global model is documented with a Qualcomm Snapdragon 8 Elite, 802.11 a/b/g/n/ac/ax/be on 2.4 and 5 GHz, Bluetooth 5.4, 5G SA/NSA with LTE bands, and NFC [4].

Randomization is unknown: no source consulted states realme's default setting. An NVD keyword search for realme returns mostly RealMedia and RealPlayer issues, but also CVE-2023-38297, a preinstalled factory app on the Realme C25Y that let any app factory-reset the phone, leak its IMEI and serial number and switch on Wi-Fi, Bluetooth and GPS, and two local flaws in realme software, CVE-2025-25370 on the GT 2 and CVE-2025-57452 in the BackupRestore app [5]. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry, and iFixit has no realme teardown [6]; nothing is filled in from memory.

## Sources
1. Realme - Wikipedia - https://en.wikipedia.org/wiki/Realme (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. realme Global site - https://www.realme.com/global/ (accessed 2026-10-27)
4. realme GT 7 Pro specifications - realme - https://www.realme.com/global/realme-gt-7-pro/specs (accessed 2026-10-27)
5. NVD CVE API, keyword realme - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=realme (accessed 2026-10-27)
6. iFixit guide search, realme teardown - https://www.ifixit.com/api/2.0/search/Realme%20teardown?filter=guide (accessed 2026-10-27)
