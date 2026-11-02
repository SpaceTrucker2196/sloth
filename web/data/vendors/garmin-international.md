---
name: Garmin International
aliases: []
country: US [1]
parent: "Garmin Ltd. (legal domicile Schaffhausen, Switzerland since 2010; operational HQ Olathe, Kansas) [1]"
founded: 1989 [1]
kind: brand
device_classes: [wearable, automotive-infotainment, iot-sensor]
found_in: ["Garmin smartwatches, fitness trackers and sports watches (Forerunner, Fenix, etc.) [1][6][7]", "Aviation avionics (G1000, Autoland), marine chartplotters/fishfinders, automotive infotainment units and domain controllers, cameras [1]", "ANT+ fitness sensors (heart-rate monitors, pedometers, speed sensors, weight scales) [5]"]
radios: ["BLE: on Garmin watches since the Forerunner 220/620 (2013) [6]", "ANT+ at 2.4 GHz (Garmin-owned via Dynastream, bought 2006) [5]", "2.4 GHz (ANT+ and BLE) [5][6]", "Wi-Fi (generation and band not stated) on the Forerunner 920XT for automatic activity upload [6]", "LTE: Fenix 8 Pro (inReach satellite + LTE) [7]", "GNSS (GPS) across the product line [1]"]
silicon: ["'Sifter IV' GNSS chipset in Forerunner 910XT (2012) [6]"]
fcc_grantee: []
randomization: unknown
security_notes: ["23 July 2020 ransomware attack encrypted Garmin's internal network and some production systems, taking Garmin Connect offline for days; Garmin said there was no indication personal data was stolen [1]", "CVE-2020-27483 to CVE-2020-27486: Connect IQ TVM array-index, integer-overflow and buffer-overflow bugs in Forerunner 235 before 8.20, exploitable via a malicious Connect IQ app [8]", "CVE-2023-23303 to CVE-2023-23306 and others: GarminOS TVM / Connect IQ API 1.0.0-4.1.7 buffer overflows, permission bypass (Toybox.SensorHistory) and type confusion (Toybox.Ant.BurstPayload) [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Garmin International is the Olathe, Kansas operating subsidiary of Garmin Ltd., founded in October 1989 in Lenexa, Kansas by Gary Burrell and Min Kao and re-domiciled to Schaffhausen, Switzerland in 2010; the group builds GPS products for wearables, aviation, marine, automotive and fitness, with 2025 revenue of USD 7.25 billion and about 23,000 employees [1]. The registrant holds 15 MA-L blocks registered between 2001 and 2026 [10]. On a home or office network a Garmin MAC is most likely a watch or fitness device; on a boat or in a vehicle it can be a marine unit or an infotainment head unit, since Garmin supplies infotainment units and domain controllers to vehicle makers [1]. Most of Garmin's radio traffic is Bluetooth Low Energy, on watches since the Forerunner 220/620 of 2013 [6], and the Garmin-owned ANT+ protocol, both in the 2.4 GHz band [5]; Wi-Fi, where present, arrived on watches with the Forerunner 920XT for automatic activity upload, with no generation or band stated in the sources reached [6], while the Fenix 8 Pro adds LTE alongside inReach satellite messaging [7]. The only chipset a source names is Garmin's own "Sifter IV" GNSS part in the 2012 Forerunner 910XT [6]; the Bluetooth/Wi-Fi silicon in current watches is not documented in anything reached in this session, and no statement on MAC randomization was found. Garmin's FCC grantee code and per-product filings are not recorded because fccid.io returned HTTP 403 for every page fetched in this session. Security history is the 23 July 2020 ransomware attack that took Garmin Connect offline [1] and a series of Connect IQ virtual-machine CVEs (2020 on Forerunner 235, 2023 across Connect IQ API versions up to 4.1.7) that require a malicious watch app to be installed [8][9].
## Sources
1. Garmin - Wikipedia - https://en.wikipedia.org/wiki/Garmin (accessed 2026-10-27)
2. Garmin International Inc FCC ID Applications (IPH) - fccid.io - https://fccid.io/IPH (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
3. FCC ID IPH-A5220 - Fitness Product - fccid.io - https://fccid.io/IPH-A5220 (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
4. FCC ID IPH-A5231 - Portable Digital Transceiver - fccid.io - https://fccid.io/IPH-A5231 (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
5. ANT (network) - Wikipedia - https://en.wikipedia.org/wiki/ANT_(network) (accessed 2026-10-27)
6. Garmin Forerunner - Wikipedia - https://en.wikipedia.org/wiki/Garmin_Forerunner (accessed 2026-10-27)
7. Garmin Fenix - Wikipedia - https://en.wikipedia.org/wiki/Garmin_Fenix (accessed 2026-10-27)
8. CVE search garmin / forerunner_235_firmware - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/garmin/forerunner_235_firmware (accessed 2026-10-27)
9. CVE search garmin / connect-iq - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/garmin/connect-iq (accessed 2026-10-27)
10. Garmin International MAC address blocks - maclookup.app - https://maclookup.app/vendors/garmin-international (accessed 2026-10-27)
