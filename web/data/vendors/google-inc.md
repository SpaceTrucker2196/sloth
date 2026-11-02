---
name: Google, Inc.
aliases: []
country: US [1]
parent: "Alphabet Inc. (since the 2015 reorganisation) [1]"
founded: 1998 [1]
kind: brand
device_classes: [phone, wearable, speaker, tv, camera, smart-home, ap/router, laptop]
found_in: ["Pixel phones (since 2016) [1]", "Pixel 9 / 9 Pro / 9 Pro XL (2024) [4]", "Nest Wifi (2019) and Nest Wifi Pro (2022) routers [5]", "Chromecast, all generations 2013-2024 [6]", "Google Home / Nest Mini / Nest Audio / Nest Hub speakers and displays [7]", "Pixel Watch (2022) [8]", "Pixel Buds (2017-2025) [9]", "Nest thermostats, Protect, Cam, Doorbell, Nest x Yale lock [10]", "Fitbit trackers and smartwatches (Google-owned since January 2021) [11]", "Chromebooks [1]"]
radios: ["Wi-Fi 7 (802.11be) in Pixel 9 [4]", "Wi-Fi 6E (AXE5400) in Nest Wifi Pro [5]", "Wi-Fi 5 (802.11ac dual-band) in Chromecast gen 2 onward, Nest speakers and Nest Wifi [5][6][7]", "Wi-Fi 4 2.4 GHz only in Chromecast gen 1 and Pixel Watch (802.11b/g/n) [6][8]", "2.4 GHz [6][8]", "5 GHz [6][7]", "6 GHz (Wi-Fi 6E Nest Wifi Pro; Wi-Fi 7 Pixel 9) [4][5]", "BT Classic / BLE 5.3 in Pixel 9 [4]", "BLE 4.2 in Chromecast with Google TV, 5.0 in Pixel Watch, 5.4 in Pixel Buds 2a [6][8][9]", "Thread/Zigbee (802.15.4): Thread in Pixel 9, Nest Wifi (Thread 1.2), Nest Wifi Pro (Thread 1.4), Nest Hub Max [4][5][7]", "UWB in Pixel 9 Pro / Pro XL [4]", "LTE/5G in Pixel phones (5G in Pixel 9) and the Pixel Watch LTE variant [4][8]", "NFC in Pixel Watch [8]"]
silicon: ["Google Tensor G4 SoC with Samsung Exynos 5400 modem in Pixel 9 [4]", "Qualcomm QCS404 (router) / QCS405 (point) in Nest Wifi [5]", "Qualcomm IPQ5018 in Nest Wifi Pro [5]", "Marvell Armada 1500 Mini 88DE3005 / Mini Plus 88DE3006 in Chromecast gen 1-3 and Audio [6]", "Amlogic S905D3 in Chromecast with Google TV 4K and Nest Hub 2nd gen [6][7]", "Amlogic S805X2 in Chromecast with Google TV HD [6]", "Marvell 88DE3006 in Google Home and Home Mini; Synaptics AS-370 in Nest Mini and Nest Audio [7]", "Samsung Exynos 9110 with Cortex-M33 co-processor in Pixel Watch [8]", "Google Tensor A1 in Pixel Buds Pro 2 and Pixel Buds 2a [9]"]
fcc_grantee: []
randomization: "mixed: Pixel phones and other Android 10+ devices randomize per SSID by default, while no public statement was found for Nest, Chromecast or Pixel Watch [12]"
security_notes: ["Monthly Pixel Update Bulletins supplement the Android Security Bulletins for Pixel devices [13]", "CVE-2023-6339: Google Nest WiFi Pro root code-execution and user-data compromise [15]", "CVE-2025-36939: OpenThread MLE packet handling denial of service, listed against Nest Wifi Pro firmware [15]", "CVE-2023-48418: Pixel Watch allowed adb access before setup-wizard completion (local privilege escalation) [16]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: inferred}
researched: 2026-10-27
---
## Summary
Google, Inc. is the Mountain View, California company founded in 1998 and reorganised under Alphabet Inc. in 2015; its hardware lines are Pixel phones (since 2016), Pixel Watch, Pixel Buds, Nest smart-home devices including Nest Wifi routers, Chromecast (2013-2024) and Chromebooks [1], plus Fitbit wearables since the January 2021 acquisition [11]. The IEEE registrant holds 113 MA-L blocks [14], so a MAC in a Google block is most often a Pixel phone, but it can equally be a Nest speaker, Nest Hub, Chromecast, Nest Wifi router or Pixel Watch [5][6][7][8]. On the air, expect current Pixel phones to be Wi-Fi 7 with Bluetooth 5.3, Thread and, on Pro models, UWB [4]; Nest Wifi Pro is Wi-Fi 6E and so also uses the 6 GHz band [5]; older Nest/Chromecast hardware is 802.11ac dual-band or, for first-generation Chromecast and Pixel Watch, 2.4 GHz 802.11b/g/n only [6][8]. Because Android 10 and later randomize the Wi-Fi MAC per SSID by default [12], a Pixel phone will normally show a locally-administered address on networks it joins and its Google OUI appears mainly on networks where the owner disabled randomization, in Bluetooth, or in the infrastructure-side devices (Nest Wifi, Chromecast, Nest speakers) whose randomization behaviour is not publicly documented. Documented silicon includes Google's own Tensor G4 (with a Samsung Exynos 5400 modem) in Pixel 9 [4], Qualcomm QCS404/405 and IPQ5018 in Nest Wifi and Nest Wifi Pro [5], Marvell Armada 1500 and Amlogic S905D3/S805X2 in Chromecast generations [6], and Synaptics AS-370 in Nest Mini/Audio [7]; the discrete Wi-Fi/Bluetooth combo chips were not identified in any source reached in this session. Google's FCC grantee code and per-product filings are not recorded because fccid.io returned HTTP 403 for every page fetched in this session. Security-relevant: Pixel devices receive monthly bulletins [13], while Nest Wifi Pro has a published root code-execution CVE (CVE-2023-6339) and an OpenThread MLE denial-of-service CVE (CVE-2025-36939) [15], and the original Pixel Watch had a pre-setup adb exposure (CVE-2023-48418) [16].
## Sources
1. Google - Wikipedia - https://en.wikipedia.org/wiki/Google (accessed 2026-10-27)
2. Google LLC FCC ID Applications (A4R) - fccid.io - https://fccid.io/A4R (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
3. FCC ID A4RGUJ0N - Phone - fccid.io - https://fccid.io/A4RGUJ0N (accessed 2026-10-27) (not reachable 2026-10-27, HTTP 403)
4. Pixel 9 - Wikipedia - https://en.wikipedia.org/wiki/Pixel_9 (accessed 2026-10-27)
5. Google Nest Wifi - Wikipedia - https://en.wikipedia.org/wiki/Google_Nest_Wifi (accessed 2026-10-27)
6. Chromecast - Wikipedia - https://en.wikipedia.org/wiki/Chromecast (accessed 2026-10-27)
7. Google Nest (smart speakers) - Wikipedia - https://en.wikipedia.org/wiki/Google_Nest_(smart_speakers) (accessed 2026-10-27)
8. Google Pixel Watch - Wikipedia - https://en.wikipedia.org/wiki/Google_Pixel_Watch (accessed 2026-10-27)
9. Pixel Buds - Wikipedia - https://en.wikipedia.org/wiki/Pixel_Buds (accessed 2026-10-27)
10. Google Nest - Wikipedia - https://en.wikipedia.org/wiki/Google_Nest (accessed 2026-10-27)
11. Fitbit - Wikipedia - https://en.wikipedia.org/wiki/Fitbit (accessed 2026-10-27)
12. MAC randomization behavior - Android Open Source Project - https://source.android.com/docs/core/connect/wifi-mac-randomization (accessed 2026-10-27)
13. Pixel Update Bulletins - Android Open Source Project - https://source.android.com/docs/security/bulletin/pixel (accessed 2026-10-27)
14. Google, Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/google-inc (accessed 2026-10-27)
15. CVE search google / nest_wifi_pro_firmware - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/google/nest_wifi_pro_firmware (accessed 2026-10-27)
16. CVE search google / pixel_watch_firmware - CIRCL vulnerability-lookup API - https://cve.circl.lu/api/search/google/pixel_watch_firmware (accessed 2026-10-27)
