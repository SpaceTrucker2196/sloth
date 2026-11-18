---
name: "Apple, Inc."
aliases: []
affiliates: []
country: US [1]
parent: independent (publicly traded) [1]
founded: 1976 [1]
kind: brand
device_classes: [phone, tablet, laptop, wearable, tv, speaker]
found_in: ["iPhone [1]", "iPad [1]", "Mac [1]", "Apple Watch [1]", "AirPods [1]", "Apple TV [1]", "HomePod [1]", "Vision Pro [1]"]
radios: ["Wi-Fi 7 (802.11be) 2x2 MIMO, iPhone 16 Pro [3]", "Wi-Fi 7 + Bluetooth 6 + Thread via N1, iPhone 17 [4]", "2.4 / 5 / 6 GHz: the bands 802.11be defines; the spec page names Wi-Fi 7 and does not itemise bands [3]", "BT Classic/BLE 5.3, iPhone 16 Pro [3]", "Thread/Zigbee (802.15.4) - Thread only [3]", "LTE/5G incl. mmWave n258/n260/n261, iPhone 16 Pro [3]", "UWB (second-generation Ultra Wideband chip) [3]", "NFC [3]"]
silicon: ["Apple N1 wireless networking chip (Wi-Fi 7, Bluetooth 6, Thread) in iPhone 17 [4]", "USI 339S01464 Bluetooth & Wi-Fi module (iFixit: 'likely') in iPhone 16 Pro [5]", "Qualcomm SDX71M-000 modem in iPhone 16 Pro [5]", "USI 339M00326 UWB module in iPhone 16 Pro [5]", "NXP NFC controller in iPhone 16 Pro [5]"]
fcc_grantee: []
randomization: "randomizes by default (iOS 14 / iPadOS 14 / visionOS, watchOS 7, macOS Sequoia 15 and later) [2]"
security_notes: ["Apple publishes a rolling security-releases catalogue with CVE detail; three iOS/iPadOS security releases were dated 26 Oct 2026 alone [6]", "CISA KEV carries Apple entries, e.g. CVE-2026-86950, an out-of-bounds write in CoreGraphics on iOS, iPadOS and macOS [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: documented}
researched: 2026-10-27
---
## Summary
Apple, Inc. is the consumer-electronics company founded in 1976 in Los Altos and now headquartered in Cupertino, California [1]; it designs the iPhone, iPad, Mac, Apple Watch, AirPods, Apple TV, HomePod and Vision Pro lines [1], so a MAC in one of its blocks is most likely a phone, tablet, laptop, watch, earbud case, set-top box or speaker rather than a module inside another brand's product. Apple holds 1594 MA-L blocks, by far the largest allocation in this research set [8]. Expect a modern Apple handset to carry Wi-Fi 7 (802.11be), Bluetooth 5.3, Thread, UWB, NFC and 5G including mmWave [3]; from iPhone 17 the Wi-Fi/Bluetooth/Thread radio is Apple's own N1 chip [4], while iPhone 16 Pro used a USI Wi-Fi/Bluetooth module and a Qualcomm SDX71M modem [5]. The on-air caveat that matters to an operator: since iOS 14 / watchOS 7 / macOS Sequoia 15 Apple devices use a different, private MAC per Wi-Fi network by default, with "Fixed" (stable per network) and "Rotating" (changes every two weeks) modes; Fixed is chosen by default on WPA2-or-stronger networks and Rotating on weak or open ones [2]. A private address is locally administered and will not resolve to an Apple OUI at all, so a frame that does carry an Apple OUI is either a pre-iOS 14 device, a device whose owner set Private Address to Off, or a wired/Ethernet interface, each of which is a reason to look twice. Apple publishes security releases continuously [6] and its products appear in CISA's Known Exploited Vulnerabilities catalogue [7]; patch level, not vendor, is the relevant risk variable. An FCC grantee code could not be verified from a reachable primary source in this session (fccid.io, fcc.report and apps.fcc.gov all refused automated fetches, and Apple's regulatoryinfo pages render client-side), so none is recorded.
## Sources
1. Apple Inc. - Wikipedia - https://en.wikipedia.org/wiki/Apple_Inc. (accessed 2026-10-27)
2. Use private Wi-Fi addresses on Apple devices - Apple Support - https://support.apple.com/en-us/102509 (accessed 2026-10-27)
3. iPhone 16 Pro - Technical Specifications - Apple Support - https://support.apple.com/en-us/121031 (accessed 2026-10-27)
4. Apple debuts iPhone 17 - Apple Newsroom - https://www.apple.com/newsroom/2025/09/apple-debuts-iphone-17/ (accessed 2026-10-27)
5. iPhone 16 Pro Chip ID - iFixit - https://www.ifixit.com/Teardown/iPhone+16+Pro+Chip+ID/177358 (accessed 2026-10-27)
6. Apple security releases - Apple Support - https://support.apple.com/en-us/100100 (accessed 2026-10-27)
7. Known Exploited Vulnerabilities Catalog (JSON feed) - CISA - https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (accessed 2026-10-27)
8. Apple, Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/apple-inc (accessed 2026-10-27)
