---
name: LG Electronics
aliases: [LG ELECTRONICS, LG Electronics Inc., LG ELECTRONICS INC, LG Electronics (Mobile Communications)]
country: KR [1][2]
parent: LG Corporation (about 33 percent) [2]
founded: 1958 [2]
kind: brand [2]
device_classes: [tv [2][3], phone [2], laptop [2], speaker [2]]
found_in: ["LG webOS smart TVs, e.g. OLED55A3PSA [3]", "LG mobile phones (business exited 2021) [2]", "LG home appliances, laptops, monitors and soundbars [2]"]
radios: ["Wi-Fi 5 (OLED55A3PSA) [3]", "Bluetooth 5.0 (OLED55A3PSA) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2023-6317: prompt bypass in the secondscreen.gateway service on webOS 4 through 7 [4]", "Tens of thousands of webOS 4 to 7 smart TVs had takeover bugs disclosed April 2024, patched by LG 2024-03-22 [2]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

LG Electronics was founded in October 1958 as GoldStar, renamed in 1995, and is headquartered at the LG Twin Tower in Seoul; LG Corporation owns about 33 percent of it [2]. The registry spells the company several ways: LG Electronics (Mobile Communications) alone holds 77 MA-L blocks at a Geumcheon-gu, Seoul address, LG Electronics another 28, and LG ELECTRONICS INC six at Pyeongtaek [1].

LG makes televisions and soundbars, home appliances, air conditioning, laptops and monitors, EV components and telematics; it left the mobile phone business in 2021 [2]. Given that registry name and the 2021 exit, a MAC in the Mobile Communications blocks is most likely an older LG phone, while one in the other blocks is more likely a webOS smart TV or another LG product [1][2]. LG's OLED55A3PSA, for example, runs webOS 23 with Wi-Fi 5 and Bluetooth 5.0 [3].

webOS versions 4 to 7 carried a prompt bypass in the secondscreen.gateway service (CVE-2023-6317) [4], one of the bugs a security firm disclosed in April 2024 that let attackers take over tens of thousands of LG TVs; LG patched them on 22 March 2024 [2]. Silicon and the FCC grantee code are not listed: the module documentation and FCC ID databases refused this session's requests. No source in hand documents MAC randomization for LG TVs or phones, so it is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. LG Electronics - Wikipedia - https://en.wikipedia.org/wiki/LG_Electronics (accessed 2026-10-27)
3. LG OLED55A3PSA specifications - LG Singapore - https://www.lg.com/sg/tvs-soundbars/lg-oled55a3psa (accessed 2026-10-27)
4. CVE-2023-6317 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2023-6317 (accessed 2026-10-27)
