---
name: Belkin International Inc.
aliases: []
affiliates: []
country: US [1][3]
parent: "Foxconn Interconnect Technology (acquired Belkin September 2018 for $866 million) [1]"
founded: 1983 [1]
kind: brand
device_classes: [smart-home, ap/router]
found_in: ["Wemo Mini Smart Plug V2 F7C063 [5][6]", "Wemo smart-home line (launched 2012) [1]", "Belkin F9K1113 v4 dual-band 802.11ac router [4]", "Wemo Thread-based devices WLS0503, WSC010, WSP100, WDC010 [7]"]
radios: ["Wi-Fi 4, 2.4 GHz (MT7688AN in F7C063) [5]", "Wi-Fi 5, 2.4 GHz + 5 GHz 2x2 (F9K1113 v4) [4]", "Thread/Zigbee (802.15.4) (four Thread-enabled Wemo models) [7]"]
silicon: ["MediaTek MT7688AN SoC with integrated 2.4 GHz Wi-Fi in Wemo Mini Smart Plug V2 F7C063 [5]", "Realtek RTL8197D SoC + RTL8812AR (5 GHz ac 2x2) + RTL8192CE (2.4 GHz n 2x2) in F9K1113 v4 [4]"]
fcc_grantee: ["K7S (e.g. FCC ID K7SF9K1117V2) [4]"]
randomization: unknown
security_notes: ["CVE-2023-27217: stack buffer overflow in ChangeFriendlyName() reachable via UPnP on Wemo Smart Outlet V2 F7C063 firmware 2.00.11420, CVSS 3.1 9.8; Belkin declared the device end-of-life and declined to patch (2023-02-22) [5][6]", "Wemo cloud service and app shut down 2026-01-31; 33 product SKUs lose app and third-party control, 11 HomeKit-configured models keep working locally, four Thread models are unaffected [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Belkin International is a consumer-electronics brand founded on 18 April 1983 and headquartered in El Segundo, California; Foxconn Interconnect Technology bought it in September 2018 for $866 million [1]. It launched the Wemo smart-home line in 2012, bought Linksys from Cisco in March 2013 (Linksys has been a subsidiary of Foxconn Interconnect Technology and Fortinet since 2021), and co-founded the Phyn water-monitoring venture with Uponor in 2016 [1], so the Belkin OUIs cover Belkin-branded gear rather than Linksys routers. The IEEE registry holds 18 MA-L blocks for "Belkin International Inc." registered from February 2006 to March 2023 [2], at a Playa Vista, California address [3]. On a home network a MAC in one of these blocks is most often a Wemo plug, switch or sensor, or an older Belkin router: the Wemo Mini Smart Plug V2 (F7C063) is a MediaTek MT7688AN running OpenWrt with 2.4 GHz-only Wi-Fi [5], while the F9K1113 v4 router is Realtek RTL8197D with RTL8812AR/RTL8192CE dual-band radios, FCC ID K7SF9K1117V2 under grantee code K7S [4]. Security posture is poor for the legacy fleet: CVE-2023-27217 (CVSS 9.8, UPnP-reachable stack overflow) went unpatched because Belkin called the F7C063 end-of-life [5][6], and on 31 January 2026 the Wemo cloud and app were shut down, leaving 33 SKUs without app control and 11 HomeKit-configured models working only locally [7]. A Wemo seen chattering on the network after that date is either a HomeKit-local survivor or one of the four Thread-based models [7]. No documentation on MAC randomization for these products was found.
## Sources
1. Belkin - Wikipedia - https://en.wikipedia.org/wiki/Belkin (accessed 2026-10-27)
2. Belkin International Inc. MAC address blocks - maclookup.app - https://maclookup.app/vendors/belkin-international-inc (accessed 2026-10-27)
3. OUI 24:F5:A2 registrant record - maclookup.app - https://maclookup.app/macaddress/24F5A2 (accessed 2026-10-27)
4. Belkin F9K1113 v4 - DeviWiki - https://deviwiki.com/wiki/Belkin_F9K1113_v4 (accessed 2026-10-27)
5. Wemo Mini Smart Plug V2 buffer-overflow vulnerability (CVE-2023-27217) - Sternum - https://sternumiot.com/iot-blog/mini-smart-plug-v2-vulnerability-buffer-overflow/ (accessed 2026-10-27)
6. CVE-2023-27217 record - CVE.org (MITRE CVE Services API) - https://cveawg.mitre.org/api/cve/CVE-2023-27217 (accessed 2026-10-27)
7. Wemo end-of-support notice - Belkin support - https://www.belkin.com/support-article/?articleNum=335419 (accessed 2026-10-27)
