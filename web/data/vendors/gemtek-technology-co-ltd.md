---
name: "Gemtek Technology Co., Ltd."
aliases: []
country: TW [1]
parent: unknown
founded: 1988 [2]
kind: odm/ems [3]
device_classes: [ap/router [3], smart-home [3], module-in-other-brands [3]]
found_in: ["Buffalo WHR-1166D, WMR-433, WZR-AG300NH routers [3]", "Belkin WeMo Mini Smart Plug and WeMo Smart Switch [3]", "Razer Sila and ZyXEL WSQ50 routers [3]", "Linksys WRT400N and WAP54G v3, Netgear WNR834M and WNR854T [3]", "Cisco VEN401, D-Link DWL-6600AP, Fortinet FortiAP-210B access points [3]", "Kingston MobileLite Wireless G3 [3]"]
radios: ["Wi-Fi (802.11 routers and access points across generations) [3]", "LTE/5G [2]"]
silicon: ["Qualcomm IPQ4019 with QCA9984 in Razer Sila and ZyXEL WSQ50 (Gemtek WRTQ-334ACN) [3]", "MediaTek MT7620A with MT7612E in Buffalo WHR-1166D [3]", "Realtek RTL8881AM in Buffalo WMR-433 [3]", "MediaTek MT7688AN in Belkin WeMo Mini Smart Plug [3]", "Qualcomm IPQ4019 with QCA9984 in Gryphon and Onelink AC3000 [3]", "Broadcom BCM4717 (BCM4717A1, BCM4717VA1) in AirTies Air 4420 and Cisco VEN401 [3]"]
fcc_grantee: ["MXF [3]"]
randomization: unknown
security_notes: ["CVE-2020-24365: authenticated root command execution from the Monitor Diagnostic page of Gemtek WRTM-127ACN and WRTM-127x9 [4]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Gemtek Technology is a Taiwanese manufacturer; the IEEE registry lists 15 MA-L blocks to "Gemtek Technology Co., Ltd." at addresses in Hukou, Hsinchu, Taiwan [1]. Its own site says it was established in 1988 and makes optical transceivers, AIoT modules, fibre network equipment, Wi-Fi, 5G and satcom devices for data centres, service providers and brand vendors [2]. DeviWiki calls it a prolific OEM/ODM [3], so a MAC in a Gemtek block is usually a router, access point or smart-home device sold under another brand: DeviWiki lists 495 devices with Gemtek as manufacturer, among them Buffalo, Belkin WeMo, Razer, ZyXEL, Linksys, Netgear, Cisco, D-Link and Fortinet products [3].

DeviWiki gives Gemtek the FCC grantee code MXF and documents silicon from every major Wi-Fi vendor, for example Qualcomm IPQ4019 with QCA9984 in the Razer Sila, MediaTek MT7620A with MT7612E in the Buffalo WHR-1166D and MediaTek MT7688AN in the Belkin WeMo Mini smart plug [3]. NVD records CVE-2020-24365, authenticated command execution as root on the Gemtek WRTM-127ACN and WRTM-127x9 [4]. Parent company and randomization behaviour are not documented by the sources consulted [2][3].

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About Gemtek - https://www.gemteks.com/en/about (accessed 2026-10-27)
3. Gemtek - DeviWiki - https://deviwiki.com/wiki/Gemtek (accessed 2026-10-27)
4. NVD - CVE-2020-24365 - https://nvd.nist.gov/vuln/detail/CVE-2020-24365 (accessed 2026-10-27)
