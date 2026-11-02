---
name: "NEC Platforms, Ltd."
aliases: ["NEC Platforms, Ltd"]
country: JP [1][2]
parent: NEC Corporation (100 percent) [2]
founded: 1918 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][3], pos [2]]
found_in: ["NEC Aterm home Wi-Fi routers, repeaters and mobile routers, including the Wi-Fi 7 Aterm 19000T12BE [3]", "NEC Aterm MR03LN mobile hotspot [4]", "NEC AccessTechnica RG-G201L router and IoT hub [4]"]
radios: ["Wi-Fi 6E/7 [3]", "6 GHz [3]"]
silicon: ["Qualcomm MDM9225 in Aterm MR03LN [4]", "Mindspeed Comcerto 2000 with Atheros AR9382 in RG-G201L [4]"]
fcc_grantee: ["2AA5W (on the Aterm MR03LN and RG-G201L FCC IDs) [4]"]
randomization: unknown
security_notes: ["CVE-2026-4619 to CVE-2026-4622: path traversal, OS command injection and a hidden telnet enable in the Aterm series [5]", "CVE-2026-6059 and CVE-2026-8652: cross-site scripting and admin OS command injection in Aterm [5]", "CVE-2013-0717: CSRF in the web management of several Aterm WR and WM routers [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

NEC Platforms is a wholly owned NEC Corporation subsidiary with its head office in Chiyoda, Tokyo; it traces back to Nihon Denwa Kogyo, founded in Osaka on 8 February 1918, later Nitsuko and NEC Infrontia, and took its present name in July 2014 when it absorbed NEC AccessTechnica and others [2]. The IEEE registry lists 15 MA-L blocks to "NEC Platforms, Ltd." at Tokyo and Kakegawa, Shizuoka addresses and one to "NEC Platforms, Ltd" at Kawasaki [1]. From NEC AccessTechnica it inherited the Aterm home routers and the Kakegawa site, and from NEC Infrontia POS systems, business telephones and network equipment (the POS business went to Steeretail in 2025) [2].

A MAC in these blocks is most likely an NEC Aterm Wi-Fi home router, repeater or mobile router, a line whose new model is the Wi-Fi 7 tri-band Aterm 19000T12BE and whose product site also describes the 6 GHz band of Wi-Fi 6E [3]. DeviWiki lists the Aterm MR03LN mobile hotspot on a Qualcomm MDM9225 and the RG-G201L wireless router and IoT hub on a Mindspeed Comcerto 2000 with an Atheros AR9382, both with FCC IDs under 2AA5W [4]. NVD records 2026 Aterm-series flaws attributed to NEC Platforms, including path traversal, OS command injection and a hidden function that enables telnet [5], further XSS and command injection in Aterm [5], and older CSRF in several Aterm models [6]. Randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. NEC Platforms - Japanese Wikipedia - https://ja.wikipedia.org/wiki/NEC%E3%83%97%E3%83%A9%E3%83%83%E3%83%88%E3%83%95%E3%82%A9%E3%83%BC%E3%83%A0%E3%82%BA (accessed 2026-10-27)
3. Aterm - NEC Wi-Fi and mobile router product site - https://www.aterm.jp/ (accessed 2026-10-27)
4. NEC - DeviWiki - https://deviwiki.com/wiki/NEC (accessed 2026-10-27)
5. NVD CVE API, keyword Aterm (CVE-2026-4619 to 4622, CVE-2026-6059, CVE-2026-8652) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Aterm (accessed 2026-10-27)
6. NVD - CVE-2013-0717 - https://nvd.nist.gov/vuln/detail/CVE-2013-0717 (accessed 2026-10-27)
