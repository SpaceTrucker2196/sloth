---
name: Nokia
aliases: ["Nokia Corporation"]
country: FI [2]
parent: independent; public company listed on Nasdaq Helsinki and the New York Stock Exchange [2]
founded: 1865 [2]
kind: network-equipment [2]
device_classes: [ap/router [3][4][5], phone [2]]
found_in: ["Nokia A-020W-A Wi-Fi mesh system [3]", "Nokia HA-030W-B 7368 ISAM CPE [4]", "Nokia G-240W-F fibre gateway ONT [5]", "Nokia FastMile gateways and FastMile 5G Receiver [7]", "Nokia mobile phones up to the 2014 sale of the devices division to Microsoft [2]"]
radios: ["Wi-Fi 4 [5]", "Wi-Fi 5 [3][4]", "2.4 GHz [3]", "5 GHz [3]", "LTE/5G [7]"]
silicon: ["MediaTek MT7621A SoC with two MediaTek MT7615DN radios in the Nokia A-020W-A [3]", "Broadcom BCM68460 SoC with two Broadcom BCM4366E radios in the Nokia HA-030W-B [4]", "EcoNet EN7526GT SoC with a MediaTek MT7592 2.4 GHz radio in the Nokia G-240W-F [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Nokia G-120W-F: stored XSS in the admin interface (CVE-2021-30003) [6]", "Nokia FastMile gateways: privilege escalation, path traversal and a hardcoded admin account on units shipped by Optus (CVE-2021-45896, CVE-2022-36221, CVE-2022-36222) [7]", "Nokia FastMile 5G Receiver 5G14-B: Bluetooth uses outdated pairing, so a passively captured pairing can be cracked offline for the PIN and long-term key (CVE-2022-38788) [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Nokia is a Finnish public company, Nokia Oyj in Finnish, headquartered in Espoo, whose history dates from 1865; it sold its mobile devices division to Microsoft in April 2014, HMD Global has made Nokia-branded phones under a licensing deal signed in 2016, and Nokia Networks, its largest division, is a data networking and telecommunications equipment business [2]. Nokia took over the Nokia Siemens Networks joint venture in 2013 and Alcatel-Lucent in 2016 [2]. The IEEE registry lists 150 MA-L blocks to "Nokia", 149 of them at 600 March Road, Kanata, Ontario and one at Westford, Massachusetts, and 90 to "Nokia Corporation", 52 of them at Elektroniikkatie 10, Oulu, 36 at Joensuunkatu 7, Salo, and 2 at Bochum, Germany [1]; the registry also carries separate entries for Nokia Shanghai Bell, Nokia Danmark, Nokia Solutions and Networks and others, which this file does not cover [1].

Which device a MAC in the "Nokia" blocks is cannot be read from the sources consulted; that the Finnish "Nokia Corporation" blocks belong to the former handset business is an inference from the addresses only [1]. Nokia-branded home equipment documented on DeviWiki includes the A-020W-A mesh system (MediaTek MT7621A with two MT7615DN 802.11ac radios), the HA-030W-B 7368 ISAM CPE (Broadcom BCM68460 with two BCM4366E radios, 802.11ac, flagged Wave2 and MU-MIMO) and the G-240W-F ONT (EcoNet EN7526GT with a MediaTek MT7592 802.11n radio) [3][4][5]. Their FCC IDs begin 2ADZR, and DeviWiki names the holder of the A-020W-A's as Nokia Shanghai Bell and of the HA-030W-B's as Alcatel-Lucent Shanghai Bell, both separate registry names, so no grantee code is listed against this entry [3][4].

NVD records a stored XSS in the G-120W-F gateway [6] and, for the FastMile fixed-wireless gateways, a privilege escalation, a path traversal, a hardcoded admin account on units shipped by Optus and outdated Bluetooth pairing on the 5G receiver [7]. Randomization is unknown; Nokia's own product pages and the FCC ID databases refused the session's requests.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Nokia - Wikipedia - https://en.wikipedia.org/wiki/Nokia (accessed 2026-10-27)
3. Nokia A-020W-A - DeviWiki - https://deviwiki.com/wiki/Nokia_A-020W-A (accessed 2026-10-27)
4. Nokia HA-030W-B - DeviWiki - https://deviwiki.com/wiki/Nokia_HA-030W-B (accessed 2026-10-27)
5. Nokia G-240W-F - DeviWiki - https://deviwiki.com/wiki/Nokia_G-240W-F (accessed 2026-10-27)
6. Nokia G-120W-F CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Nokia%20G-120W-F (accessed 2026-10-27)
7. Nokia FastMile CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Nokia%20FastMile (accessed 2026-10-27)
