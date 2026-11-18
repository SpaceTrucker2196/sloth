---
name: "Qingdao Haier Technology Co.,Ltd"
aliases: ["Qingdao Haier Technology Co.Ltd", "Qingdao HaierTechnology Co.,Ltd"]
affiliates: []
country: CN [1][2]
parent: Haier Group, inferred from the name and the registry's Haier Information Park address [1][2]
founded: unknown
kind: brand [2]
device_classes: [smart-home [2][3], phone [4]]
found_in: ["GE Kitchen Hub (UVH1301), a Haier-built appliance (whether it carries this registrant's blocks is not documented) [3]"]
radios: ["Wi-Fi 5 (GE Kitchen Hub) [3]", "BLE, version not documented (GE Kitchen Hub) [3]"]
silicon: ["Rockchip RK3288 SoC, Realtek RTL8822BS Wi-Fi and Cypress CYW20737 Bluetooth LE in the Haier-built GE Kitchen Hub [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["pre-installed apps exposing privileged capabilities on Haier-brand Android phones A6, P10 and G8 (CVE-2019-15359, CVE-2019-15367, CVE-2019-15370) [4][5][6]", "German media reported pre-installed malware on Haier phones and tablets in 2014 [2]"]
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 18 MA-L blocks to Qingdao Haier Technology
Co.,Ltd, one to the spelling "Qingdao Haier Technology Co.Ltd" and
three to "Qingdao HaierTechnology Co.,Ltd", all at the Haier
Information Park on Haier Road, Qingdao [1]. Haier, founded in 1984 as
Qingdao Refrigerator Co. and headquartered in Qingdao, makes
refrigerators, air conditioners, washing machines and other appliances
under brands including Haier, Casarte, GE Appliances, Fisher and
Paykel, Aqua and Candy, and since 2015 has worked on bringing
the internet of things into its appliances [2]. A MAC in these blocks
is therefore most likely a connected Haier-group appliance, though no
source consulted ties a specific product to this registrant [1][2].

DeviWiki records Haier as the manufacturer of the GE Kitchen Hub
(UVH1301), with FCC IDs ZKJ-KITCHENHUB1 and ZKJ-BLEA003, a Rockchip
RK3288 SoC, a Realtek RTL8822BS 802.11a/b/g/n/ac radio and a Cypress CYW20737 for Bluetooth
LE [3]. In 2024 Haier sent cease-and-desist letters to the open-source
hOn and pyhOn projects that let Home Assistant control its appliances
without Haier's cloud, and in 2014 German media accused it of shipping
phones and tablets with pre-installed malware [2]. NVD lists
pre-installed app flaws on Haier-brand Android phones [4][5][6].
Randomisation is unknown, and no FCC grantee code is listed: no source
reachable from the session that verified this entry names the grantee
behind the ZKJ prefix, which may be GE Appliances rather than this
registrant, and the FCC ID databases refused it [3].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Haier - Wikipedia - https://en.wikipedia.org/wiki/Haier (accessed 2026-10-27)
3. GE Kitchen Hub (UVH1301) - DeviWiki - https://deviwiki.com/wiki/GE_Kitchen_Hub_(UVH1301) (accessed 2026-10-27)
4. CVE-2019-15359 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2019-15359 (accessed 2026-10-27)
5. CVE-2019-15367 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2019-15367 (accessed 2026-10-27)
6. CVE-2019-15370 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2019-15370 (accessed 2026-10-27)
