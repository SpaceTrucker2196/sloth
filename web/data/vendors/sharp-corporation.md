---
name: SHARP Corporation
aliases: ["SHARP CORPORATION", "SHARP Corporation."]
affiliates: []
country: JP [1][2]
parent: Hon Hai Precision Industry (Foxconn), majority owner since 2016 [2]
founded: 1912 [2]
kind: brand [2]
device_classes: [tv [2][3], phone [2][4][6], printer [7], ap/router [8][9]]
found_in: ["Sharp Aquos TVs including LC-60UD27U, LC-70LE757U, LC-70UQ17U and LC-80SQ15U (possibly, via the DHUB-SP1 Wi-Fi module) [3]", "Sharp SH-01F phone [4]", "Sharp AQUOS phones including SH-M02, SH-M03 and SH-M05 to SH-M08 [6]", "Sharp multifunction printers [7]", "Sharp routers [8][9]"]
radios: ["Wi-Fi 4 [3][4]", "Bluetooth, version not documented (DHUB-SP1) [3]"]
silicon: ["Broadcom BCM43242 in the Sharp DHUB-SP1 TV Wi-Fi module [3]"]
fcc_grantee: ["APY, the prefix of the Sharp SH-01F phone's FCC ID APYHRO00197 [4]"]
randomization: unknown
security_notes: ["AQUOS phones leak sensitive information (CVE-2020-5571) [6]", "command injection in the web interface of Sharp MFPs (CVE-2022-45796) [7]", "hidden debug function on Sharp routers allows unauthenticated root command execution (CVE-2024-46873) [8]", "unauthenticated retrieval of Sharp router configuration backups (CVE-2024-52321) [9]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Sharp is a Japanese electronics maker founded in 1912 in Tokyo by
Tokuji Hayakawa, headquartered in Sakai, Osaka, and majority owned by
Hon Hai Precision Industry (Foxconn) since 2016; it makes Aquos LCD
TVs, mobile phones, microwave ovens, refrigerators, washing machines
and air purifiers [2]. The IEEE registry lists 16 MA-L blocks to SHARP
Corporation, three to SHARP CORPORATION and one to SHARP Corporation.
at Osaka and Sakai addresses [1]. A MAC in these blocks is most likely
a Sharp TV, phone, multifunction printer, router or networked
appliance [2][3][7][8].

DeviWiki records the DHUB-SP1, a Broadcom BCM43242 802.11a/b/g/n 2x2
USB module made by Wistron NeWeb with Bluetooth, which the page says
is used with various Sharp TVs [3], the Sharp
SH-01F phone with FCC ID APYHRO00197 and 802.11b/g/n [4], and further
Sharp-tagged Wi-Fi adapter pages, one of them a module used by Sharp
for its LCD TVs [5]. NVD lists an information leak on
AQUOS Android phones [6], command injection in Sharp MFPs [7], and on
Sharp routers a hidden debug function that gives an unauthenticated
remote attacker root commands [8] and unauthenticated download of
configuration backups [9]. Randomisation is unknown; the FCC ID
databases and web search were unavailable to the session that wrote
this entry [1].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Sharp Corporation - Wikipedia - https://en.wikipedia.org/wiki/Sharp_Corporation (accessed 2026-10-27)
3. Sharp DHUB-SP1 - DeviWiki - https://deviwiki.com/wiki/Sharp_DHUB-SP1 (accessed 2026-10-27)
4. Sharp SH-01F - DeviWiki - https://deviwiki.com/wiki/Sharp_SH-01F (accessed 2026-10-27)
5. DeviWiki search results for Sharp - https://deviwiki.com/w/index.php?search=Sharp&fulltext=1&limit=40 (accessed 2026-10-27)
6. CVE-2020-5571 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2020-5571 (accessed 2026-10-27)
7. CVE-2022-45796 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2022-45796 (accessed 2026-10-27)
8. CVE-2024-46873 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-46873 (accessed 2026-10-27)
9. CVE-2024-52321 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-52321 (accessed 2026-10-27)
