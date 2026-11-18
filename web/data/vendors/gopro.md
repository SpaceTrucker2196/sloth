---
name: GoPro
aliases: []
affiliates: []
country: US [1][2]
parent: independent, listed on Nasdaq since 2014 [2]
founded: 2002 [2]
kind: brand [2]
device_classes: [camera [2], drone [2]]
found_in: ["GoPro HERO action cameras [2]", "GoPro MAX cameras [2]", "GoPro Karma drone, discontinued in 2018 [2]"]
radios: ["Wi-Fi 6 (HERO13 Black) [2]", "2.4 GHz [2]", "5 GHz (HERO6 Black) [2]", "Bluetooth (from the HERO4 Black Edition) [2]"]
silicon: ["Qualcomm QCA6134X-AM2D Wi-Fi/Bluetooth SiP and Ambarella A7LS video SoC in HERO4 Session [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2014-6433 and CVE-2014-6434: gpExec on the HERO3+ lets remote attackers execute files and commands through start and restart actions [4][5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

GoPro is a US action-camera maker founded in 2002 by Nick Woodman as Woodman Labs, headquartered in San Mateo, California, and public on Nasdaq since 2014 [2]. The IEEE registry lists 8 MA-L blocks under "GoPro" at a San Mateo address [1]. A MAC in a GoPro block is most likely a HERO or MAX camera, which carry Wi-Fi and, since the HERO4 Black Edition, Bluetooth: the HERO6 Black has 2.4 and 5 GHz Wi-Fi, the 2018 HERO 2.4 GHz only, and the HERO13 Black Wi-Fi 6 [2]; the Karma drone was recalled for power failures and discontinued in January 2018 [2].

iFixit's HERO4 Session teardown found a Qualcomm QCA6134X-AM2D Wi-Fi/Bluetooth SiP on the wireless daughterboard and an Ambarella A7LS video SoC [3]. On the HERO3+, the gpExec handler allowed remote execution of files and commands (CVE-2014-6433, CVE-2014-6434) [4][5]. Silicon for later HERO generations and FCC grantee codes are not listed: the teardown and FCC ID sites that would document them refused or rate-limited automated access from the session that wrote this entry, and nothing is filled in from memory; randomization is unknown.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. GoPro - Wikipedia - https://en.wikipedia.org/wiki/GoPro (accessed 2026-10-27)
3. GoPro Hero4 Session Teardown - iFixit - https://www.ifixit.com/Teardown/GoPro+Hero4+Session+Teardown/44307 (accessed 2026-10-27)
4. NVD - CVE-2014-6433 - https://nvd.nist.gov/vuln/detail/CVE-2014-6433 (accessed 2026-10-27)
5. NVD - CVE-2014-6434 - https://nvd.nist.gov/vuln/detail/CVE-2014-6434 (accessed 2026-10-27)
