---
name: "Tenda Technology Co.,Ltd.Dongguan branch"
aliases: []
affiliates: ["SHEN ZHEN TENDA TECHNOLOGY CO.,LTD [1][2]", "Tenda Technology Co., Ltd. [1][2]"]
country: CN [1]
parent: Shenzhen Tenda Technology Co., Ltd. (inferred from the registrant name) [1][2]
founded: unknown
kind: brand [2]
device_classes: [ap/router [2][3], camera [3], switch [2][3]]
found_in: ["Tenda AC-series routers (AC6, AC9, AC10, AC15) [4]", "Tenda Wi-Fi 6 and Wi-Fi 7 routers, IP cameras, USB adapters, outdoor CPE and 4G/5G routers [3]"]
radios: ["Wi-Fi 6 [3]", "Wi-Fi 7 [3]", "2.4 GHz [4]", "5 GHz [4]", "LTE/5G [3]"]
silicon: ["Broadcom BCM4708A0 with BCM4360 in Tenda AC15 [4]", "Realtek RTL8197FS with RTL8812BRH in Tenda AC10 [4]", "Broadcom BCM53573B0 with BCM43217 in Tenda AC6 [4]", "Broadcom BCM47189B0 with BCM43217 in Tenda AC9 [4]", "MediaTek MT7620N in Tenda 4G300 [4]"]
fcc_grantee: ["V7T [4][5]"]
randomization: unknown
security_notes: ["CVE-2020-10987: remote OS command execution via the deviceName parameter of goform/setUsbUnload on the AC15, in the CISA Known Exploited Vulnerabilities catalog since 2021-11-03 [6]", "CVE-2018-5767: unauthenticated remote code execution through the COOKIE password parameter on the AC15 [7]", "CVE-2026-24101: command injection via goform/formSetIptv in AC15 V15.03.05.18 firmware [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 11 MA-L blocks to "Tenda Technology Co.,Ltd.Dongguan branch" at a Dalang Town, Dongguan, Guangdong address, five more to "SHEN ZHEN TENDA TECHNOLOGY CO.,LTD" and one to "Tenda Technology Co., Ltd." at Shenzhen addresses [1]. Tenda's own site names the company Shenzhen Tenda Technology Co., Ltd., founded in 1999 and headquartered in Shenzhen, selling home and business networking, switches, broadband CPE, gateways, powerline, mobile broadband and IP cameras [2]. A MAC in a Tenda block is most likely a consumer router or access point, or one of its cameras or USB adapters: the current site lists Wi-Fi 7 and Wi-Fi 6 series, pan/tilt and bullet cameras, NVRs, USB adapters, outdoor CPE, cloud-managed switches and 4G and 5G routers [3].

DeviWiki gives Tenda the FCC grantee code V7T, the prefix of every Tenda FCC ID it lists, and documents its routers on Broadcom and Realtek silicon, for example the AC15 on a Broadcom BCM4708A0 with a BCM4360 radio and the AC10 on a Realtek RTL8197FS with an RTL8812BRH 5 GHz radio [4][5]. Tenda routers have a poor security record: CVE-2020-10987, remote command execution through goform/setUsbUnload on the AC15, is in CISA's Known Exploited Vulnerabilities catalog [6], CVE-2018-5767 gave unauthenticated remote code execution on the same model [7], and CVE-2026-24101 is a further goform command injection in AC15 firmware [8]. Randomization is unknown, as no source consulted documents it.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About Tenda - https://www.tendacn.com/about (accessed 2026-10-27)
3. Tenda - home page product range - https://www.tendacn.com/ (accessed 2026-10-27)
4. List of Tenda Wireless Devices - DeviWiki - https://deviwiki.com/wiki/List_of_Tenda_Wireless_Devices (accessed 2026-10-27)
5. Tenda - DeviWiki - https://deviwiki.com/wiki/Tenda (accessed 2026-10-27)
6. NVD - CVE-2020-10987 - https://nvd.nist.gov/vuln/detail/CVE-2020-10987 (accessed 2026-10-27)
7. NVD - CVE-2018-5767 - https://nvd.nist.gov/vuln/detail/CVE-2018-5767 (accessed 2026-10-27)
8. NVD - CVE-2026-24101 - https://nvd.nist.gov/vuln/detail/CVE-2026-24101 (accessed 2026-10-27)
