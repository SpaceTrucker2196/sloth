---
name: Routerboard.com
aliases: []
country: LV [1][2]
parent: independent, privately held by its two founders [2]
founded: 1996 [2]
kind: network-equipment [2]
device_classes: [ap/router [2][3], switch [2]]
found_in: ["MikroTik RouterBOARD routers and access points running RouterOS: hAP, cAP, wAP, mAP, SXT, RB4011 and others [3][4]", "small and medium wireless ISPs serving rural and remote areas [2]"]
radios: ["Wi-Fi 4/5/6 [2][3][4]", "2.4 GHz [3][4]", "5 GHz [3][4]", "60 GHz (802.11ad), wAP 60G [3]", "LTE/5G [2]"]
silicon: ["Qualcomm IPQ-6010 with QCN-5022 and QCN-5052 in hAP ax2 [4]", "Qualcomm IPQ4018 in hAP ac2 and cAP ac [3]", "Qualcomm Atheros QCA9558 with QCA9880 in hAP ac [3]", "Qualcomm Atheros QCA9531 with QCA9887 in hAP ac lite [3]", "Qualcomm Atheros QCA9533 in hAP lite, hAP mini, mAP lite, cAP [3]", "Annapurna Labs Alpine AL21400 with QCA9984 in RB4011 [3]", "Qualcomm IPQ4019 with QCA6335 (802.11ad) in wAP 60G [3]"]
fcc_grantee: ["TV7 (inferred from the FCC ID prefix of every listed MikroTik device) [3]"]
randomization: unknown
security_notes: ["CVE-2018-14847: WinBox directory traversal in RouterOS through 6.42 (unauthenticated file read), in the CISA Known Exploited Vulnerabilities catalog [5]", "routers compromised through CVE-2018-14847 formed the Meris DDoS botnet reported in September 2021; upgrading alone does not remove a stolen password [6]", "VPNFilter (2018): MikroTik RouterOS up to 6.38.5 listed among firmware at risk, and some MikroTik devices found vulnerable [7][2]", "FOISted (2022): an administrator could gain super-admin access, patched in RouterOS from October 2022 [2]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Routerboard.com is the IEEE registrant name of MikroTik, the Latvian network-equipment maker; the registry lists 22 MA-L blocks under that name, most of them at "Mikrotikls SIA, Riga" [1]. MikroTik was founded in Riga on 14 March 1996 by John Tully and Arnis Riekstins, is privately held by the two founders, and sells RouterBOARD hardware running RouterOS, its Linux-based router operating system, mainly to small and medium wireless ISPs [2]. A MAC in one of these blocks is almost always a MikroTik router, access point, outdoor wireless link, or switch, the range including sector, dish and omni antennas, 60 GHz systems and 2G to 5G cellular models [2].

Every MikroTik FCC ID DeviWiki lists begins TV7, the company's grantee code by inference, and DeviWiki documents mostly Qualcomm Atheros silicon: QCA9531 and QCA9533 in the small hAP, mAP and cAP units, IPQ4018 and IPQ4019 in the ac generation, QCA6335 for 802.11ad in the wAP 60G, and an Annapurna Labs Alpine CPU with a QCA9984 radio in the RB4011 [3]; the Wi-Fi 6 hAP ax2 uses a Qualcomm IPQ-6010 with QCN-5022 and QCN-5052 radios [4]. MikroTik is a frequent target: CVE-2018-14847, a WinBox directory traversal in RouterOS through 6.42, is in CISA's Known Exploited Vulnerabilities catalog [5]; MikroTik says the Meris botnet of 2021 was built from routers compromised through that bug in 2018 and that an upgrade without a password change does not clean them [6]; and in 2018 Cisco Talos found some MikroTik devices vulnerable to VPNFilter, whose at-risk list includes RouterOS up to 6.38.5 [2][7]. Randomization is unknown: no source consulted documents it.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. MikroTik - Wikipedia - https://en.wikipedia.org/wiki/MikroTik (accessed 2026-10-27)
3. MikroTik - DeviWiki - https://deviwiki.com/wiki/MikroTik (accessed 2026-10-27)
4. hAP ax2 - MikroTik product page - https://mikrotik.com/product/hap_ax2 (accessed 2026-10-27)
5. NVD - CVE-2018-14847 - https://nvd.nist.gov/vuln/detail/CVE-2018-14847 (accessed 2026-10-27)
6. Meris botnet - MikroTik security - https://mikrotik.com/supportsec/meris-botnet/ (accessed 2026-10-27)
7. VPNFilter - Wikipedia - https://en.wikipedia.org/wiki/VPNFilter (accessed 2026-10-27)
