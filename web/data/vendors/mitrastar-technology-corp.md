---
name: MitraStar Technology Corp.
aliases: []
country: TW [1]
parent: unknown
founded: unknown
kind: odm/ems [3]
device_classes: [ap/router [2][4], switch [2], module-in-other-brands [3]]
found_in: ["Zyxel NBG6816 (ARMOR Z1) router [3]", "MitraStar GPT-2541GNAC fibre gateway [4]"]
radios: ["Wi-Fi 5 [4]", "2.4 GHz [4]", "5 GHz [4]", "LTE/5G [2]"]
silicon: ["Broadcom BCM68380 SoC in GPT-2541GNAC [4]", "Quantenna QT3740BC and QT2518B 5 GHz Wi-Fi in GPT-2541GNAC [4]", "Broadcom BCM43217T 2.4 GHz Wi-Fi in GPT-2541GNAC [4]"]
fcc_grantee: ["ZMY [3]"]
randomization: unknown
security_notes: ["CVE-2017-16522 and CVE-2017-16523 root shell and hardcoded zyad1234 account in GPT-2541GNAC and DSL-100HN-T1 [5]", "CVE-2021-42165, CVE-2023-33381, CVE-2024-9977 OS command injection (deviceinfo path parameter, ping function, firewall settings page) in GPT-2541GNAC and GPT-2741GNAC [5]", "CVE-2025-50753 restricted shell escape to root in GPT-2741GNAC-N2 [5]", "CVE-2026-52483 and CVE-2026-52484 command injection in GPT-2741GNAC-N2-SV and GPT-2742GX4X5v6-SV [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

MitraStar Technology Corp. is a Taiwanese maker of broadband customer and central-office equipment; the IEEE registry lists 20 MA-L blocks under the name at a Hsinchu address [1]. Its own site lists LTE and outdoor CPE, XGS-PON/GPON HGU and SFU units and ONTs, PON MDUs and OLTs, DSL copper access, and multi-gigabit switches [2]. DeviWiki describes it as an OEM manufacturer that was previously part of ZyXEL, credits it with 41 devices including the ZyXEL NBG6816 (ARMOR Z1), and gives its FCC grantee code as ZMY [3].

A MAC in a MitraStar block is therefore most likely an ISP-supplied fibre or DSL gateway, an LTE CPE, or a Zyxel-branded device MitraStar built. The GPT-2541GNAC fibre gateway pairs a Broadcom BCM68380 SoC with Quantenna QT3740BC and QT2518B for the 4x4 802.11an+ac radio and a Broadcom BCM43217T for the 2x2 802.11bgn radio [4]. NVD lists a run of flaws in the GPT-2541GNAC and GPT-2741GNAC gateway families: a hardcoded root-equivalent account, a restricted-shell escape to a root shell and repeated OS command injection through the ping function, the firewall settings page and other CGI handlers [5].

Founding year, current ownership and randomisation behaviour are unknown: the company's English about page returned an error and the Chinese one states none of them, the FCC databases refused the session, and nothing is filled in from memory.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. MitraStar Technology Corp. home page - https://www.mitrastar.com/ (accessed 2026-10-27)
3. MitraStar - DeviWiki - https://deviwiki.com/wiki/MitraStar (accessed 2026-10-27)
4. MitraStar GPT-2541GNAC - DeviWiki - https://deviwiki.com/wiki/MitraStar_GPT-2541GNAC (accessed 2026-10-27)
5. NVD CVE API keyword search MitraStar - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=MitraStar&resultsPerPage=30 (accessed 2026-10-27)
