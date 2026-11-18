---
name: "Compal Broadband Networks, Inc."
aliases: []
affiliates: []
country: TW [1][2]
parent: Compal Group [1]
founded: 2009 [1]
kind: network-equipment [1]
device_classes: [ap/router [1][3]]
found_in: ["CH7465LG Connect Box cable gateway supplied by UPC, Ziggo (NL), Unitymedia (DE) and Virgin Media in Ireland (Super Hub 3.0) [3]"]
radios: ["Wi-Fi 5 802.11ac at 5 GHz and 802.11b/g/n at 2.4 GHz (CH7465LG) [3]"]
silicon: ["Intel Puma DHCE2652 SoC with Celeno CL242 (2.4 GHz) and Celeno CL2330 (5 GHz) in the CH7465LG [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-13025: crafted HTTP POST to a backend API of the CH7465LG (firmware 6.12.18.24-5p8-NOSH) runs shell commands [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Compal Broadband Networks (CBN) is a member of Taiwan's Compal Group, founded in August 2009 and based in Zhubei City, Hsinchu County; its product lines are broadband access equipment, LTE/5G mobile communications and home networking equipment [1]. The IEEE registry lists nine MA-L blocks to "Compal Broadband Networks, Inc." at Taiyuan 1st Street, Zhubei City [2].

A MAC in these blocks is most likely an ISP-supplied cable gateway: the CH7465LG is the Connect Box of UPC, Ziggo and Unitymedia and the Super Hub 3.0 of Virgin Media in Ireland [3]. It runs an Intel Puma DHCE2652 SoC with Celeno CL242 (2.4 GHz, 2x2) and CL2330 (5 GHz, 3x3, 802.11ac) radios; WikiDevi names Arcadyan as its OEM and lists FCC ID O2U-AP7465, whose grantee is not stated, so no grantee code is listed here [3].

CVE-2019-13025 lets an attacker run shell commands on the CH7465LG with firmware 6.12.18.24-5p8-NOSH through a crafted HTTP POST to a backend API [4]. Randomization behaviour is not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources
1. Compal Broadband Networks (CBN) - https://www.icbn.com.tw/ (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Compal Broadband Networks CH7465LG-LC - WikiDevi - https://wikidevi.wi-cat.ru/Compal_Broadband_Networks_CH7465LG-LC (accessed 2026-10-27)
4. CVE-2019-13025 - CIRCL Vulnerability-Lookup - https://cve.circl.lu/vuln/cve-2019-13025 (accessed 2026-10-27)
