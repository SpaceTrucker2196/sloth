---
name: "Hangzhou Hikvision Digital Technology Co.,Ltd."
aliases: []
country: CN [1][2]
parent: China Electronics Technology HIK Group, a subsidiary of state-owned China Electronics Technology Group (CETC) [1]
founded: 2001 [1]
kind: brand [1]
device_classes: [camera [1][3]]
found_in: ["Hikvision CCTV and network surveillance cameras [1]", "Ezviz, Hilook, Hiwatch and Hiksemi brands [1]", "DS-2CD2xx2F-I, DS-2CD2xx0F-I, DS-2CD4xx5 and DS-2DFx camera series [3]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2017-7921: improper authentication in several IP camera series lets an attacker escalate privileges and read sensitive data [3]", "CVE-2021-36260: command injection in the web server of some Hikvision products [4]", "FCC banned sale or import of Hikvision equipment in November 2022 on national-security grounds [1]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Hikvision is a Chinese maker of CCTV and network surveillance systems
founded in 2001, headquartered in Hangzhou, Zhejiang, and listed on the
Shenzhen Stock Exchange since 2010; its controlling shareholder is
China Electronics Technology HIK Group, a wholly owned subsidiary of
the state-owned China Electronics Technology Group, and its brands
include Ezviz, Hilook, Hiwatch and Hiksemi [1]. The IEEE registry lists
83 MA-L blocks to it at Hangzhou addresses [2]. A MAC in a Hikvision
block is most likely an IP camera, recorder or other surveillance
device [1].

CVE-2017-7921, published by ICS-CERT, is an improper authentication
flaw in the DS-2CD2xx2F-I, DS-2CD2xx0F-I, DS-2CD2xx2FWD, DS-2CD4x2xFWD,
DS-2CD4xx5, DS-2DFx and DS-2CD63xx camera series that lets an attacker
escalate privileges and reach sensitive information [3].
CVE-2021-36260, assigned by Hikvision, is a command injection in the
web server of some Hikvision products caused by insufficient input
validation [4]. The FCC declared Hikvision equipment an unacceptable
risk to US national security in March 2021 and banned its sale or
import in November 2022 [1].

The radios and silicon in Hikvision devices are not documented by the
sources consulted, randomization is unknown, and FCC grantee codes are
not listed because the FCC ID databases and Hikvision's own site
refused the session that wrote this entry.

## Sources

1. Hikvision - Wikipedia - https://en.wikipedia.org/wiki/Hikvision (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. CVE-2017-7921 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2017-7921 (accessed 2026-10-27)
4. CVE-2021-36260 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2021-36260 (accessed 2026-10-27)
