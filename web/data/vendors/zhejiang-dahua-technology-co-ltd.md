---
name: "Zhejiang Dahua Technology Co., Ltd."
aliases: ["ZHEJIANG DAHUA TECHNOLOGYCO.,LTD"]
country: CN [1][2]
parent: independent, majority owned by founder Fu Liquan and Chen Ailing with state-linked holders at 11.67% (2023) [1]
founded: 2001 [1]
kind: brand [1][3]
device_classes: [camera [1][3]]
found_in: ["Dahua network, PTZ and thermal cameras, NVR/DVR and video intercoms [1][3]", "Lorex, owned by Dahua from 2018 until its sale completed in February 2023 [1]", "IPC-HX3XXX, IPC-HX5XXX and IPC-HUM7XXX cameras and VTO/VTH intercoms [4]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2021-33044: login authentication bypass in IP cameras, intercoms, PTZ domes and thermal cameras built before June 2021 [4]", "2016 botnet of Dahua and OEM cameras and DVRs used in a record DDoS; a 2017 backdoor report [1]", "FCC interim freeze order on new Dahua equipment, November 2022 [1]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Dahua Technology is a Chinese video surveillance company founded in
2001 by Fu Liquan, headquartered in Binjiang District, Hangzhou, and
listed on the Shenzhen Stock Exchange since 2008; it is majority owned
by Fu Liquan and his wife Chen Ailing, with state-linked holders at 11.67% as of 2023 [1]. It makes network, PTZ and fisheye cameras, HDCVI
equipment and NVR/DVR recorders, and owned Lorex from 2018 until the
sale to Skywatch completed in February 2023 [1]; its own site also lists thermal cameras, video intercoms, access control, switches and routers, EV
chargers and dash cameras [3]. The IEEE registry lists 27 MA-L blocks
to "Zhejiang Dahua Technology Co., Ltd." and four to "ZHEJIANG DAHUA
TECHNOLOGYCO.,LTD", at Hangzhou addresses, one of them with its city field garbled in the registry [2].

A MAC in a Dahua block is most likely a camera, recorder or intercom
[1][3]. CVE-2021-33044, assigned by Dahua, is an identity
authentication bypass at login in IP cameras (IPC-HX3XXX, IPC-HX5XXX,
IPC-HUM7XXX), video intercoms, PTZ domes and thermal cameras built
before June 2021 [4]. In 2016 a botnet of Dahua and OEM cameras and
DVRs carried out a record DDoS attack, and in 2017 researchers reported
a backdoor whose firmware fix reportedly kept the same flaw elsewhere
in the code [1]. The FCC found Dahua an unacceptable risk to US
national security in March 2021 and imposed an interim freeze order on
new equipment in November 2022 [1].

Radios and silicon are not documented by the sources consulted,
randomization is unknown, and FCC grantee codes are not listed because
the FCC ID databases refused the session that wrote this entry.

## Sources

1. Dahua Technology - Wikipedia - https://en.wikipedia.org/wiki/Dahua_Technology (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Dahua Technology company introduction - https://www.dahuasecurity.com/aboutUs/introduction (accessed 2026-10-27)
4. CVE-2021-33044 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2021-33044 (accessed 2026-10-27)
