---
name: "Fiberhome Telecommunication Technologies Co.,LTD"
aliases: []
country: CN [1][2]
parent: unknown
founded: 1999 [2][3]
kind: network-equipment [2]
device_classes: [ap/router [3]]
found_in: ["FiberHome HG6245D GPON home gateway [5]", "FiberHome AN5506 series GPON ONUs [6]", "FiberHome HG320 China Telecom home gateway (whose documented OUI 00:0A:C2 belongs to the registry's separate Wuhan FiberHome Digital entry) [4][1]"]
radios: ["Wi-Fi 4 [4]", "2.4 GHz [4]"]
silicon: ["Broadcom BCM5358U SoC and radio in the FiberHome HG320 (China Telecom) [4]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Added to the US Commerce Department Entity List in May 2020 over alleged complicity in human rights abuses in Xinjiang [2]", "HG6245D through RP2613: dozens of hardcoded ISP web and telnet credentials, a MAC-derived telnet enable backdoor API, cleartext Wi-Fi passwords, no IPv6 firewall by default (CVE-2021-27139 to CVE-2021-27179) [5]", "AN5506 ONUs: authenticated OS command injection (CVE-2021-42912), stack overflow in the web service shared with HG6245D (CVE-2021-4464), XSS and further 2025 issues [6]"]
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

FiberHome Telecommunication Technologies is a Chinese networking and telecommunication equipment provider founded in 1999, headquartered in Hongshan District, Wuhan, Hubei, and traded on the Shanghai Stock Exchange under 600498 [2]. Its own site gives 1999 as its founding year and lists PON access, broadband gateways, wireless routers, video terminals, FTTR all-optical home kits, MIFON gaming routers and 4K TV boxes [3]. The IEEE registry lists 215 MA-L blocks to this exact spelling at No.5 DongXin Road, Wuhan [1].

A MAC in these blocks is most likely an ISP-supplied fibre ONT or home gateway, since PON access and broadband gateways are the company's operator products [3]; that mapping from block to device type is inferred, not stated by a source. The one FiberHome gateway with a documented teardown, the HG320 for China Telecom, runs a Broadcom BCM5358U as SoC and 2x2 802.11b/g/n radio, but the OUI DeviWiki gives for it, 00:0A:C2, is registered to Wuhan FiberHome Digital Technology rather than to this entry [4][1].

The HG6245D GPON gateway shipped, through firmware RP2613, with many hardcoded ISP credentials, a telnet backdoor enabled by a value computed from the MAC, cleartext Wi-Fi passwords and no IPv6 firewall rules by default [5]. AN5506 ONUs carry an authenticated command injection and a web-service stack overflow [6]. The US Commerce Department put FiberHome on its Entity List in May 2020 [2]. Randomization is unknown; FCC grantee codes are not listed because the FCC ID databases (fccid.io, fcc.report, apps.fcc.gov) refused the session's requests.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. FiberHome - Wikipedia - https://en.wikipedia.org/wiki/FiberHome (accessed 2026-10-27)
3. FiberHome official site - https://www.fiberhome.com/ (accessed 2026-10-27)
4. FiberHome HG320 (China Telecom) - DeviWiki - https://deviwiki.com/wiki/FiberHome_HG320_(China_Telecom) (accessed 2026-10-27)
5. FiberHome HG6245D CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=FiberHome%20HG6245D (accessed 2026-10-27)
6. FiberHome AN5506 CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Fiberhome%20AN5506 (accessed 2026-10-27)
