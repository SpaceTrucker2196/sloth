---
name: Vantiva - Connected Home
aliases: [Vantiva Connected Home - Subcomponents, Vantiva Connected Home - Orange Belgium, Vantiva Connected Home - Home Networks]
affiliates: ["Technicolor (China) Technology Co., Ltd. [8]", "Technicolor CH USA Inc for Telus [8]"]
country: FR [1]
parent: Vantiva SA (Paris; formerly Technicolor SA, formerly Thomson) [1]
founded: 1893 [1]
kind: network-equipment
device_classes: [ap/router, tv]
found_in: ["Xfinity XB6 (CGM4140COM, Wi-Fi 5; a Technicolor design per DeviWiki) [4][5]", "Xfinity XB7 (CGM4331COM, Wi-Fi 6; Technicolor per DeviWiki) [4][7]", "Xfinity XB8 (CGM4981COM, Wi-Fi 6E), of which the Technicolor MXB1 (CGM4981COM2) is the wall-mountable version [4]", "Mediacom CGM4231, Comcast TC8706C / TC8717C, CenturyLink C1100T [5]", "Operators named in the IEEE registrant strings: Orange Belgium, Telus [8]"]
radios: ["Wi-Fi 5 (802.11ac) [4][5]", "Wi-Fi 6 [4][7]", "Wi-Fi 6E (6 GHz) [4]", "2.4 GHz [5]", "5 GHz [5]", "6 GHz [4]", "LTE/5G (5G FWA gateways) [3]"]
silicon: ["Broadcom BCM3390 cable SoC in CGM4231 (Mediacom) [5]", "Broadcom BCM3382 / BCM33843 in TC8706C / TC8717C (Comcast) [5]", "Broadcom BCM63168 in C1100T (CenturyLink) [5]", "Quantenna QT10GA 8x8 802.11ac radio in CGM4140COM (Xfinity XB6) [5]", "Broadcom BCM43602 in TG589vac v2; Broadcom BCM4360 in CGA2121; Quantenna QT3840BC in DWA1230 [5]", "Realtek RTL8672 / RTL8676 in older DSL models; Marvell 88DE3218 in CM-7600 set-top box [5]"]
fcc_grantee: ["G95 (FCC-ID prefix appearing on Technicolor gateways per DeviWiki, e.g. G954331X on the CGM4331COM; other prefixes seen there: RSE, RK9, N89, VUICGA) [5][7]"]
randomization: unknown
security_notes: ["NVD lists 40 CVEs with the Technicolor keyword, e.g. CVE-2014-0620/0621 (TC7200 XSS and CSRF), CVE-2014-9144 (TD5130 command injection via ping field), CVE-2016-7454 (dpc3941T CSRF), CVE-2014-1677 (TC7200 information disclosure), CVE-2011-4506 (TG585 UPnP IGD arbitrary port mappings) [6]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Vantiva is the Paris-headquartered company formerly known as Thomson (1893) and Technicolor SA (2010), renamed Vantiva on 27 September 2022; its Connected Home division makes broadband gateways, set-top boxes and Android TV devices, held the largest gateway/modem market share outside China as of September 2020, and acquired CommScope's Home Networks (the former Arris) business on 2 January 2024 in exchange for a 25% stake [1]. Its US gateway lineage is Scientific Atlanta via Cisco, whose set-top-box and cable-modem business Technicolor bought for $600 million in 2015 [2]. In the IEEE registry copy shipped with sloth, "Vantiva - Connected Home" holds 7 MA-L blocks at Norcross, Georgia; the related "Vantiva USA LLC" (its own entry) holds 98 and "Vantiva Technologies Belgium" 12, with further Vantiva and Technicolor spellings, two of which name operators (Orange Belgium, Telus) [8]. Given the product line, a MAC in these blocks is most likely an operator-supplied cable, fiber or 5G FWA gateway, Wi-Fi extender or set-top box [3]. Comcast's Xfinity XB6 (CGM4140COM) and XB7 (CGM4331COM) are Technicolor units per DeviWiki, and Comcast itself names the Technicolor MXB1 as the wall-mountable version of the XB8, spanning Wi-Fi 5 to Wi-Fi 6E [4][5][7]; the Wi-Fi 7 XB9, XB10 and XER10 are listed by Comcast without a manufacturer name and are not attributed here [4]. Documented silicon is Broadcom cable SoCs with Broadcom or Quantenna radios [5]. On the air expect an access point, dual- or tri-band, often broadcasting operator SSIDs. NVD carries 40 Technicolor-keyword CVEs, mostly web-UI XSS/CSRF and command injection in older TC/TD/dpc-series gateways [6]. The grantee code G95 is read off FCC-ID prefixes DeviWiki records on Technicolor hardware, not from the FCC database directly [5][7], and no statement on MAC randomization was found. The live IEEE oui.txt could not be fetched when this entry was verified (HTTP 418), so the block counts come from the registry copy in the repository.
## Sources
1. Vantiva - Wikipedia - https://en.wikipedia.org/wiki/Vantiva (accessed 2026-10-27)
2. Technicolor SA - Wikipedia - https://en.wikipedia.org/wiki/Technicolor_SA (accessed 2026-10-27)
3. Connected Home - Vantiva - https://www.vantiva.com/connected-home/ (accessed 2026-10-27)
4. Xfinity Gateways: user guides and models - Comcast Xfinity support - https://www.xfinity.com/support/articles/broadband-gateways-userguides (accessed 2026-10-27)
5. Technicolor - DeviWiki - https://deviwiki.com/wiki/Technicolor (accessed 2026-10-27)
6. NVD API keyword search "Technicolor" - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Technicolor&resultsPerPage=8 (accessed 2026-10-27)
7. Technicolor CGM4331COM - DeviWiki - https://deviwiki.com/wiki/Technicolor_CGM4331COM (accessed 2026-10-27)
8. IEEE Registration Authority MA-L public listing (oui.csv; read from the copy shipped in sloth web/data/oui.csv, ieee-data 20260625) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
