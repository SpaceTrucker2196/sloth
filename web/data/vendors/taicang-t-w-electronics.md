---
name: Taicang T&W Electronics
aliases: ["T&W Electronics Company"]
affiliates: []
country: CN [1]
parent: unknown
founded: unknown
kind: odm/ems [3]
device_classes: [ap/router [3][4], module-in-other-brands [3]]
found_in: ["Nokia E-140W-P EPON ONU, T&W as ODM [4]", "ASUS, D-Link, Belkin, Motorola, eero, Netgear, ZyXEL, Sagemcom and SmartRG routers and DSL modems listed as made by Shenzhen Gongjin Electronics, formerly T&W [2][3]", "T&W BE126 Wi-Fi repeater [5]"]
radios: ["Wi-Fi 4 [4]", "2.4 GHz [4]"]
silicon: ["Broadcom BCM68380 SoC with a Broadcom BCM43217T radio in the Nokia E-140W-P [4]", "MediaTek MT7621AT in D-Link DIR-878 and Motorola MR2600 builds, Qualcomm IPQ8062 in the eero Home (A010001), per the Gongjin product list [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["T&W BE126 Wi-Fi repeater: authenticated command injection in cgi-bin/webupg (CVE-2017-13713) and no firmware authentication on upgrade (CVE-2018-9232) [5]"]
confidence: {country: documented, silicon: inferred, radios: inferred, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists 43 MA-L blocks, one MA-M and one MA-S block to "Taicang T&W Electronics" and one MA-L block to "T&W Electronics Company", all at 89# Jiang Nan Road, given as Lu Du, Taicang or as Suzhou, Jiangsu [1]. Shenzhen Gongjin Electronics says it was formerly called T&W, was founded in 1991, listed on the Shanghai Stock Exchange in February 2015 (603118), names Taicang among its R&D, sales and production sites, and makes FTTx, cable, xDSL and Wi-Fi access equipment, enterprise switches and access points, 5G fixed wireless access, automotive electronics and smart-home devices [2]. That Taicang T&W Electronics is the Taicang arm of Gongjin is inferred from the shared T&W name and the Taicang site; the sources do not name it as a subsidiary [2].

A MAC in these blocks is most likely a broadband gateway, router or ONT that T&W built for an operator or another brand. DeviWiki lists T&W as the ODM of the Nokia E-140W-P EPON ONU, a Broadcom BCM68380 unit with a BCM43217T 2x2 802.11n radio, though that unit's documented OUI is not a T&W block [4]. DeviWiki's Gongjin page lists dozens of routers and DSL modems made for ASUS, D-Link, Belkin, Motorola, eero, Netgear, ZyXEL, Sagemcom and SmartRG [3].

NVD records an authenticated command injection and unauthenticated firmware upgrade in the T&W BE126 Wi-Fi repeater [5]. Parent, the Taicang entity's founding year, FCC grantee codes and randomization are unknown; the FCC ID databases refused the session's requests.

## Sources
1. IEEE Registration Authority, MA-L, MA-M and MA-S assignments (oui.csv, mam.csv, oui36.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. About us - Shenzhen Gongjin Electronics - http://www.twsz.com/en/about/ (accessed 2026-10-27)
3. Shenzhen Gongjin Electronics - DeviWiki - https://deviwiki.com/wiki/Shenzhen_Gongjin_Electronics (accessed 2026-10-27)
4. Nokia E-140W-P - DeviWiki - https://deviwiki.com/wiki/Nokia_E-140W-P (accessed 2026-10-27)
5. T&W CVE records - NVD - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=T%26W (accessed 2026-10-27)
