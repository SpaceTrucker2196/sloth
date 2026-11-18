---
name: "TCL King Electrical Appliances(Huizhou)Co.,Ltd"
aliases: ["TCL King Electrical Appliances (Huizhou) Co., Ltd"]
affiliates: []
country: CN [1][2]
parent: unknown
founded: unknown
kind: brand [2]
device_classes: [tv [2]]
found_in: ["TCL 65P7K (model code 65P7KX9) 65-inch UHD LCD television, for which it is the manufacturer of record in the EU declaration of conformity [2]"]
radios: ["2.4 GHz (declared against ETSI EN 300 328) [2][6]", "5 GHz (declared against ETSI EN 301 893) [2][7]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2020-27403: TCL Technology Group's Android Smart TV firmware (V8-R851T02-LF1 V295 and below, V8-T658T01-LF1 V373 and below) ran an unauthenticated web server on port 7989 that let an adjacent-network attacker browse and download most system files [4]"]
confidence: {country: documented, silicon: unknown, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

TCL King Electrical Appliances (Huizhou) is a TCL television manufacturing company in Huizhou, Guangdong; the IEEE registry lists its MA-L blocks under two spellings at the TCL Multimedia Building in TCL International E City, Huizhou [1]. It signs the EU declaration of conformity as manufacturer of the TCL 65P7K 65-inch UHD LCD television, giving a factory address in the ZhongKai New and High-tech Industries Development Zone, Huizhou [2]. TCL Technology, the group whose name the company carries, is headquartered in Huizhou, makes TVs among other products and in August 2014 partnered with Roku for use as its primary smart TV platform [3]; TCL Electronics, listed in Hong Kong, is a subsidiary of TCL Industries Holdings, itself a subsidiary of TCL Technology [3][5]. The fetched sources do not state the ownership chain from TCL Technology down to this company, so parent and founding year are left unknown.

A MAC in one of these blocks is most likely a TCL-branded smart TV like the 65P7K [2]. That declaration lists ETSI EN 300 328 and ETSI EN 301 893 among its radio standards [2], the harmonised standards for wideband data transmission in the 2.4 GHz band and for 5 GHz RLAN [6][7], so expect a dual-band Wi-Fi client. NVD records CVE-2020-27403 against TCL Android Smart TV firmware by TCL Technology Group, an unauthenticated file-listing web server on port 7989 reachable from the adjacent network [4]; NVD does not say which manufacturing company built those sets, so the firmware lines are not listed as products in these blocks. Silicon, FCC grantee codes and randomization behaviour are not listed: the FCC ID databases refused access from the session that wrote this entry, and nothing is filled in from memory.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. EU Declaration of Conformity, TCL 65P7K (65P7KX9) - https://www.yettel.bg/sites/default/files/2026-04/TV_TCL_65P7KX9_DOC.pdf (accessed 2026-10-27)
3. TCL Technology - Wikipedia - https://en.wikipedia.org/wiki/TCL_Technology (accessed 2026-10-27)
4. NVD, CVE-2020-27403 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-27403 (accessed 2026-10-27)
5. TCL Electronics - Wikipedia - https://en.wikipedia.org/wiki/TCL_Electronics (accessed 2026-10-27)
6. ETSI EN 300 328 V2.2.2, Wideband transmission systems; Data transmission equipment operating in the 2,4 GHz band - https://www.etsi.org/deliver/etsi_en/300300_300399/300328/02.02.02_60/en_300328v020202p.pdf (accessed 2026-10-27)
7. ETSI EN 301 893 V2.1.1, 5 GHz RLAN - https://www.etsi.org/deliver/etsi_en/301800_301899/301893/02.01.01_60/en_301893v020101p.pdf (accessed 2026-10-27)
