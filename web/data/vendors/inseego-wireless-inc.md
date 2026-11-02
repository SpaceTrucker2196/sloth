---
name: "Inseego Wireless, Inc"
aliases: []
country: US [1][2]
parent: unknown
founded: unknown
kind: network-equipment [2]
device_classes: [ap/router [2][4]]
found_in: ["Inseego MiFi mobile hotspots sold through Verizon Wireless, AT&T, T-Mobile, Sprint, Rogers and Telstra [2]", "MiFi M2000 5G hotspot, launched first with Verizon (2020) [3]", "Inseego 5G fixed wireless access gateways, Wavemaker FX routers and FastMile gateways [2][4]", "Skyus IoT gateways, routers and modems [2]"]
radios: ["LTE/5G [2][3]", "Wi-Fi 6 [3][4]", "Wi-Fi 7 (FastMile gateway) [4]"]
silicon: ["Qualcomm Snapdragon X55 5G Modem-RF System in the MiFi M2000 [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Novatel Wireless MiFi 2352 firmware 11.47.17 password information disclosure via backup copies of the configuration file (2010, BID 37962, no CVE) [5]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Inseego Corp. is a Delaware corporation formed in 2016 as the successor to Novatel Wireless, Inc.; its FY2020 annual report places corporate offices in San Diego and describes 4G and 5G products including MiFi mobile hotspots, USB modems, 5G fixed wireless access gateways and Skyus IoT gateways, routers and modems, with Verizon Wireless about 55 percent of 2020 revenue and AT&T, T-Mobile, Sprint, Rogers and Telstra among its other carrier customers [2]. The same report names Foxconn and Inventec Appliance Corporation as its contract manufacturers [2]. The IEEE registry lists five MA-L blocks to "Inseego Wireless, Inc" at 9710 Scranton Rd., San Diego [1]; how that entity sits under Inseego Corp. is not stated by the sources consulted, so parent and founding year are left unknown.

A MAC in an Inseego block is most likely the Wi-Fi side of a carrier-branded cellular hotspot or router [2]. The MiFi M2000 combines the Qualcomm Snapdragon X55 5G Modem-RF System with simultaneous dual-band Wi-Fi 6 for up to 30 devices and launched first with Verizon [3]. Inseego's current catalogue adds MiFi X PRO hotspots, Wavemaker FX routers and FastMile Wi-Fi 6 and Wi-Fi 7 gateways [4].

The only advisory found is for the predecessor's MiFi 2352, whose firmware 11.47.17 could let an authenticated attacker obtain passwords from backup copies of its configuration file (exploit-db, 2010, no CVE) [5]. Randomization behaviour and FCC grantee codes are not documented by the sources that could be consulted; the FCC ID databases were not reachable when this entry was verified [2].

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Inseego Corp. Form 10-K for fiscal year 2020 - SEC EDGAR - https://www.sec.gov/Archives/edgar/data/1022652/000102265221000017/insg-20201231.htm (accessed 2026-10-27)
3. Inseego unveils new 5G mobile hotspot, launches first with Verizon - Telecompaper - https://www.telecompaper.com/news/inseego-unveils-new-5g-mobile-hotspot-launches-first-with-verizon--1353284 (accessed 2026-10-27)
4. About us - Inseego - https://inseego.com/company/about-us/ (accessed 2026-10-27)
5. Novatel Wireless MiFi 2352 - Password Information Disclosure - Exploit Database - https://www.exploit-db.com/exploits/33568 (accessed 2026-10-27)
