---
name: Sagemcom Broadband SAS
aliases: []
country: FR [1]
parent: "Charterhouse Capital Partners LLP (70%) and employees (30%); Charterhouse bought it from The Carlyle Group in October 2016 [1]"
founded: 2007 [1]
kind: network-equipment
device_classes: [ap/router, tv]
found_in: ["Orange Livebox [1]", "Bouygues Telecom Wi-Fi 6 box (January 2020) [1]", "Spectrum (Charter) RAC2V1S = Sagemcom F@ST 5280 [6]", "F@ST 3686 and F@ST 3890 cable gateways, F@ST 1704 / 2704N / 3965CV DSL routers, DCIW387 / DIW387 set-top boxes [5]", "Smart-grid / energy metering products [1]"]
radios: ["Wi-Fi 6: Bouygues box (2020) [1]", "Wi-Fi 5 (802.11ac Wave 2, 4x4 5 GHz + 3x3 2.4 GHz) on F@ST 5280 [6]; 802.11ac 3x3 + 802.11n 2x2 on F@ST 3686 V2.2 [5]", "Wi-Fi 4 (802.11b/g/n) on F@ST 1704 / 2704N DSL routers [5]", "2.4 GHz [5][6]", "5 GHz [5][6]", "DOCSIS cable gateways (F@ST 3686, F@ST 3890) [5]"]
silicon: ["Broadcom BCM4906 SoC with BCM4366E (5 GHz 4x4) and BCM4365E (2.4 GHz 3x3) in F@ST 5280 / Spectrum RAC2V1S [6]", "Broadcom BCM7271U in DCIW387 / DIW387 set-top boxes [5]", "Broadcom BCM3384ZU with BCM4360 (5 GHz 3x3) and BCM43217 (2.4 GHz 2x2) radios in F@ST 3686 V2.2 [5]", "Broadcom BCM6338 with BCM4312 radio in F@ST 1704, BCM6318 in F@ST 2704N [5]", "Ikanos IKF7185 with Atheros AR9382 / AR9580 radios in F@ST 3965CV [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE records are indexed for F@ST 3686, F@ST 5280, F@ST 3890 and Livebox firmware (CIRCL vulnerability-lookup product index; the individual CVE IDs and descriptions could not be verified this session) [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Sagemcom Broadband SAS is the Bois-Colombes, France maker of operator broadband gateways, set-top boxes and smart-grid equipment that emerged from the 2008 break-up of Sagem's communications business after the Safran merger [2]; Wikipedia dates the company to 2007 as Sagem Communications (renamed Sagemcom in 2010), and it is now 70% owned by Charterhouse Capital Partners and 30% by employees, with EUR 2.3 billion revenue and 6,500 staff in 2024 [1]. It is an ISP-supplied CPE vendor rather than a retail brand: its boxes ship as the Orange Livebox and a Bouygues Telecom Wi-Fi 6 box in France [1] and the Spectrum RAC2V1S in the US [6], and the registrant holds 219 MA-L blocks [8], so a Sagemcom MAC is almost always the home gateway, Wi-Fi extender or TV box an operator installed. Expect a dual-band access point: installed-base units such as the F@ST 5280 are 802.11ac Wave 2 on Broadcom BCM4906 / BCM4366E / BCM4365E silicon [6], the F@ST 3686 V2.2 cable gateway pairs a Broadcom BCM3384ZU with BCM4360 and BCM43217 radios, and older DSL models run Broadcom BCM6338 / BCM6318 or an Ikanos IKF7185 with Atheros radios [5]. The Wi-Fi 7, Wi-Fi 6E and 5G CPE grants that an earlier draft of this entry took from fccid.io grantee VW3 were removed because those pages returned HTTP 403 on verification, so no FCC grantee code is recorded. MAC randomization does not apply to this infrastructure role and no statement was found, so it is recorded as unknown. The CIRCL vulnerability index lists CVE-bearing firmware for the F@ST 3686, F@ST 5280, F@ST 3890 and the Livebox [7]; the individual advisories were not reachable, so none is quoted.
## Sources
1. Sagemcom - Wikipedia - https://en.wikipedia.org/wiki/Sagemcom (accessed 2026-10-27)
2. Sagem - Wikipedia - https://en.wikipedia.org/wiki/Sagem (accessed 2026-10-27)
3. SAGEMCOM BROADBAND SAS FCC ID Applications (VW3) - fccid.io (not reachable 2026-10-27, HTTP 403; the grantee code and the Wi-Fi 7 / 6E / 5G CPE list cited to it were removed) - https://fccid.io/VW3 (accessed 2026-10-27)
4. FCC ID VW3FAST5297 - WiFi 7 Router - fccid.io (not reachable 2026-10-27, HTTP 403; the band list cited to it was removed) - https://fccid.io/VW3FAST5297 (accessed 2026-10-27)
5. Sagemcom - DeviWiki (ex WikiDevi) - https://deviwiki.com/wiki/Sagemcom (accessed 2026-10-27)
6. Sagemcom F@ST 5280 - DeviWiki (ex WikiDevi) - https://deviwiki.com/wiki/Sagemcom_F@ST_5280 (accessed 2026-10-27)
7. CVE search sagemcom (products f@st_3686_firmware, f@st_5280_router_firmware, f@st_3890_firmware, livebox_firmware) - CIRCL vulnerability-lookup API (the product index was reachable; the individual CVE IDs were not shown by it) - https://cve.circl.lu/api/browse/sagemcom (accessed 2026-10-27)
8. Sagemcom Broadband SAS MAC address blocks - maclookup.app - https://maclookup.app/vendors/sagemcom-broadband-sas (accessed 2026-10-27)
