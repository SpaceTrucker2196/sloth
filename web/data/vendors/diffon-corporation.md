---
name: Diffon Corporation
aliases: []
country: KR [1]
parent: "Franklin Wireless Corp. (acquired ~50.6% of Diffon's capital stock, October 2009) [3]"
founded: unknown
kind: odm/ems
device_classes: [ap/router, module-in-other-brands]
found_in: ["Franklin U772 USB modem / mobile hotspot for C Spire Wireless, 802.11 OUI F4:63:49 [2]", "Franklin Wireless wireless data products generally (Diffon is Franklin's exclusive supplier under a 2009 supply agreement) [3]"]
radios: ["Wi-Fi 4 (802.11b/g/n, 1x1:1, HT20 only) in Franklin U772 [2]", "2.4 GHz [2]", "LTE/5G (LTE + CDMA via Qualcomm MDM9615) in Franklin U772 [2]"]
silicon: ["Qualcomm MDM9615 baseband in Franklin U772 [2]", "Atheros 802.11bgn 1x1:1 Wi-Fi (model not given) in Franklin U772 [2]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
Diffon Corporation is a South Korean company whose single IEEE MA-L block, F4:63:49, was registered on 5 January 2010 to an address at Digital Tower Aston 1505, Seoul [1][4]. Its public footprint is almost entirely through Franklin Wireless Corp. (San Diego): an 8-K filed in October 2009 records Franklin acquiring roughly 50.6% of Diffon's stock via a share exchange and a cash purchase, together with a five-year supply agreement under which "Diffon agrees to supply its products exclusively to the Company" [3]. A MAC in F4:63:49 is therefore most likely a Franklin-branded cellular hotspot or USB modem built by Diffon, not a Diffon-branded device. The one documented example is the Franklin U772, a CDMA/LTE USB dongle-hotspot sold by C Spire Wireless (FCC ID RB2-U772, approved 11 October 2012) that uses a Qualcomm MDM9615 modem and a 1x1 Atheros 802.11b/g/n radio and advertises F4:63:49 as its 802.11 OUI [2]; note that grantee code RB2 belongs to the FCC applicant Franklin, so no Diffon-owned grantee code was identified. On the air, expect a 2.4 GHz-only hotspot AP (and a cellular uplink sloth cannot see) rather than a client. Diffon's own website (diffon.com) could not be fetched in this session because of a TLS certificate mismatch, the FCC ID databases were unreachable (HTTP 403), and web search was unavailable, so founding year, current product line and any security history remain unknown rather than guessed.
## Sources
1. MAC prefix F4:63:49 - maclookup.app - https://maclookup.app/macaddress/F46349 (accessed 2026-10-27)
2. Franklin U772 - DeviWiki - https://deviwiki.com/wiki/Franklin_U772 (accessed 2026-10-27)
3. Franklin Wireless Corp. Form 8-K, filed 2009-10-21 (accession 0001019687-09-003747) - SEC EDGAR - https://www.sec.gov/Archives/edgar/data/722572/000101968709003747/franklin_8k-101909.txt (accessed 2026-10-27)
4. Diffon Corporation MAC address blocks - maclookup.app - https://maclookup.app/vendors/diffon-corporation (accessed 2026-10-27)
