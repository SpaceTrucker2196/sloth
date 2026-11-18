---
name: "The Chamberlain Group, Inc"
aliases: []
affiliates: []
country: US [1][2]
parent: "Blackstone Inc. (acquired from The Duchossois Group in 2021) [1]"
founded: 1954 [1]
kind: brand
device_classes: [smart-home, camera]
found_in: ["Chamberlain and LiftMaster Wi-Fi garage door openers that connect through the myQ app [4]", "myQ Smart Garage Control [4]", "myQ Smart Garage Video Keypad and myQ smart cameras [4]", "myQ-controlled smart locks [4]"]
radios: ["Wi-Fi (myQ remote monitoring over Wi-Fi; band and 802.11 generation not documented) [1][4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["November 2023: Chamberlain restricted third-party access to the myQ platform; Home Assistant removed its myQ integration in release 2023.12 (6 December 2023) [1][5]", "December 2025: Chamberlain left the Connectivity Standards Alliance, the body behind Matter, further reducing third-party interoperability [1]", "Home Assistant recommends ratgdo, an ESPHome device wired to the opener that speaks Security+, as the local-control alternative [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
The Chamberlain Group is a garage-door-opener and access-control company founded in 1954 and headquartered in Oak Brook, Illinois; it owns the Chamberlain, LiftMaster, Merlin and Grifco brands and has been a Blackstone portfolio company since 2021 [1]. Its five MA-L blocks (64:52:99 from 2011, CC:6A:10 from 2019, 0C:95:05 from 2022, 44:11:46 from 2024, AC:2B:A2 from 2026) all register to 300 Windsor Drive, Oak Brook [2][3]; a separate IEEE registrant named "Chamberlain Access Solutions" in Scottsdale, Arizona also exists, and its relationship to this entity is not documented in the sources consulted [3]. A MAC in one of these blocks is most likely a myQ endpoint, an inference from the product line: a Wi-Fi garage door opener, the Smart Garage Control, a myQ camera or video keypad, or a myQ lock [4]; myQ provides remote monitoring over Wi-Fi [1], but the product page does not state the band, generation or any Bluetooth radio [4]. The platform is cloud-mediated rather than locally controlled: since November 2023 the company has restricted third-party access to myQ, Home Assistant dropped its integration in December 2023, and in December 2025 Chamberlain left the Connectivity Standards Alliance [1][5]; persistent outbound cloud sessions are the expectation that follows, though no source measures them. The silicon inside myQ hubs and openers is not documented in the sources reachable for this entry (FCC exhibit mirrors fccid.io and fcc.report refused the fetch, and no teardown was reachable), so the chipset, Wi-Fi generation and the FCC grantee code are left unknown rather than guessed. Nothing in the sources speaks to MAC randomization, so it is recorded as unknown.
## Sources
1. Chamberlain Group - Wikipedia - https://en.wikipedia.org/wiki/Chamberlain_Group (accessed 2026-10-27)
2. The Chamberlain Group, Inc MAC address blocks - maclookup.app - https://maclookup.app/vendors/the-chamberlain-group-inc (accessed 2026-10-27)
3. IEEE Registration Authority MA-L registry, the copy committed in sloth as web/data/oui.csv (Debian ieee-data 20260625) - https://github.com/SpaceTrucker2196/sloth/blob/main/web/data/oui.csv (accessed 2026-11-02)
4. myQ Smart Home Products - Chamberlain Group - https://www.myq.com/products (accessed 2026-10-27)
5. Removal of the myQ integration - Home Assistant blog, 2023-11-06 - https://www.home-assistant.io/blog/2023/11/06/removal-of-myq-integration/ (accessed 2026-10-27)
