---
name: SimpliSafe
aliases: []
country: US [1]
parent: GTCR (acquisition from Hellman & Friedman completed 12 November 2025) [1]
founded: 2006 [1]
kind: brand
device_classes: [smart-home, camera, iot-sensor]
found_in: ["SimpliSafe Base Station and Keypad (gen 3 uses cellular plus Wi-Fi) [1]", "SimpliCam (2017), Video Doorbell Pro (2018), Wireless Outdoor Security Camera (2021), Smart Alarm Wireless Indoor Camera (2023) [1]", "SimpliSafe Smart Lock (2019) [1]"]
radios: ["Wi-Fi 2.4 GHz (systems and cameras require 2.4 GHz networks) [6]", "LTE/cellular backhaul on the gen-3 Base Station [1]", "433.92 MHz sub-GHz sensor and keypad link, base station replying at 315 MHz (original generation) [4][5]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["IOActive, Feb 2016: original-generation keypad PINs sent as cleartext/replayable on-off-keyed 433 MHz; one-time-programmable MCUs prevented a firmware fix [4]", "CVE-2018-11399/11400/11401/11402: unencrypted sensor and keypad transmissions, no tamper detection, no alert on 433.92 MHz RF interference (SimpliSafe Original) [5]", "CVE-2019-3997, CVE-2020-5727: rogue keypads pairable to an armed SS3 system; CVE-2019-3998: unauthenticated Wi-Fi settings change on SS3 base station fw 1.4 [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary
SimpliSafe is a Boston, Massachusetts self-install home-security brand founded on 11 August 2006 by Chad and Eleanor Laurans, owned by Hellman & Friedman from 2018 until GTCR completed its acquisition on 12 November 2025 [1]. It holds exactly one MA-L block, F8:51:28, registered 1 April 2020 to 294 Washington St, Boston [2][3][7]; one community camera-fingerprint project notes that this single-block registrant passes its narrow-registrant test cleanly but withholds it from its tables until a real unit has been captured on the air [8]. A MAC in this block is a gen-3 SimpliSafe Base Station, camera, doorbell or lock on the house Wi-Fi: the company states its systems and cameras require 2.4 GHz networks, and the gen-3 base also carries a cellular backhaul with lithium battery backup [1][6]. The sensors and keypad do not use Wi-Fi at all; they talk to the base over a 433 MHz link (base replies at 315 MHz), which was unencrypted and replayable in the original generation (IOActive 2016; CVE-2018-11399 to -11402) and was re-engineered with encrypted firmware in 2018 [1][4][5]. The SS3 generation then had three authentication-bypass CVEs in 2019-2020 allowing rogue keypad pairing and unauthenticated Wi-Fi reconfiguration [5]. No public documentation found for the chipsets inside the base station or cameras, for SimpliSafe's FCC grantee code (the FCC ID databases refused automated access), or for MAC randomization behaviour.
## Sources
1. SimpliSafe - Wikipedia - https://en.wikipedia.org/wiki/SimpliSafe (accessed 2026-10-27)
2. maclookup.app F8:51:28 registrant record - https://maclookup.app/macaddress/F85128 (accessed 2026-10-27)
3. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
4. IOActive, "Remotely Disabling a Wireless Burglar Alarm" (17 Feb 2016) - https://ioactive.com/remotely-disabling-a-wireless-burglar-alarm/ (accessed 2026-10-27)
5. NVD CVE API, keyword "simplisafe" (7 results) - https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=simplisafe&resultsPerPage=20 (accessed 2026-10-27)
6. SimpliSafe Help Center ("systems and cameras require 2.4GHz Wi-Fi networks") - https://support.simplisafe.com/ (accessed 2026-10-27)
7. ManySecured D3DB device-type assertion for SimpliSafe - https://github.com/TechWorksHub/ManySecured-D3DB/blob/main/manufacturers/S/SimpliSa/device.type.d3.yaml (accessed 2026-10-27)
8. all-cameras-are-beacons signature notes (SimpliSafe single-block registrant) - https://github.com/soyboi1312/all-cameras-are-beacons/blob/main/docs/signatures.md (accessed 2026-10-27)
