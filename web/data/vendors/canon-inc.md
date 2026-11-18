---
name: CANON INC.
aliases: []
affiliates: []
country: JP [1][2]
parent: independent, listed on the Tokyo Stock Exchange [2]
founded: 1937 [2]
kind: brand [2]
device_classes: [camera [2][3], printer [2][4]]
found_in: ["Canon EOS 80D DSLR, which joins Wi-Fi networks and speaks PTP over them [3]", "Canon Satera, imageCLASS and i-SENSYS small office multifunction and laser printers [4]"]
radios: ["Wi-Fi (EOS 80D connects to access points) [3]", "NFC (EOS 80D) [5]"]
silicon: ["DIGIC 6 image processor in the EOS 80D [5]"]
fcc_grantee: ["AZD [6]"]
randomization: unknown
security_notes: ["Six PTP flaws in Canon DSLR firmware (CVE-2019-5994, -5995, -5998, -5999, -6000, -6001) let an attacker on the same LAN, for example via a rogue access point, take over the camera; CVE-2019-5995 is a zero-interaction remote firmware update, demonstrated with ransomware on an EOS 80D (Check Point, 2019) [3]", "CVE-2023-0851: buffer overflow in the CPCA Resource Download process of Canon office and small office multifunction and laser printers, firmware 11.04 and earlier, letting an attacker on the network segment make the printer unresponsive or run code (2023) [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists twenty-five MA-L blocks to "CANON INC.", almost all at 30-2 Shimomaruko 3-chome, Ohta-ku, Tokyo [1]. Canon is the Japanese imaging company headquartered at that Ota, Tokyo address, founded on 10 August 1937 by its infobox (the article's history section traces it to a 1933 precision-optics laboratory), listed on the Tokyo Stock Exchange, and making cameras, camcorders, lenses, printers, photocopiers, scanners and ophthalmic instruments [2].

A MAC in these blocks is most likely a camera or a printer on the local network [1][2]. Canon cameras such as the EOS 80D join Wi-Fi networks and speak the Picture Transfer Protocol over them; in 2019 Check Point found six PTP flaws in Canon's firmware, including a remote firmware update needing no user interaction, and demonstrated ransomware on an EOS 80D reached through a rogue access point, after which Canon advised users not to connect the camera to a PC or mobile device used on an unsecure network [3]. The EOS 80D uses a DIGIC 6 processor and added built-in NFC [5]. Canon's office and small office multifunction and laser printers with firmware 11.04 and earlier carry CVE-2023-0851, a buffer overflow an attacker on the network segment can use to make the device unresponsive or execute code [4]. The FCC grantee code AZD is listed for Canon [6].

Randomization is not documented by the sources consulted, and the FCC ID databases refused automated access from this session, so no filing under AZD was checked.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Canon Inc. - Wikipedia - https://en.wikipedia.org/wiki/Canon_Inc. (accessed 2026-10-27)
3. Hack of a Canon EOS 80D DSLR - Threatpost - https://threatpost.com/hack-of-a-canon-eos-80d-dslr/147214 (accessed 2026-10-27)
4. CVE-2023-0851 record - CVE Program - https://cveawg.mitre.org/api/cve/CVE-2023-0851 (accessed 2026-10-27)
5. Canon EOS 80D - Wikipedia - https://en.wikipedia.org/wiki/Canon_EOS_80D (accessed 2026-10-27)
6. FCC ID quick reference - Deskthority wiki - https://deskthority.net/wiki/FCC_ID_quick_reference (accessed 2026-10-27)
