---
name: Bose Corporation
aliases: []
country: US [1][2]
parent: private, majority-owned by MIT through non-voting shares [2]
founded: 1964 [2]
kind: brand [2]
device_classes: [speaker [2], wearable [2], smart-home [2]]
found_in: ["QuietComfort noise-cancelling headphones [2]", "SoundLink portable Bluetooth speakers [2]", "SoundTouch speakers [3][4]", "soundbars and home theater systems [2]"]
radios: ["Bluetooth (headphones and SoundLink speakers) [2]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2017-17751: SoundTouch devices remotely controllable from a crafted web site over WebSocket [4]", "CVE-2017-17749 and CVE-2017-17750: XSS in SoundTouch via crafted Pandora song data or Spotify playlists [6][7]", "CVE-2017-6520: SoundTouch 30 mDNS responder answers off-link unicast queries, usable for traffic amplification [3]", "April 2017 lawsuit alleging a privacy violation by Bose's headphone control apps [2]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Bose is a private US audio company founded in 1964 by Amar Bose and headquartered in Framingham, Massachusetts; MIT is its majority owner through non-voting shares donated in 2011 [2]. The IEEE registry lists 13 MA-L blocks under "Bose Corporation", 12 at The Mountain, Framingham and one for the Automotive Systems Division in Stow, Massachusetts [1]; the "Transom Post OpCo LLC dba Bose Professional" MA-M block is a separate registrant and is not aliased here [5]. Bose sells QuietComfort noise-cancelling headphones, SoundLink portable Bluetooth speakers, soundbars, home theater systems and smart-home devices, so a MAC in a Bose block is most likely a Bluetooth headphone or speaker, or a networked speaker [2].

The SoundTouch networked speakers drew several records: remote control from a crafted web site over WebSocket (CVE-2017-17751) and cross-site scripting through crafted music-service data (CVE-2017-17749, CVE-2017-17750) [6][7], and an mDNS responder on the SoundTouch 30 that answered off-link unicast queries (CVE-2017-6520) [3]. In April 2017 Bose was sued over alleged privacy violations by the apps that control its Bluetooth headphones [2]. Silicon, Wi-Fi radios and FCC grantee codes are not listed: no teardown was found and the FCC ID databases refused automated access from the session that wrote this entry, and nothing is filled in from memory; randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Bose Corporation - Wikipedia - https://en.wikipedia.org/wiki/Bose_Corporation (accessed 2026-10-27)
3. NVD - CVE-2017-6520 - https://nvd.nist.gov/vuln/detail/CVE-2017-6520 (accessed 2026-10-27)
4. NVD - CVE-2017-17751 - https://nvd.nist.gov/vuln/detail/CVE-2017-17751 (accessed 2026-10-27)
5. IEEE Registration Authority, MA-M assignments (mam.csv) - https://standards-oui.ieee.org/oui28/mam.csv (accessed 2026-10-27)
6. NVD - CVE-2017-17749 - https://nvd.nist.gov/vuln/detail/CVE-2017-17749 (accessed 2026-10-27)
7. NVD - CVE-2017-17750 - https://nvd.nist.gov/vuln/detail/CVE-2017-17750 (accessed 2026-10-27)
