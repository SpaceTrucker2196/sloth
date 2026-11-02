---
name: Thomson Telecom Belgium
aliases: []
affiliates: []
country: BE [1]
parent: Thomson, renamed Technicolor in 2010 and Vantiva in 2022, which keeps an office in Edegem (inferred from the name and address) [2]
founded: unknown
kind: network-equipment [3]
device_classes: [ap/router [3][4]]
found_in: ["Thomson SpeedTouch ADSL modems and gateways, e.g. ST580, ST585, ST780, made by Thomson Multimedia 2001-2009 (inferred) [3]", "BT Home Hub, counted among the Thomson SpeedTouch routers using the same default-key algorithm [4]", "Thomson SpeedTouch ST585v6 routers supplied by Orange in Spain [4]"]
radios: ["802.11b (ST570) [3]", "802.11g (ST580) [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["Default SSID and WEP/WPA key both derived from a SHA-1 hash of the serial number, so a six-hex-digit default SSID narrows the key to about two candidates (2008) [4]", "Manufacturer's default SSID and WEP/WPA-PSK password algorithm easily compromised [3]", "2002 SDSC advisory: multiple flaws in Alcatel SpeedTouch devices including a challenge-response backdoor bypassing the user password [3]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE registry lists nine MA-L blocks to "Thomson Telecom Belgium" at Prins Boudewijnlaan 47, Edegem, Antwerp [1]. Thomson renamed itself Technicolor in 2010 and became Vantiva in 2022; Vantiva's Connected Home division makes broadband gateways and set-top boxes and the company lists Edegem, Belgium among its offices [2]. The SpeedTouch line of ADSL modems, residential gateways and wireless access equipment was made by Alcatel from 1999 to 2001 and by Thomson Multimedia from 2001 to 2009, after Alcatel sold its DSL business to Thomson, and was rebranded "Thomson Gateway" in 2009 [3].

A MAC in these blocks is most likely a SpeedTouch or Thomson Gateway DSL router handed out by an ISP; the link between this Belgian entity and that product line is inferred from the name and the Edegem address, not stated by a source [1][2][3]. The wireless models ran 802.11b (ST570) and then 802.11g with WPA (ST580) [3]. GNUCITIZEN showed in 2008 that SpeedTouch routers, including the BT Home Hub, derive both the default SSID and the default key from a SHA-1 hash of the serial number, so a six-hex-digit SSID narrows the key to about two candidates [4]. A 2002 San Diego Supercomputer Center advisory also reported flaws in Alcatel SpeedTouch devices that allowed full takeover, including a challenge-response backdoor [3].

Chipsets, founding year and FCC grantee codes are not documented by the sources consulted; the FCC ID databases refused automated access from this session.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Vantiva - Wikipedia - https://en.wikipedia.org/wiki/Vantiva (accessed 2026-10-27)
3. SpeedTouch - Wikipedia - https://en.wikipedia.org/wiki/SpeedTouch (accessed 2026-10-27)
4. Default Key Algorithm in Thomson and BT Home Hub Routers - GNUCITIZEN - https://www.gnucitizen.org/blog/default-key-algorithm-in-thomson-and-bt-home-hub-routers/ (accessed 2026-10-27)
