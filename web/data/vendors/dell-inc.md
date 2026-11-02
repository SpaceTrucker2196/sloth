---
name: Dell Inc.
aliases: []
country: US [1][2]
parent: Dell Technologies [1]
founded: 1984 [1]
kind: brand [1]
device_classes: [laptop [1], switch [1]]
found_in: ["XPS notebooks, and the now-discontinued Latitude and Inspiron lines [1]", "PowerEdge servers [1]", "Dell Networking switches [1]", "Dell Wireless (DW) Wi-Fi cards [3]"]
radios: ["Wi-Fi 4/5 [3]", "2.4 GHz [3]", "5 GHz [3]"]
silicon: ["Broadcom BCM4352 in the DW1550 and DW1560 [3]", "Qualcomm Atheros QCA6174A in the DW1820 [3]", "Broadcom BCM4350 in the DW1820A [3]", "Qualcomm Atheros QCA9377 in the DW1810 [3]", "Broadcom BCM43602 in the DW1830 [3]", "Realtek RTL8723BE in the DW1801 [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["Dell System Detect installed a trusted root certificate with its private key (DSDTestProvider), CERT/CC VU#925497, November 2015, CVSS v2 9.4 [4]"]
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Dell was founded by Michael Dell in Austin in 1984, was renamed Dell Inc.
in 2003, is based in Round Rock, Texas, and has been a subsidiary
of the publicly traded Dell Technologies since 2016 [1]. Its lines
include XPS notebooks, Precision workstations, PowerEdge servers, Dell
Networking switches and gateways, and monitors [1]. The IEEE registry
lists 184 MA-L blocks to "Dell Inc.", almost all at One Dell Way, Round
Rock; Dell EMC, Dell Technologies and a Sunnyvale "Dell" hold separate
blocks under their own names [2].

A MAC in a Dell block is most likely the wired or wireless interface of
a Dell notebook, desktop or server, or a Dell switch [1][2]. DeviWiki
documents the Dell Wireless (DW) cards: 802.11abgn
and 802.11ac cards built on Broadcom (BCM4313, BCM4352, BCM4350,
BCM43602), Atheros and Qualcomm Atheros (AR9285, AR9462, QCA9377,
QCA6174A) and Realtek (RTL8723BE) silicon, plus older TrueMobile cards
[3]. Whether the address is randomised depends on the host operating
system, so randomization is unknown here. In November 2015 CERT/CC
reported that Dell System Detect, pre-installed on some Dell PCs and
tablets, installed the DSDTestProvider root certificate together with
its private key, allowing HTTPS interception and code signing [4]. FCC
grantee codes are not listed: the FCC ID databases refused the session
that wrote this entry, and nothing is filled in from memory.

## Sources

1. Dell - Wikipedia - https://en.wikipedia.org/wiki/Dell (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Dell - DeviWiki - https://deviwiki.com/wiki/Dell (accessed 2026-10-27)
4. VU#925497 Dell System Detect installs root certificate and private key (DSDTestProvider) - CERT/CC - https://www.kb.cert.org/vuls/id/925497 (accessed 2026-10-27)
