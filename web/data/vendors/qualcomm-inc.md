---
name: Qualcomm Inc.
aliases: ["QUALCOMM Incorporated"]
affiliates: []
country: US [1][2]
parent: independent, public on Nasdaq as QCOM [1]
founded: 1985 [1]
kind: chip-vendor [1][3]
device_classes: [phone [4], wearable [4]]
found_in: ["Wi-Fi chipsets used by over 30 wireless device manufacturers (Qualcomm Atheros) [3]", "Snapdragon Mobile, Auto, Compute, IoT and Wearables platforms [4]"]
radios: ["Wi-Fi 4/5 [3]"]
silicon: ["WCN3660 Wi-Fi, Bluetooth and FM combo chip for Snapdragon processors [3]", "WCN3680 802.11ac combo chip for smartphones and tablets [3]", "QCA9531 802.11n 2x2 2.4 GHz Wi-Fi SoC for WLAN platforms [3]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-10538: WLAN host trusts the address range in a modem firmware response, letting a malicious modem write into host memory; Snapdragon Mobile, Auto, IoT and Wearables chipsets [4]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary

Qualcomm is an American technology company founded on July 1, 1985 by
former Linkabit employees led by Irwin Jacobs, headquartered in San
Diego and listed on Nasdaq as QCOM; its products include CDMA/WCDMA
chipsets, the Snapdragon line of processors and Gobi modems [1]. The
IEEE registry lists four MA-L blocks to "Qualcomm Inc." at San Diego
and San Jose addresses and one to "QUALCOMM Incorporated" at 5775
Morehouse Drive, San Diego [2]. Qualcomm took over Atheros in May 2011
and runs it as the subsidiary Qualcomm Atheros, whose 802.11 chipsets
are used by over 30 wireless device manufacturers [3].

Qualcomm Atheros chips ship inside other manufacturers' devices [3],
which normally carry their own OUIs; no source consulted names a device carrying Qualcomm's own blocks, so what sits behind such a MAC is not documented here [3]. The documented Wi-Fi silicon covers 802.11n and
802.11ac: the WCN3660 Wi-Fi, Bluetooth and FM combo for Snapdragon
processors, the WCN3680 802.11ac combo for smartphones and tablets, and
the QCA9531 802.11n 2x2 2.4 GHz SoC [3]. CVE-2019-10538, assigned by
Qualcomm, is an improper input validation flaw in the WLAN host in
which a malicious modem firmware response can write arbitrary pages
into the host's address range, affecting Snapdragon Mobile, Auto,
Compute, IoT and Wearables chipsets [4].

Randomization is a host operating system choice and is unknown here.
FCC grantee codes are not listed: the FCC ID databases (fccid.io,
fcc.report, apps.fcc.gov) refused the session that wrote this entry,
and nothing is filled in from memory.

## Sources
1. Qualcomm - Wikipedia - https://en.wikipedia.org/wiki/Qualcomm (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Qualcomm Atheros - Wikipedia - https://en.wikipedia.org/wiki/Qualcomm_Atheros (accessed 2026-10-27)
4. CVE-2019-10538 - CVE Program record - https://cveawg.mitre.org/api/cve/CVE-2019-10538 (accessed 2026-10-27)
