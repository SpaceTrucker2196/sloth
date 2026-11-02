---
name: Cambium Networks Limited
aliases: []
country: US [1][2]
parent: Univastu India Limited, which completed its acquisition on 14 October 2026 [1]
founded: 2011 [1]
kind: network-equipment [1][3]
device_classes: [ap/router [1][4][5], switch [3]]
found_in: ["ePMP fixed-wireless access points and subscriber modules, including the ePMP 3000 and 4000 series and Force 130 to 4625 [4]", "cnPilot and X-series Wi-Fi access points and the RV22 home mesh router [5]", "PMP (formerly Canopy) and PTP (formerly Orthogon) lines bought from Motorola Solutions [1]", "Xirrus Wi-Fi products, acquired in July 2019 [1]"]
radios: ["Wi-Fi 5/6/6E/7 [5]", "2.4 GHz [5]", "5 GHz [4][5]", "6 GHz [4][5]", "900 MHz and 3 GHz fixed wireless [1]", "802.11ax fixed wireless with GPS synchronisation [4]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["ePMP firmware 3.5 and earlier: non-administrative users can change other users' passwords (CVE-2017-5254) [6]", "cnPilot firmware 4.3.2-R4 and earlier: undocumented root web shell (CVE-2017-5259) and missing CSRF protection (CVE-2017-5263) [7][8]", "Enterprise Wi-Fi System Software before 6.4.2: unsanitised ping host argument in device-agent (CVE-2022-35908) [9]", "ePMP Force 300-25 4.7.0.1: code injection allowing remote code execution (CVE-2023-6691) [10]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Cambium Networks was created in October 2011 when Motorola Solutions sold its Canopy and Orthogon wireless businesses, went public on Nasdaq as CMBM in 2019, and is headquartered in Hoffman Estates, Illinois [1][3]. Its IEEE blocks, nine MA-L assignments, are registered to "Cambium Networks Limited" at Ashburton, Devon, in the UK, where Cambium still keeps an office [2][3]. Wikipedia reports a Chapter 11 filing on 10 September 2026 and an acquisition by Univastu India Limited completed on 14 October 2026, after which Cambium operates as a standalone Univastu subsidiary [1].

A MAC in a Cambium block is most likely outdoor fixed-wireless gear used by broadband providers, enterprises and utilities, or an enterprise Wi-Fi access point or switch [1][3]. The ePMP line runs from 4910 MHz in the ePMP 4500 up to 7.125 GHz in the 6 GHz ePMP 4600 series, with 802.11ax-based radios in the 4000 series and GPS synchronisation [4]; the Wi-Fi line spans cnPilot Wi-Fi 5 access points through X7 Wi-Fi 7 access points on 2.4, 5 and 6 GHz, plus the RV22 home mesh router [5]. Wikipedia also names 900 MHz and 3 GHz fixed-wireless products and the Xirrus Wi-Fi line acquired in 2019 [1].

NVD lists firmware flaws in ePMP and cnPilot, including an undocumented root web shell in cnPilot 4.3.2-R4 and earlier, and a remote code execution flaw in the ePMP Force 300-25 [6][7][8][9][10]. Silicon and FCC grantee codes are not listed: the FCC ID databases refused requests from this session and no teardown was found, and nothing is filled in from memory. Randomization is unknown because these are infrastructure devices with no documented behaviour.

## Sources

1. Cambium Networks - Wikipedia - https://en.wikipedia.org/wiki/Cambium_Networks (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. About Cambium Networks - https://www.cambiumnetworks.com/about-cambium/ (accessed 2026-10-27)
4. Cambium ePMP products - https://www.cambiumnetworks.com/products/epmp (accessed 2026-10-27)
5. Cambium Wi-Fi products - https://www.cambiumnetworks.com/products/wifi/ (accessed 2026-10-27)
6. NVD CVE-2017-5254 - https://nvd.nist.gov/vuln/detail/CVE-2017-5254 (accessed 2026-10-27)
7. NVD CVE-2017-5259 - https://nvd.nist.gov/vuln/detail/CVE-2017-5259 (accessed 2026-10-27)
8. NVD CVE-2017-5263 - https://nvd.nist.gov/vuln/detail/CVE-2017-5263 (accessed 2026-10-27)
9. NVD CVE-2022-35908 - https://nvd.nist.gov/vuln/detail/CVE-2022-35908 (accessed 2026-10-27)
10. NVD CVE-2023-6691 - https://nvd.nist.gov/vuln/detail/CVE-2023-6691 (accessed 2026-10-27)
