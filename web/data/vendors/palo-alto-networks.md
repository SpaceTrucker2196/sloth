---
name: Palo Alto Networks
aliases: []
country: US [1][2]
parent: public company, Nasdaq-listed (PANW) [1]
founded: 2005 [1]
kind: network-equipment [1][3]
device_classes: [ap/router [1][3]]
found_in: ["PA-series next-generation firewalls, current hardware PA-50R, PA-500, PA-1500, PA-3500, PA-5500 and PA-7500 [1][3]", "VM-series and CN-series virtual and container firewalls [1]"]
radios: ["LTE/5G (integrated 5G cellular) in the PA-50R [3]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["PAN-OS GlobalProtect: unauthenticated command injection with root code execution, attacks exploiting it acknowledged by the vendor (CVE-2024-3400, CVSS-B 10.0) [4]", "PAN-OS SAML authentication bypass when IdP certificate validation is disabled (CVE-2020-2021) [5]"]
confidence: {country: documented, silicon: unknown, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Palo Alto Networks is an American cybersecurity company headquartered in Santa Clara, California, founded in 2005 by Nir Zuk and Rajiv Batra, listed on Nasdaq as PANW since moving from the NYSE in 2021 [1]. The IEEE registry lists 40 MA-L blocks to "Palo Alto Networks", 39 of them at 3000 Tannery Way, Santa Clara [2]. Its products are PA-series hardware firewalls, VM-series and CN-series software firewalls, the Prisma SASE and cloud products and the Cortex security-operations products [1].

A MAC in a Palo Alto Networks block is most likely a firewall interface, physical or virtual, sitting at a network edge or data-center boundary [1][3]. The current hardware runs from the PA-50R, which has integrated 5G cellular connectivity, to the PA-7500 chassis; no current model is described with Wi-Fi [3]. Its PAN-OS firewalls have had critical flaws, most notably CVE-2024-3400, an unauthenticated command injection in GlobalProtect that the vendor said was being exploited in an increasing number of attacks, and CVE-2020-2021, a SAML authentication bypass [4][5].

Silicon and FCC grantee codes are not listed: the FCC ID databases refused requests from this session and no teardown was found, and nothing is filled in from memory. Randomization behaviour is not documented.

## Sources

1. Palo Alto Networks - Wikipedia - https://en.wikipedia.org/wiki/Palo_Alto_Networks (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Palo Alto Networks next-generation firewall hardware - https://www.paloaltonetworks.com/network-security/next-generation-firewall-hardware (accessed 2026-10-27)
4. Palo Alto Networks security advisory CVE-2024-3400 - https://security.paloaltonetworks.com/CVE-2024-3400 (accessed 2026-10-27)
5. NVD CVE-2020-2021 - https://nvd.nist.gov/vuln/detail/CVE-2020-2021 (accessed 2026-10-27)
