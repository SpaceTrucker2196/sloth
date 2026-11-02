---
name: Avaya Inc
aliases: [Avaya LLC]
country: US [1][2]
parent: privately owned by its former creditors since the 2023 restructuring [1]
founded: 2000 [1]
kind: network-equipment [1]
device_classes: [phone [1], switch [1], ap/router [1]]
found_in: ["1100-series and 9600-series IP deskphones [1]", "VSP and ERS series routers and switches [1]", "IP Office and Aura communications servers and software [4][5]"]
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: ["IP Office before 11.1.3.1: improper input validation in the Web Control component allowing remote command or code execution (CVE-2024-4196) [4]", "Aura Device Services: OS command injection allowing remote code execution (CVE-2023-3722) [5]"]
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Avaya is an enterprise communications company headquartered in Morristown, New Jersey, spun off from Lucent in 2000 [1]. It was taken private by TPG Capital and Silver Lake in 2007, went through Chapter 11 in 2017 and again in 2023, and since its May 2023 restructuring operates as Avaya LLC, owned by its former creditors [1]. The IEEE registry lists 52 MA-L blocks to "Avaya Inc" and one to "Avaya LLC", all at Morristown addresses [2].

A MAC in an Avaya block is most likely an IP desk phone such as the 1100 or 9600 series, or a server or appliance running its IP Office or Aura communications software [1][4][5]. Older blocks may also belong to VSP or ERS switches and routers [1]; Extreme Networks bought Avaya's networking business in 2017 [3]. NVD lists a remote code execution flaw in Avaya IP Office and an OS command injection in Aura Device Services [4][5].

The sources consulted document no Wi-Fi or Bluetooth radios, silicon or FCC grantee codes for Avaya devices: the FCC ID databases refused requests from this session and Avaya's device pages were not reachable, and nothing is filled in from memory. Randomization behaviour is not documented.

## Sources

1. Avaya - Wikipedia - https://en.wikipedia.org/wiki/Avaya (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Extreme Networks - Wikipedia - https://en.wikipedia.org/wiki/Extreme_Networks (accessed 2026-10-27)
4. NVD CVE-2024-4196 - https://nvd.nist.gov/vuln/detail/CVE-2024-4196 (accessed 2026-10-27)
5. NVD CVE-2023-3722 - https://nvd.nist.gov/vuln/detail/CVE-2023-3722 (accessed 2026-10-27)
