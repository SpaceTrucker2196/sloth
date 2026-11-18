---
name: IEEE Registration Authority
aliases: []
affiliates: []
country: US [1][3]
parent: IEEE Standards Association [2]
founded: unknown
kind: other [2]
device_classes: [unknown]
found_in: []
radios: []
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: unknown, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary

The IEEE Registration Authority is not a device maker: it runs under the IEEE Standards Association, directed by the IEEE SA Board of Governors, and assigns identifiers, among them MA-L blocks (an OUI with large blocks of EUI-48 and EUI-64 values), medium MA-M blocks, small MA-S blocks and 24-bit company IDs [2]. Its registry address is 445 Hoes Lane, Piscataway, New Jersey, where most IEEE business is done at the IEEE Operations Center; the IEEE itself was formed in 1963 and has its corporate office in New York City [1][3].

The registry lists 426 MA-L blocks, one MA-S block and one IAB to the IEEE Registration Authority itself [1]. Comparing the registry files shows that 425 of those 426 MA-L blocks are the parents from which MA-M, MA-S and IAB sub-blocks are assigned to other companies [1]. An IAB is the older form, an MA-L OUI plus 12 IEEE-provided bits leaving the holder 4,096 addresses, replaced by MA-S [4].

So a MAC shown as IEEE Registration Authority is almost always a device of some smaller company holding a sub-block inside one of these OUIs, which a lookup should resolve against the MA-M, MA-S and IAB lists rather than the MA-L list; when it does not, the sub-block's holder is simply unknown [1][4]. No device class, radio, silicon or randomization behaviour belongs to the Registration Authority itself, so those fields are empty or unknown.

## Sources
1. IEEE Registration Authority, MA-L, MA-M, MA-S and IAB assignments (oui.csv, mam.csv, oui36.csv, iab.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. IEEE Registration Authority - IEEE Standards Association - https://standards.ieee.org/products-programs/regauth/ (accessed 2026-10-27)
3. IEEE - Wikipedia - https://en.wikipedia.org/wiki/IEEE (accessed 2026-10-27)
4. Organizationally unique identifier - Wikipedia - https://en.wikipedia.org/wiki/Organizationally_unique_identifier (accessed 2026-10-27)
