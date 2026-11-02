---
name: Wi-Fi Alliance
aliases: []
affiliates: []
country: US [1][3]
parent: independent [1]
founded: 1999 [1]
kind: other
device_classes: [unknown]
found_in: []
radios: ["Wi-Fi (the OUI appears in 802.11 vendor-specific information elements and NAN identifiers, not as a radio product) [4][5][9]"]
silicon: []
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: unknown, radios: documented, found_in: unknown, randomization: unknown}
researched: 2026-10-27
---
## Summary
Wi-Fi Alliance is not a manufacturer: it is the American non-profit trade association, founded in 1999 and based in Austin, Texas, that owns the Wi-Fi trademark and certifies interoperability, running programmes such as Wi-Fi Direct, Wi-Fi Aware (NAN), Passpoint, WPA3 and Easy Connect [1]. It holds two IEEE MA-L blocks, 50:6F:9A (registered 11 April 2010, at 3925 W. Braker Lane, Austin) and D4:5C:70 (5 October 2012) [2][3]. The 50:6F:9A block is used as a protocol identifier rather than as a pool of NIC addresses: wpa_supplicant defines OUI_WFA as 0x506f9a and derives the WFA vendor-specific IE types from it, including P2P (type 9), Wi-Fi Display (10), Hotspot 2.0 indication (16), OSEN (18), NAN (0x13), MBO (22), Multi-AP (0x1b), OWE transition (28), DPP (0x1e), QoS Management (0x22) and WFA Capabilities (0x23) [4], and Wireshark's NAN dissector defines the same NAN IE type 0x13 and NAN action type 0x18 [9]. The NAN (Wi-Fi Aware) network ID is likewise built from this OUI with the local bit set: wpa_supplicant hard-codes it as 51:6f:9a:01:00:00 [5]. Wi-Fi Aware, announced January 2015, lets devices discover each other and open data paths without an access point by forming clusters managed by the OS; Android has shipped it since 8.0 (API 26) [6][7][8]. So a passive monitor that records "devices" in the Wi-Fi Alliance block is most likely seeing protocol-defined addresses from Aware/NAN or other WFA programmes carried in frames from ordinary phones and laptops, not hardware from a vendor called Wi-Fi Alliance; the exact NAN cluster-ID address range was not found in a fetchable public source in this research, so it is not asserted here. There is no silicon, FCC grantee or product line to document, and randomization does not apply to a registrant that ships no devices.
## Sources
1. Wikipedia - Wi-Fi Alliance - https://en.wikipedia.org/wiki/Wi-Fi_Alliance (accessed 2026-10-27)
2. maclookup.app - Wi-Fi Alliance vendor page - https://maclookup.app/vendors/wi-fi-alliance (accessed 2026-10-27)
3. maclookup.app - OUI 50:6F:9A registration - https://maclookup.app/macaddress/506F9A (accessed 2026-10-27)
4. wpa_supplicant (Android mirror) - src/common/ieee802_11_defs.h, OUI_WFA and WFA OUI types - https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/src/common/ieee802_11_defs.h (accessed 2026-10-27)
5. wpa_supplicant (Android mirror) - src/common/nan_de.c, nan_network_id - https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/main/src/common/nan_de.c (accessed 2026-10-27)
6. Android Developers - Wi-Fi Aware overview - https://developer.android.com/develop/connectivity/wifi/wifi-aware (accessed 2026-10-27)
7. Wi-Fi Alliance - Wi-Fi Aware - https://www.wi-fi.org/discover-wi-fi/wi-fi-aware (accessed 2026-10-27)
8. Wikipedia - Wi-Fi Aware - https://en.wikipedia.org/wiki/Wi-Fi_Aware (accessed 2026-10-27)
9. Wireshark - epan/dissectors/packet-wifi-nan.c - https://gitlab.com/wireshark/wireshark/-/raw/master/epan/dissectors/packet-wifi-nan.c (accessed 2026-10-27)
