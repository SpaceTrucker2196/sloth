---
name: CLOUD NETWORK TECHNOLOGY SINGAPORE PTE. LTD.
aliases: []
affiliates: ["Cloud Network Technology (Samoa) Limited [1]"]
country: CN [2]
parent: Hon Hai Precision Industry (Foxconn) (inferred from community OUI-to-vendor mappings; no filing found) [3][4]
founded: unknown
kind: odm/ems
device_classes: [laptop, module-in-other-brands]
found_in: ["WLAN Pi M4 Wi-Fi 6E M.2 module (MediaTek MT7921K or MT7922) [5][6]", "Foxconn-built laptops' network adapters (community fingerprint rule) [4]"]
radios: ["Wi-Fi 6E 2.4 GHz / 5 GHz / 6 GHz (MediaTek MT7922 / MT7921K module in WLAN Pi M4) [5][6]"]
silicon: ["MediaTek MT7922 and MT7921K in the WLAN Pi M4 Wi-Fi 6E module [5][6]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: documented, found_in: inferred, randomization: unknown}
researched: 2026-10-27
---
## Summary
Cloud Network Technology Singapore Pte. Ltd. is one of the most prolific IEEE registrants with no consumer-facing identity: 61 MA-L blocks under the Singapore name plus three under "Cloud Network Technology (Samoa) Limited" in the Wireshark manuf export [1], with the Singapore entity's registry address actually in Nanning, Guangxi, China (B22 Building, No. 51 Tongle Road, Shajing Town), country code CN [2]. The country field follows that registry address, not the Singapore in the name. Community OUI-normalisation tables fold the name into Foxconn alongside "Hon Hai Precision Ind. Co., Ltd.", and one Wi-Fi fingerprinting rule classifies it as "a Foxconn-built laptop" [3][4]; Foxconn, founded 1974 in Taipei, was estimated in 2012 to build about 40% of the world's consumer electronics, for brands including Apple, Sony, Nintendo, Microsoft, Google and Cisco [7]. That parentage is inferred from these mappings, not from a corporate filing reachable here. The one concretely documented product is the WLAN Pi M4, whose MediaTek MT7921K/MT7922 Wi-Fi 6E M.2 module carries this OUI, which fits the pattern of Foxconn-made Wi-Fi/Ethernet modules inside other brands' laptops and appliances [5][6]. A MAC in these blocks is therefore most likely a laptop or embedded computer's network adapter, with the brand on the lid unrecoverable from the OUI; tri-band 6 GHz capability is possible where the MT7922 is fitted. No public documentation found for FCC grantee codes, MAC randomization behaviour or vendor security advisories under this name.
## Sources
1. Wireshark manuf (OUI database) - https://www.wireshark.org/download/automated/data/manuf (accessed 2026-10-27)
2. maclookup.app 00:41:0E registrant record (Nanning address) - https://maclookup.app/macaddress/00410E (accessed 2026-10-27)
3. korenyako/netok process_manuf.py vendor normalisation ("cloud network technology singapore pte. ltd." -> Foxconn) - https://github.com/korenyako/netok/blob/main/scripts/process_manuf.py (accessed 2026-10-27)
4. AntiHunter vendor_rules.tsv ("cloud network technology  computer  a Foxconn-built laptop") - https://github.com/TheRealSirHaXalot/AntiHunter-Command-Control-PRO/blob/main/apps/backend/data/classify/vendor_rules.tsv (accessed 2026-10-27)
5. jiribrejcha/wifi-vendor-lookup README ("WLAN Pi M4 with MT7922 - Cloud Network Technology Singapore") - https://github.com/jiribrejcha/wifi-vendor-lookup/blob/main/README.md (accessed 2026-10-27)
6. WLAN Pi, M4 hardware ("Mediatek MT7921K or MT7922 (Wi-Fi 6E module)") - https://www.wlanpi.com/ (accessed 2026-10-27)
7. Foxconn - Wikipedia - https://en.wikipedia.org/wiki/Foxconn (accessed 2026-10-27)
