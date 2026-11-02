---
name: "TECNO MOBILE LIMITED"
aliases: []
affiliates: []
country: HK [1][2]
parent: Transsion Holdings [1][3]
founded: 2006 [1]
kind: brand
device_classes: [phone [1][4], tablet [1][4], laptop [4], ap/router [1], wearable [4]]
found_in: ["TECNO PHANTOM, CAMON, POVA, SPARK and POP phones [4]", "TECNO Phantom X smartphone (MediaTek Helio G95) [5]", "TECNO MEGABOOK laptops and MEGAPAD tablet [4]"]
radios: ["Wi-Fi 5 [5]", "BLE 4.x/5.x [5]", "LTE/5G [5]"]
silicon: ["MediaTek Helio G95 in TECNO Phantom X [5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["2020: Triada backdoor and xHelper trojan found preinstalled on TECNO W2 phones sold in Africa, attributed to the supply chain (Upstream Secure-D) [6]", "CVE-2026-10510: cross-site scripting in the GeniexWebView component of the Transsion AI Assistant Lifestyle app (com.transsion.aiassistantlifestyle), all versions on Android [7]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

TECNO Mobile was established in 2006 and is a subsidiary of Transsion Holdings, with a registered office in the New Territories, Hong Kong and operational headquarters in Shenzhen; its line-up covers phones, tablets, routers and accessories in the Camon, Phantom, Spark and Pova series [1]. Transsion runs the TECNO, itel and Infinix brands and sells in Africa, West, South and Southeast Asia and South America [3]. TECNO's site also lists MEGABOOK laptops, a MEGAPAD tablet and smart wearables, audio and home products [4]. The IEEE registry lists 54 MA-L blocks to "TECNO MOBILE LIMITED" at a Tsim Sha Tsui, Kowloon, Hong Kong address [2]; four further blocks to "SHENZHEN TECNO TECHNOLOGY " are a separate Shenzhen registrant that no source consulted ties to TECNO Mobile, so it is not folded in here [2].

A MAC in a TECNO block is most likely a TECNO phone [1][2]. The TECNO Phantom X is documented with a MediaTek Helio G95, 802.11 b/g/n/ac Wi-Fi, Bluetooth 5.0 and 4G LTE [5]. In August 2020 Upstream's Secure-D reported the Triada backdoor, which downloaded the xHelper trojan, preinstalled on TECNO W2 phones, blocking fraudulent transactions from Ethiopia, Cameroon, Egypt, Ghana, South Africa and other countries; Google attributed it to an actor in the supply chain, and Secure-D found no sign of it on other Transsion models [6]. NVD lists CVE-2026-10510, a medium-severity cross-site scripting flaw in the GeniexWebView component of Transsion's AI Assistant Lifestyle app, all versions on Android [7].

Randomization is unknown: no source consulted states the default on TECNO's HiOS. FCC grantee codes are not listed because the FCC ID databases refused automated access from the session that wrote this entry, and iFixit has no TECNO teardown; nothing is filled in from memory.

## Sources
1. Tecno Mobile - Wikipedia - https://en.wikipedia.org/wiki/Tecno_Mobile (accessed 2026-10-27)
2. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
3. Transsion - Wikipedia - https://en.wikipedia.org/wiki/Transsion (accessed 2026-10-27)
4. TECNO Mobile global site - https://www.tecno-mobile.com/ (accessed 2026-10-27)
5. Tecno Phantom X - Wikipedia - https://en.wikipedia.org/wiki/Tecno_Phantom_X (accessed 2026-10-27)
6. Tecno smartphone reportedly comes with malware preinstalled - Techzim - https://techzim.co.zw/2020/08/tecno-smartphone-reportedly-comes-with-malware-preinstalled (accessed 2026-10-27)
7. NVD CVE API, CVE-2026-10510 - https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-10510 (accessed 2026-10-27)
