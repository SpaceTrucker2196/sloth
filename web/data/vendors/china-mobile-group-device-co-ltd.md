---
name: "China Mobile Group Device Co.,Ltd."
aliases: []
country: CN [1]
parent: China Mobile, as one of its first specialised subsidiaries [2]
founded: 2011 [2]
kind: carrier/isp
device_classes: [ap/router [3], iot-sensor [2]]
found_in: ["CMCC RAX3000M Wi-Fi 6 router, whose stock boot log shows a Wi-Fi address in the C0:2D:2E block [3][1]"]
radios: ["Wi-Fi 6 (RAX3000M) [3]", "2.4 GHz [3]", "5 GHz [3]", "LTE/5G (5G devices and NB-IoT terminals in the company's remit) [2]"]
silicon: ["MediaTek MT7981 (device tree mt7981b-cmcc-rax3000m) in CMCC RAX3000M [3]"]
fcc_grantee: []
randomization: unknown
security_notes: []
confidence: {country: documented, silicon: documented, radios: inferred, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

China Mobile Group Device Co., Ltd. is the device subsidiary of the operator China Mobile, described by a Tsinghua University recruitment profile as one of China Mobile's first specialised subsidiaries, established in October 2011, with a remit covering 5G devices, NB-IoT terminals and smart hardware [2]. The IEEE registry lists 76 MA-L blocks to "China Mobile Group Device Co.,Ltd." at 32 Xuanwumen West Street in Beijing's Xicheng District [1].

A MAC in one of these blocks is most likely operator-supplied home equipment: OpenWrt documents the CMCC RAX3000M, an 802.11ax two-stream router on 2.4 GHz and 5 GHz built on a MediaTek MT7981 (its OpenWrt device tree is named mt7981b-cmcc-rax3000m), whose stock firmware boot log shows a Wi-Fi interface address beginning c0:2d:2e [3], a block registered to this company [1]. Other products in the company's stated range, such as 5G devices and NB-IoT terminals, were not tied to a specific model or address in any source consulted [2].

No FCC grantee code is listed: the FCC ID databases refused requests from the session that wrote this entry, and the products found are sold in China. No advisories naming the company were found, and randomization is unknown.

## Sources

1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. China Mobile Group Device Co., Ltd. - Tsinghua University Career Development Center - https://career.tsinghua.edu.cn/careeren/info/1008/1079.htm (accessed 2026-10-27)
3. CMCC RAX3000M - OpenWrt Table of Hardware - https://openwrt.org/toh/cmcc/rax3000m (accessed 2026-10-27)
