---
name: Rivet Networks
aliases: []
affiliates: []
country: US [1]
parent: Intel, which acquired Rivet Networks in May 2020 [2][3]
founded: unknown
kind: brand [3]
device_classes: [laptop [3][5], module-in-other-brands [5]]
found_in: ["Killer network adapters in Dell/Alienware, MSI, Gigabyte and Acer machines (Rivet, 2015) [4]", "Dell XPS 17 [3]", "Killer Wireless-AC 1535 M.2 card, tested in MSI GT72S and GE72 notebooks [5]"]
radios: ["Wi-Fi 5 (802.11ac, Killer Wireless-AC 1535) [5]", "2.4 GHz [5]", "5 GHz [5]", "BT Classic and BLE (Bluetooth 4.1 on the AC 1535) [5]", "Wi-Fi 6 (Killer Wi-Fi 6 AX1650, a joint Intel-Rivet design) [2]"]
silicon: ["Qualcomm Atheros QCA6174 in Killer Wireless-AC 1535 (subsystem 1a56:1535) [6][5]"]
fcc_grantee: []
randomization: unknown
security_notes: ["CVE-2019-15661, stack-based buffer overflow giving ring 0 code execution in the KfeCo10X64.sys driver of Rivet Killer Control Center, fixed October 2019 [7]", "CVE-2021-26258 (INTEL-SA-00644), improper access control in Intel Killer Control Center before 2.4.3337.0, CVSS 6.7 [8]"]
confidence: {country: documented, silicon: documented, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Rivet Networks made the Killer line of network adapters and the Killer Control Center software [2]; the IEEE registry lists one MA-L block under this name at an Austin, Texas, address [1]. In a November 2015 interview Rivet recounted that Qualcomm Atheros acquired Bigfoot Networks, the original Killer NIC maker, in 2011, and it said Killer was sold in Dell/Alienware, MSI, Gigabyte and Acer machines [4]. Intel announced on 20 May 2020 that it was acquiring Rivet Networks, moving the team into its Wireless Solutions Group and folding Killer into its PC Wi-Fi line [2][3]. The founding year is not stated in the sources consulted; the 2015 interview only says the company started the previous December [4].

A MAC in the Rivet block is most likely a laptop, such as the Dell XPS 17, or a gaming motherboard with a Killer adapter [3][4]. The Killer Wireless-AC 1535 is an M.2 2230 card, dual-band 802.11ac 2x2 with MU-MIMO plus Bluetooth 4.1, built on a Qualcomm chip with Rivet's software, hardware design and certification [5]; Linux identifies it as a Qualcomm Atheros QCA6174 with a Bigfoot Networks subsystem ID 1a56:1535 [6]. The later Killer Wi-Fi 6 AX1650 was a joint Intel-Rivet design [2].

The Killer Control Center software had a 2019 kernel driver bug, CVE-2019-15661, a stack overflow in KfeCo10X64.sys reachable by an administrator and giving ring 0 code execution, fixed in October 2019 [7], and Intel's advisory INTEL-SA-00644 covers CVE-2021-26258, a local privilege escalation fixed in 2.4.3337.0 [8]. Randomization depends on the host operating system and is not documented here; FCC grantee codes are not listed because the FCC ID databases refused requests from the session that wrote this entry.

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Intel Acquires Rivet Networks, Makers of Killer Networking Products - PC Perspective - https://pcper.com/2020/05/intel-acquires-rivet-networks-killer-networking/ (accessed 2026-10-27)
3. Intel buys Rivet Networks and its Killer Networking brand to beef up its Wi-Fi tech - PCWorld - https://www.pcworld.com/article/3543884/intel-buys-rivet-networks-and-its-killer-networking-brand-to-beef-up-its-wi-fi-tech.html (accessed 2026-10-27)
4. Rivet Networks Q&A: From The Bigfoot Killer NIC To Qualcomm And Back - HotHardware - https://hothardware.com/reviews/rivet-networks-qa-from-the-bigfoot-killer-nic-to-qualcomm-and-back?page=1 (accessed 2026-10-27)
5. Killer Wireless-AC 1535 Review - Notebookcheck - https://www.notebookcheck.net/Killer-Wireless-AC-1535-Review.178877.0.html (accessed 2026-10-27)
6. Bug 1670041, poor performance of Atheros QCA6174 (Killer Wireless 1535) - Launchpad - https://bugs.launchpad.net/ubuntu/+source/linux/+bug/1670041 (accessed 2026-10-27)
7. FEYE-2019-0005, Rivet Killer Control Center KfeCo10X64.sys - FireEye Vulnerability Disclosures - https://github.com/fireeye/Vulnerability-Disclosures/blob/master/FEYE-2019-0005/FEYE-2019-0005.md (accessed 2026-10-27)
8. INTEL-SA-00644, Intel Killer Control Center Software Advisory - Intel - https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00644.html (accessed 2026-10-27)
