---
name: Seiko Epson Corporation
aliases: []
affiliates: []
country: JP [1][2]
parent: independent [2]
founded: 1942 [2]
kind: brand [2]
device_classes: [printer [2][3][5]]
found_in: ["Epson WF-2510, WF-2530, WF-2540, WF-3520, WF-3540, WorkForce WF-5190 and WF-7110, C462M, XP-200, XP-211, XP-410, XP-411 and XP-610 (Askey WLU6117-D69 module) [3]", "Epson projectors (Epson-branded wireless dongles) [6]", "some Epson printers (Foxconn T77H145 module) [5]"]
radios: ["Wi-Fi 4 [3][4][5]", "2.4 GHz [3]"]
silicon: ["Broadcom BCM4319 (believed, per DeviWiki's own hedged note) in the Askey WLU6117-D69 module used in Epson printers [3]", "Realtek RTL8192DU in the Wistron NeWeb DNUK-E92 module filed under Epson's grantee code [4]", "Marvell 88W8786U in the Foxconn T77H145 module used in some Epson printers [5]"]
fcc_grantee: ["BKM (FCC IDs BKMAE-92, BKMFBWLU6117, BKMFBSP88W8786) [3][4][5][12]"]
randomization: unknown
security_notes: ["Web Config insecure initial password lets a remote unauthenticated attacker set the admin password (CVE-2024-47295) [7]", "initial administrator password guessable from SNMP-readable information on Epson and FUJIFILM products (CVE-2025-35970) [8]", "Web Config CSRF and a stack buffer overflow on Epson printers and network interfaces (CVE-2023-27520, CVE-2025-66635) [9][10]", "ESC/POS printer language has no authentication or command authorization (CVE-2026-23767) [11]"]
confidence: {country: documented, silicon: inferred, radios: documented, found_in: documented, randomization: unknown}
researched: 2026-10-27
---
## Summary

Seiko Epson is a Japanese maker of inkjet, laser, dot-matrix and
thermal printers, projectors, watches, semiconductors, smart glasses
and robots, founded in 1942 as Daiwa Kogyo in Suwa, Nagano,
headquartered in Suwa and listed on the Tokyo Stock Exchange; it is
neither a subsidiary nor an affiliate of Seiko Group, which with the
Hattori family holds about 10 percent of its shares [2]. The IEEE
registry lists 21 MA-L blocks to it at addresses in Suwa, Matsumoto and
Shiojiri, Nagano [1]. A MAC in these blocks is most likely a networked
Epson printer, scanner or projector [2][3].

The radios in Epson printers are often third-party modules: DeviWiki
records the Askey WLU6117-D69 (802.11b/g/n 1x1 on 2.4 GHz, with a
Broadcom BCM4319 that the page itself only presumes) in WorkForce and
XP-series printers [3], the Foxconn T77H145
(Marvell 88W8786U, 802.11b/g/n) in some Epson printers [5], and the
Wistron NeWeb DNUK-E92 (Realtek RTL8192DU, 802.11a/b/g/n 2x2) filed
under Seiko Epson's grantee code [4], which an FCC ID reference
lists as BKM [12], and lists Epson-branded
wireless dongles for its projectors [6]. NVD records a long run of
embedded web server issues: an insecure initial password in Web Config
that lets a remote attacker set the admin password [7], initial admin
passwords guessable from SNMP data [8], CSRF and a stack buffer
overflow in Web Config [9][10], and the ESC/POS receipt-printer
language's lack of any authentication [11]. Randomisation is unknown;
the FCC ID databases and web search were unavailable to the session
that wrote this entry [1].

## Sources
1. IEEE Registration Authority, MA-L assignments (oui.csv) - https://standards-oui.ieee.org/oui/oui.csv (accessed 2026-10-27)
2. Seiko Epson - Wikipedia - https://en.wikipedia.org/wiki/Seiko_Epson (accessed 2026-10-27)
3. Askey WLU6117-D69 - DeviWiki - https://deviwiki.com/wiki/Askey_WLU6117-D69 (accessed 2026-10-27)
4. Wistron NeWeb DNUK-E92 - DeviWiki - https://deviwiki.com/wiki/Wistron_NeWeb_DNUK-E92 (accessed 2026-10-27)
5. Foxconn T77H145 - DeviWiki - https://deviwiki.com/wiki/Foxconn_T77H145 (accessed 2026-10-27)
6. DeviWiki search results for Epson - https://deviwiki.com/w/index.php?search=Epson&fulltext=1 (accessed 2026-10-27)
7. CVE-2024-47295 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2024-47295 (accessed 2026-10-27)
8. CVE-2025-35970 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2025-35970 (accessed 2026-10-27)
9. CVE-2023-27520 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2023-27520 (accessed 2026-10-27)
10. CVE-2025-66635 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2025-66635 (accessed 2026-10-27)
11. CVE-2026-23767 - NVD - https://nvd.nist.gov/vuln/detail/CVE-2026-23767 (accessed 2026-10-27)
12. FCC ID quick reference - Deskthority wiki - https://deskthority.net/wiki/FCC_ID_quick_reference (accessed 2026-10-27)
