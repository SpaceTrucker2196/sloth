# web/data: the IEEE registry CSVs

slothweb's vendor table (#162, M4; `docs/web-ui-spec.md` §9.2) is
generated at build time by `web/tools/oui_gen.c` from the four IEEE
Registration Authority registry files kept here. They are committed by
owner ruling 2026-10-26, which reverses the 2026-10-21 ruling that
kept them out of git: a fresh clone builds the full table, so rule A4
(vendor unknown) and the Lookup and Devices vendor column work without
a manual download. The generated C table (`build/web/web_oui_table.c`)
is build output and is never committed.

| File | Registry | Published at |
|---|---|---|
| `oui.csv` | MA-L, 24-bit blocks | https://standards-oui.ieee.org/oui/oui.csv |
| `mam.csv` | MA-M, 28-bit blocks | https://standards-oui.ieee.org/oui28/mam.csv |
| `oui36.csv` | MA-S, 36-bit blocks | https://standards-oui.ieee.org/oui36/oui36.csv |
| `iab.csv` | IAB, the retired 36-bit blocks | https://standards-oui.ieee.org/iab/iab.csv |

**Licence.** The IEEE publishes these listings openly for public use;
they are the public registry of who holds each assignment. Debian
redistributes them as the `ieee-data` package and Wireshark ships the
same data in its `manuf` file.

**This copy.** Taken from Debian's `ieee-data` package, version
20260625 (files dated 2026-06-25; the package's own `.lastupdate`
stamp reads 1721654721, 2024-07-22, and is the package's, not when the
IEEE last changed a row). The bytes are the package's, unmodified.

**Refreshing.** `make update-oui` (`web/tools/update_oui.sh`) copies
each file from `/usr/share/ieee-data` when it is there and otherwise
fetches it from the URLs above with curl (the IEEE answers a plain
curl with 418, so it sends a browser User-Agent and Accept headers),
checks that each is a registry CSV with the expected header and rows
of its registry, and only then replaces the four files and rewrites the
block below. Review the diff and commit `web/data/` by hand. Nothing in
`make`, `make web`, the tests or CI runs it: a build never touches the
network. `web/tests/test_oui.c` checks that the hashes below are the
committed files', so a CSV edited without this step fails `make
web-test`.

<!-- update-oui:begin -->
Refreshed 2026-10-26 by `make update-oui`: copied from /usr/share/ieee-data (ieee-data 20260625).

| File | Registry | Rows | Bytes | SHA-256 |
|---|---|---|---|---|
| `oui.csv` | MA-L | 39630 | 3778307 | `e861ad51d45f8ae3ad9d1173a113614817dff8521b88820663cd6d1174f3b413` |
| `mam.csv` | MA-M | 6451 | 733654 | `dccd3319d7c750837a3480debf7d30035eb30189684a80a701200acd81485355` |
| `oui36.csv` | MA-S | 7064 | 654663 | `66e633ec84c7043d88abaf0c4426976cfc9b70d794ee5629c996c95b57029b02` |
| `iab.csv` | IAB | 4575 | 381115 | `20f58c75be7809404515ba9d399e112e97f2880db9c9e89bbc137db0abce76dc` |
<!-- update-oui:end -->
