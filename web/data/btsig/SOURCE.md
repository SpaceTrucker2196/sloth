# web/data/btsig: the Bluetooth SIG assigned numbers

slothweb's BLE view names what an advertisement carries: the company
behind a Manufacturer Specific Data block (`mfr_id`), the service a
16-bit UUID lists (`uuid16`, `svc_data_uuid16`) and the device class an
Appearance value states. The names come from the Bluetooth SIG's
public Assigned Numbers, kept here as three CSVs (`value,name`, RFC
4180 quoting) and compiled into slothweb at build time by
`web/tools/btsig_gen.c` (into `build/web/web_btsig_table.c`, build
output, never committed), exactly as the IEEE registry in `web/data/`
is (owner ruling 2026-10-26; the ab5fcb2 ruling: the refresh tool
copies from a given file or directory and never fetches).

| File | Table | Published at |
|---|---|---|
| `company_identifiers.csv` | Company Identifiers (Assigned Numbers §7) | https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/company_identifiers/company_identifiers.yaml |
| `service_uuids.csv` | 16-bit UUIDs, services (Assigned Numbers §3.4) | https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/uuids/service_uuids.yaml |
| `appearance_values.csv` | Appearance Values (Assigned Numbers §2.6.2) | https://bitbucket.org/bluetooth-SIG/public/raw/main/assigned_numbers/core/appearance_values.yaml |

**Licence.** The Bluetooth SIG publishes its assigned numbers for
public use; the YAML files carry the SIG's own notice that they are
not a Bluetooth Specification and that use is governed by the
Bluetooth Patent/Copyright License Agreement for members and otherwise
by the SIG's terms for the public repository. Only the value and name
columns are kept here, as data a monitor shows a reader; the notice is
not reproduced in the CSVs. The company names are the registrants'
own and are shown as the registry gives them.

**This copy.** Fetched once, during development on 2026-10-27, from
the three URLs above at the repository's `main` branch; the YAML
files' SHA-256 as downloaded were
`3b1ce76bd46bdcc0a772cd9d5d8629167f1b6a76c91e224592ec230f3e347bfe`
(`company_identifiers.yaml`, 210904 bytes),
`401d8e0962d2586dc2526e9ecedef40803c6e09b689767a526e86caa783c3166`
(`service_uuids.yaml`, 8853 bytes) and
`0341ff695f2d8aaee13a36fc7ef4cf671196455c1b1020363267786ad8fb038a`
(`appearance_values.yaml`, 17586 bytes). The CSVs below are those
files through `web/tools/update_btsig.sh`'s converter.

**Refreshing.** `make update-btsig SRC=DIR` (`web/tools/update_btsig.sh
web/data/btsig DIR`) converts the three YAML files found in DIR (flat,
or in the repository's `company_identifiers/`, `uuids/` and `core/`
layout) and only then replaces the three files and rewrites the block
below. It never fetches: download the files in a browser, or clone
the SIG's public repository, and pass the directory. When all three
come back byte for byte the same it changes nothing, so the date below
is when the data last changed. Review the diff and commit
`web/data/btsig/` by hand. Nothing in `make`, `make web`, the tests or
CI runs it. `web/tests/test_btsig.c` checks that the hashes below are
the committed files', so a CSV edited without this step fails `make
web-test`.

<!-- update-btsig:begin -->
Refreshed 2026-10-27 by `make update-btsig`: converted from a directory holding the three SIG YAML files named above.

| File | Table | Rows | Bytes | SHA-256 |
|---|---|---|---|---|
| `company_identifiers.csv` | Company Identifiers | 4057 | 115805 | `284a821cb54eb5010429e41c52a2b824268aa55c8595821f28686f34a6fa8749` |
| `service_uuids.csv` | 16-bit Service UUIDs | 76 | 1941 | `57f1a07c0e5f922dc91c824923ceab2e3a20003d885f5658f2b96f11fa98d91d` |
| `appearance_values.csv` | Appearance Values | 342 | 11858 | `a1c926d3afe9639ad41e6ccc4c02fe2b90c783582aff623504a3ea2adf5cc319` |
<!-- update-btsig:end -->
