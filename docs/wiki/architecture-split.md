# Architecture split: the coupling inventory

**Summary**: Every place sloth's one tree crosses the line that #184
proposes to cut into three repositories (`sloth`, `sloth-dash`,
`sloth-comint`), produced by grep rather than from the proposal's prose,
with the command for each list so a reviewer can re-run it. Two halves:
what `web/` reaches into (`src/`, `include/`, `docs/`, `research/`), and
which tables in `src/` are intelligence about the world rather than code.
Then #184 §2's contract table C1–C10 filled in from what was found, and a
section naming every place the grep and #184 §2 disagree.

**Sources**: `Makefile` (the slothweb section, lines 573–902, and lines
1391 and 1490 outside it), `#include` lines under `web/` and `tests/`,
`src/oui.c`, `src/dot11_ie.c`, `src/wifi_oui_attacker.c`,
`src/camera_vendor.c`, `src/vendor_watchlist.c`, `src/tool_fingerprint.c`,
`src/ble_watchlist.c`, `src/ble_flood.c`, `src/captive_portal.c`,
`src/ip_owner.c`, `src/services.c`, `src/threat_intel.c`,
`src/reg_table.c`, `src/wifi_freq.c`, `include/sloth.h`, `src/db.h`,
`web/data/SOURCE.md`, `web/data/btsig/SOURCE.md`,
`web/data/vendors/COVERAGE.md`, `packaging/systemd/`, issues #184 and
#185, owner rulings on #184 of 2026-11-04.

**Last updated**: 2026-11-05

This page is a measurement, not a plan. It is Stage 0's first deliverable
(#185 item 1) and it exists so that Stages 1 to 4 cut along lines someone
has actually looked at. Where it contradicts #184, #184 is the older
document and this page is the one that was run against the tree.

Line numbers are this commit's. They move; the commands do not.

---

## 1. How each list was produced

Run from the repository root. Each command is the authority for the
section under it; a reviewer who gets a different answer should trust
their run and say so.

```sh
# (a1) the Makefile's slothweb section, and its boundaries
grep -n '^# ──' Makefile                      # section starts 573, next starts 903

# (a2) every reference out of that section into src/ include/ docs/ research/
sed -n '573,902p' Makefile |
  grep -nE '(^|[^a-zA-Z0-9_/-])(src|include|docs|research)/'

# (a3) the same references in the rest of the Makefile
grep -nE 'web/|WEB_|slothweb' Makefile | awk -F: '$1<573 || $1>902'

# (a4) include lines under web/ that name a path outside web/
grep -rnE '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' web/ |
  grep -E '"\.\./|"(src|include|research|docs)/'

# (a5) include lines under web/ that resolve outside web/ through -iquote
#      / -I (a bare name that is not a file in web/ but is one in src/,
#      include/ or research/)
for f in $(grep -rlE '^[[:space:]]*#[[:space:]]*include[[:space:]]*"' web/); do
  d=$(dirname "$f")
  grep -oE '^[[:space:]]*#[[:space:]]*include[[:space:]]*"[^"]*"' "$f" |
    sed -E 's/.*"([^"]*)".*/\1/' | while read -r t; do
      case "$t" in ../*) continue;; esac
      [ -e "$d/$t" ] || [ -e "web/src/$t" ] || [ -e "web/tools/$t" ] ||
        [ -e "web/tests/$t" ] || {
          for base in src include research; do
            [ -e "$base/$t" ] && echo "$f -> $base/$t"
          done
        }
    done
done | sort -u

# (a6) the OTHER direction, which #184 §2 has no row for
grep -rn '#include ".*web/' tests/
grep -rn '"web/' tests/*.c
grep -rn 'web/' src/ include/ --include=*.c --include=*.h | grep -v 'www\|https'

# (b1) candidate intelligence tables in src/
grep -rnE '^static const .*\[\] *= *\{|^static const .*\[\]\[.*\] *= *\{|^const .*\[\] *= *\{' \
  src/ --include=*.c | grep -vE 'src/views/|src/alerts/'

# (b2) rows in one table: its first line to the matching `};`
awk -v s=<first-line> 'NR>s && /^\};/{print NR; exit}' <file>
sed -n '<s+1>,<e-1>p' <file> | grep -cE '^\s*\{'   # or ^\s*" for string tables

# (c) the committed data the packs will carry
wc -l web/data/*.csv web/data/btsig/*.csv
ls web/data/vendors/*.md | wc -l
```

---

## 2. (a) What `web/` reaches into

### 2.1 In the `Makefile`

The slothweb section is **lines 573 to 902** — the `# ── slothweb` banner
to the line before `# ── Test build`. #184 and #185 both say "lines 575 to
760"; see §5.

| `Makefile` | What | Reaches |
|---|---|---|
| 659 | `WEB_RECIPES_MD = docs/wiki/sqlite-schema.md` | `docs/` |
| 667–668 | `WEB_AKB_INPUTS = include/sloth_alerts.def docs/views/alerts.md docs/wiki/alerts.md docs/wiki/alert-remediation.md` | `include/`, `docs/` |
| 669 | `WEB_AKB_CORPUS = $(wildcard research/*.md research/*/*.md research/*/*/*.md)` | `research/` |
| 710 | `WEB_ASM_DIR = docs/wiki/alert-assessments` | `docs/` |
| 717–718 | `WEB_CORE_SRCS = src/dot11_frame.c src/radiotap.c src/wifi_freq.c src/dns_wire.c src/dot11_ie.c src/netstr.c` | `src/` — six files |
| 726 | `WEB_VERSION_DEF` — `sed -n 's/^#define SLOTH_VERSION .../p' include/sloth.h` at make time | `include/` |
| 727–729 | `WEB_TEST_SRCS` adds `src/db_schema.c src/rsn_ie.c src/ip_color.c src/tui_palette.c src/tui.c src/view_labels.c` | `src/` — six more, test binary only |
| 751 | `WEB_PALGEN_SRCS = web/tools/palette.c src/tui_palette.c` | `src/` |
| 755 | `$(WEB_PALGEN)` prerequisites `src/tui_palette.h src/tui.h src/ip_color.h` | `src/` |
| 757 | the palette generator compiles with `-Iinclude -Isrc` | `include/`, `src/` |
| 759–761 | `$(WEB_PAL_CSS)`: prerequisite `src/tui.c`, and the recipe passes `src/tui.c` as an argument to be read as text | `src/` |
| 763–765 | `$(WEB_PAL_JS)`: the same | `src/` |
| 770 | `web-contrast` passes `src/tui.c` | `src/` |
| 784–785 | `$(WEB_OUI_C)`: prerequisite `src/oui.c`, and the recipe passes it as an argument to be read as text | `src/` |
| 814–815 | `$(WEB_AKB_C)` recipe arguments `include/sloth_alerts.def docs/views/alerts.md docs/wiki/alerts.md docs/wiki/alert-remediation.md research` | `include/`, `docs/`, `research/` |
| 844 | `$(WEB_ASM_C)` prerequisite `include/sloth_alerts.def` | `include/` |
| 846 | `$(WEB_ASM_C)` recipe arguments `include/sloth_alerts.def $(WEB_ASM_DIR)` | `include/`, `docs/` |
| 850–851 | the `web` link line: `-iquote src` and `$(WEB_CORE_SRCS)` | `src/` |
| 861 | `WEB_DEMO_DB_SRCS = src/db_schema.c` | `src/` |
| 866 | `$(WEB_DEMO)` recipe compiles with `-Iinclude` | `include/` |
| 881–887 | the `web-test` link line: `-Iinclude -iquote src -iquote research`, `$(WEB_TEST_SRCS)`, `$(WEB_CORE_SRCS)` | `include/`, `src/`, `research/` |

Two more outside the section, both of which Stage 4 has to answer:

| `Makefile` | What | Reaches |
|---|---|---|
| 1391 | `make cppcheck` analyses `src research web` in **one** run, with `-Iinclude -Isrc -Iresearch -Iweb/src -Iweb/tests -Iweb/tools` | both directions |
| 1490 | the `install` target's staleness check walks `web/src web/ui web/tools web/data $(WEB_RECIPES_MD)` — the last expands to `docs/wiki/sqlite-schema.md` | `docs/` |

### 2.2 In `#include` lines under `web/`

Twenty-two include lines cross out of `web/`. Six name the path
explicitly; sixteen are bare names that resolve through `-iquote src`,
`-Isrc` or `-Iinclude` on the link lines above. Both forms are listed,
because only the first is visible to a grep for `../` — which is why
command (a5) exists. Two further `../` lines stay inside `web/` and are
listed so the grep's output can be matched line for line.

| File:line | Include | Resolves to | Through |
|---|---|---|---|
| `web/src/web_pcap.c:8` | `"dns_wire.h"` | `src/dns_wire.h` | `-iquote src` |
| `web/src/web_pcap.c:9` | `"dot11_frame.h"` | `src/dot11_frame.h` | `-iquote src` |
| `web/src/web_pcap.c:10` | `"dot11_ie.h"` | `src/dot11_ie.h` | `-iquote src` |
| `web/src/web_pcap.c:11` | `"radiotap.h"` | `src/radiotap.h` | `-iquote src` |
| `web/src/web_pcap.c:13` | `"wifi_freq.h"` | `src/wifi_freq.h` | `-iquote src` |
| `web/src/web_sh_stub.c:8` | `"sensor_health.h"` | `src/sensor_health.h` | `-iquote src` |
| `web/src/web_pcapdir.c:14` | `"../tools/sha256.h"` | inside `web/` | explicit |
| `web/tools/demo.c:43` | `"../tools/sha256.h"` | inside `web/` | explicit |
| `web/tools/palette.c:35` | `"ip_color.h"` | `src/ip_color.h` | `-Isrc` |
| `web/tools/palette.c:36` | `"tui.h"` | `src/tui.h` | `-Isrc` |
| `web/tools/palette.c:37` | `"tui_palette.h"` | `src/tui_palette.h` | `-Isrc` |
| `web/tests/test_alerts.c:15` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_bundle.c:36` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_chmix.c:13` | `"../../src/ip_color.h"` | `src/ip_color.h` | explicit |
| `web/tests/test_chmix.c:15` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_parity.c:12` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_ptr.c:22` | `"jsonl_ptr_fixture.h"` | `include/jsonl_ptr_fixture.h` | `-Iinclude` |
| `web/tests/test_query.c:9` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_tui_colors.c:24` | `"../../src/ip_color.h"` | `src/ip_color.h` | explicit |
| `web/tests/test_tui_colors.c:25` | `"../../src/persist_health.h"` | `src/persist_health.h` | explicit |
| `web/tests/test_tui_colors.c:26` | `"sloth.h"` | `include/sloth.h` | `-Iinclude` |
| `web/tests/test_tui_colors.c:27` | `"../../src/sloth_clock.h"` | `src/sloth_clock.h` | explicit |
| `web/tests/test_tui_colors.c:28` | `"../../src/tui.h"` | `src/tui.h` | explicit |
| `web/tests/test_tui_colors.c:29` | `"../../src/tui_palette.h"` | `src/tui_palette.h` | explicit |
| `web/tests/test_tui_colors.c:39` | `"sloth_views.def"` | `include/sloth_views.def` | `-Iinclude` |

The split that matters for C3: **no file compiled into the `slothweb`
binary includes `include/sloth.h`.** The six that do are all under
`web/tests/`, which builds `slothweb_test`. The `Makefile`'s own comment
(723–725) says "`web/` never includes `sloth.h`"; read as a statement
about the shipped binary it is true, read as a statement about the
directory it is not.

Distinct files crossed, deduplicated — this is the set a contract has to
replace:

- `src/`, compiled into `slothweb`: `dot11_frame.c`, `radiotap.c`,
  `wifi_freq.c`, `dns_wire.c`, `dot11_ie.c`, `netstr.c`.
- `src/`, compiled into `slothweb_test` as well: `db_schema.c`,
  `rsn_ie.c`, `ip_color.c`, `tui_palette.c`, `tui.c`, `view_labels.c`.
- `src/`, read as **text** at build time, never compiled: `oui.c` (by
  `web/tools/oui_gen.c`), `tui.c` (by `web/tools/palette.c`, for
  `find_brand()`'s table).
- `src/` headers: `dns_wire.h`, `dot11_frame.h`, `dot11_ie.h`,
  `radiotap.h`, `wifi_freq.h`, `sensor_health.h`, `ip_color.h`, `tui.h`,
  `tui_palette.h`, `persist_health.h`, `sloth_clock.h`.
- `include/`: `sloth.h`, `sloth_alerts.def`, `sloth_views.def`,
  `jsonl_ptr_fixture.h`, and `sloth.h` again as the `sed` source for
  `SLOTH_VERSION`.
- `docs/`: `docs/wiki/sqlite-schema.md`, `docs/wiki/alerts.md`,
  `docs/wiki/alert-remediation.md`, `docs/views/alerts.md`,
  `docs/wiki/alert-assessments/*.md`.
- `research/`: the whole corpus, three directory levels deep, as
  `WEB_AKB_CORPUS`.

### 2.3 The other direction: `tests/` into `web/`

#184 §2 has no row for this and §1 states the one-way version ("nothing
in `src/` references `web/`", `Makefile:577`). That is true of `src/` and
false of `tests/`. Three fuzz harnesses in sloth's own suite `#include`
slothweb **source files**, and two tests read `web/` paths at run time:

| File:line | What |
|---|---|
| `tests/fuzz/fuzz_web_pcap.c:31–35` | `#include` of `web/src/web_json.c`, `web/src/web_dot11_names.c`, `web/src/web_pcap.c`, `web/tools/sha256.c`, `web/src/web_pcapdir.c` |
| `tests/fuzz/fuzz_web_query.c:22–24` | `#include` of `web/src/web_json.c`, `web/src/web_query.c`, `web/src/web_scope.c` |
| `tests/fuzz/fuzz_web_sqlbox.c:34–37` | `#include` of `web/src/web_json.c`, `web/src/web_secret.c`, `web/src/web_ssid.c`, `web/src/web_sqlguard.c` |
| `tests/test_docs_consistency.c:340` | `opendir("web/data/vendors")` — the vendor-entry count the count markers are checked against |
| `tests/test_docs_consistency.c:486–487` | `web/README.md` and `web/data/vendors/COVERAGE.md` on the marked-documents list |
| `tests/test_unit_file.c:270, 803` | asserts `/var/lib/slothweb/slothweb.db` paths |
| `tests/test_unit_file.c:1416` | pins the `install` target's `find web/src web/ui … -newer slothweb` line |
| `tests/cppcheck.supp:59` | a suppression keyed on `web/tools/alertkb.c` |

Two more are comments only and cost nothing to move: `src/db.c:1942`
names `web/src/web_slothdb.h`, and `include/jsonl_ptr_fixture.h:6` names
`web/tests/test_ptr.c`.

The consequence is Stage 4's, not Stage 0's: removing `web/` from `sloth`
deletes the inputs of three fuzz harnesses that `make fuzz` builds by
wildcard, and `make fuzz` is exactly the target whose omission from a
slice's gate put a non-linking harness into CI (`agents/AGENTS.md`,
93f8c38). Each harness has to move to `sloth-dash` or be deleted in the
same change, and `tests/test_docs_consistency.c`'s vendor count has to
move to whatever ships the vendor entries — which, per the owner's
2026-11-04 ruling, is `sloth-comint`.

---

## 3. (b) Intelligence tables in `src/`

"Intelligence" here is #184 §1 item 3's test: a fact about the world's
devices or about adversary tooling, identical for every sloth
installation, that could in principle arrive as data instead of as C.
Row counts are counted, not recalled.

### 3.1 The tables #184 §1 names

| Table | File:line | Rows | Consumed by |
|---|---|---|---|
| `g_oui` | `src/oui.c:6–124` | **117** | `oui_lookup()`, `oui_vendor_label()`, `oui_lookup_str()` (`src/oui.c:128, 146, 152`) |
| `kHak5Ouis` | `src/wifi_oui_attacker.c:8–11` | **2** | `oui_is_hak5()` (`:49`) |
| `kEspressifOuis` | `src/wifi_oui_attacker.c:17–35` | **11** | `oui_is_espressif()` (`:54`) |
| `g_cam_oui` | `src/camera_vendor.c:40–517` | **455** | `cam_vendor_oui()` (`:545`), with `cam_vendor_oui_count()`, `cam_vendor_oui_at()`, `cam_vendor_oui_mixed_at()` for the provenance tests |
| `g_cam_server_brands` | `src/camera_vendor.c:572–575` | **9** | `cam_vendor_server()` (`:581`) |
| `g_cam_svcs` | `src/camera_vendor.c:622–634` | **3** | `cam_mdns_service()` |
| `g_camera_setup_ssid_pats` | `src/camera_vendor.c:665–681` | **4** | `cam_setup_ssid()` (`:694`) |
| `kEndpoints` | `src/vendor_watchlist.c:29–70` | **4** | `vendor_watchlist_match_domain()` (`:85`) |
| `TOOL_SIGNATURES` | `src/tool_fingerprint.c:29–114` | **1** plus a terminator (`SIG_ROWS`, `:116`) | `tool_fingerprint_match()` (`:149`), `tool_fingerprint_match_row()`, `tool_fingerprint_match_table()` |
| BLE watchlist | `src/ble_watchlist.c:8–9` | **0** | `ble_watchlist_match()` (`:41`); rows arrive only through `ble_watchlist_set_table()` (`:50`) |
| #151 known-stack table | — | **does not exist** | — |

Three of those need saying out loud, because a Stage 1 brief written from
#184 §1 would budget for data that is not there:

- **`src/vendor_watchlist.c` *is* "the surveillance-vendor endpoints".**
  #184 §1 and #185 item 1 list them as two separate items; they are one
  table of four rows (`evidence.com`, `axon.com`, `flocksafety.com`,
  `control.verkada.com`).
- **The BLE watchlist ships empty.** `g_rows` is a NULL pointer and
  `g_n` is zero by construction (`src/ble_watchlist.c:5–9` says why).
  What exists is the *schema* (`src/ble_watchlist.h`), the validating
  setter, and four documented candidate rows with what each still needs
  in `research/bluetooth/ble-watchlist-categories.md`. There is nothing
  to move; there is a schema for comint to publish into.
- **The #151 known-stack table does not exist.** #151 is an open issue —
  "Attack-hardware fingerprints: known-stack table, two-radio Pineapple
  pattern, verdict layer (waiting on owner rig captures)" — and
  [[attack-hardware-fingerprints]] records why: the stacks #77 named have
  no primary source in this tree, and plan #145's second ruling forbids a
  fingerprint row without one. `TOOL_SIGNATURES`'s single row is itself
  marked `UNVERIFIED` and capped at `med` confidence for the same reason.

### 3.2 Tables the grep found that #184 §1 does not name

Each of these passes #184 §1 item 3's own test. None is in its list.

| Table | File:line | Rows | Consumed by | Why it is intelligence |
|---|---|---|---|---|
| `k_oui` | `src/dot11_ie.c:95–112` | **16** | `dot11_oui_vendor()` (`:114`) | vendor-IE OUI → vendor name. **Already crosses the boundary**: `dot11_ie.c` is in `WEB_CORE_SRCS`, so this table is compiled into `slothweb` today |
| `g_svc` | `src/services.c:6–96` | **89** | `svc_name()` (`:100`), `svc_fmt_addr()` (`:111`) | IANA port → service name |
| `g_owners` | `src/ip_owner.c:20–93` | **51** | `ip_owner_lookup()` (`:97`), `ip_owner_lookup_str()` (`:105`) | public IP range → operator |
| `SENTINELS` | `src/captive_portal.c:23–66` | **13** | `cp_is_sentinel_host()` (`:86`), `cp_check_response()` (`:106`), `cp_check_dns()` (`:186`), `cp_check_tls()` (`:198`) | per-OS connectivity-check hosts, paths and exact expected bodies, cited to `research/tools/connectivity-check-sentinels.md` |
| `KITS` | `src/captive_portal.c:224–269` | **10** | `cp_match_kit()` (`:313`) | adversary tooling: phishing-kit header and body needles (wifiphisher and siblings) |
| `k_spam` | `src/ble_flood.c:29–42` | **6** | `ble_spam_family_known()` (`:44`) | adversary tooling: BLE advertisement-spam families, each row citing the tool source it came from |
| `bad_domains` | `src/threat_intel.c:24–32` | **6** | `ti_match_domain()` (`:58`) | synthetic demo IOCs — intelligence-shaped, deliberately not intelligence (`MISSION.md` §3) |
| `bad_ips` | `src/threat_intel.c:34–41` | **4** | `ti_match_ip()` (`:69`) | the same |
| `g_fcc_rows` | `src/reg_table.c:35–61` | **25** | `reg_table_get()` (`:129`), `reg_table_lookup()` (`:143`), `reg_channel_is_dfs()` (`:151`) | regulatory fact about the world, per jurisdiction |
| `g_etsi_rows` | `src/reg_table.c:83–103` | **19** | the same | the same |
| `g_eu_members` | `src/reg_table.c:123–127` | **27** | `reg_jurisdiction_for_country()` (`:134`) | country code → jurisdiction |
| `PLAN` | `src/wifi_freq.c:32–36` | **3** | `plan_for()` (`:58`), `wifi_freq_band()` (`:64`), `wifi_freq_channel()` (`:77`), `wifi_freq_mhz()` (`:103`) | band plan: derivable from IEEE 802.11, so arguably code. **Also already crosses**: `wifi_freq.c` is in `WEB_CORE_SRCS` |
| `EXCEPTIONS` | `src/wifi_freq.c:51–54` | **2** | the same | the same |

Grep also returned `src/view_labels.c`, `src/wifi_chanhop.c`,
`src/poll.c`, `src/db.c` and `src/rtsp_snoop.c`. Those are program
structure, a configuration default, and parser literals — not facts about
the world — and are listed here only so the next reader can see they were
considered and left out.

The decision this hands Stage 1 is a scoping one, not a technical one:
#184's pack covers four of the shipped tables, and the grep finds nine
more that meet its own definition. Which of them move is the owner's call
(§6).

### 3.3 The data already outside `src/`

What `web/data/` holds today, from each directory's own provenance file,
because this is the shape a pack has to carry (see [[pack-schema]]).

| Path | Content | Size today | Provenance |
|---|---|---|---|
| `web/data/oui.csv` | IEEE MA-L, 24-bit blocks | 39 630 rows | `web/data/SOURCE.md` |
| `web/data/mam.csv` | IEEE MA-M, 28-bit blocks | 6 451 rows | the same |
| `web/data/oui36.csv` | IEEE MA-S, 36-bit blocks | 7 064 rows | the same |
| `web/data/iab.csv` | IAB, the retired 36-bit blocks | 4 575 rows | the same |
| `web/data/btsig/company_identifiers.csv` | Bluetooth SIG company identifiers | 4 057 rows | `web/data/btsig/SOURCE.md` |
| `web/data/btsig/service_uuids.csv` | SIG 16-bit service UUIDs | 76 rows | the same |
| `web/data/btsig/appearance_values.csv` | SIG appearance values | 342 rows | the same |
| `web/data/vendors/*.md` | one researched OUI holder per file | **276** entries | `web/data/vendors/COVERAGE.md` |

Row counts are each `SOURCE.md`'s own, which is the count the committed
file's hash is checked against by `web/tests/test_oui.c` and
`web/tests/test_btsig.c`; the files carry one header line more.

---

## 4. #184 §2's contract table, filled in

The "Found" column is what the greps above returned. A row whose finding
differs from #184's text has it marked, and §5 says why it matters.

| # | #184 says | Found | Owner |
|---|---|---|---|
| C1 | JSONL over `--data-socket`; gains `SLOTH_JSONL_VERSION` reported in `sensor_health` | Confirmed as the starting state. `jsonl_emit_sensor_health()` is `src/jsonl.c:2104`, the record opens at `:2339`. No `SLOTH_JSONL_VERSION` exists yet (`include/sloth.h` carries `SLOTH_VERSION "1.8.5"` at line 22); it is #185 item 3, not this slice | sloth |
| C2 | `sloth.db` schema, `DB_SCHEMA_VERSION` 11, `src/db_schema.c` as DDL text; slothweb's tests link `src/db_schema.c` | Confirmed. `src/db.h:103` is `#define DB_SCHEMA_VERSION 11`. `src/db_schema.c` reaches `web/` twice, not once: `WEB_TEST_SRCS` (727) **and** `WEB_DEMO_DB_SRCS` (861), the demo generator. There is no `--print-schema` flag today | sloth |
| C3 | slothweb links `WEB_CORE_SRCS`: `dot11_frame.c`, `radiotap.c`, `wifi_freq.c`, `dns_wire.c`, `dot11_ie.c`, `rsn_ie.c`, … | **Differs.** `WEB_CORE_SRCS` (717–718) is exactly six files and `rsn_ie.c` is **not** among them: `dot11_frame.c`, `radiotap.c`, `wifi_freq.c`, `dns_wire.c`, `dot11_ie.c`, `netstr.c`. `rsn_ie.c` reaches `web/` only through `WEB_TEST_SRCS` (728), with five other `src/` files `libsloth-wire` would also have to carry or dash would have to replace | sloth |
| C4 | one generator reads `sloth_alerts.def`, `docs/views/alerts.md`, `docs/wiki/alerts.md`, `docs/wiki/alert-remediation.md`, `research/**` and `docs/wiki/alert-assessments/*.md` | **Differs.** Two generators. `web/tools/alertkb.c` takes the first four plus `research/` (`Makefile:814–815`); `web/tools/alertasm.c` takes `include/sloth_alerts.def` and `docs/wiki/alert-assessments/` (`:846`). The bundle has two consumers to satisfy, and `web-test` also passes `-DWEB_ASMGEN=` so a test can run the second generator (`:886`) | sloth |
| C5 | the palette generator parses `src/tui.c` and `src/tui_palette.c` | **Differs in kind, not in effect.** It *links* `src/tui_palette.c` (`WEB_PALGEN_SRCS`, 751) and calls `tui_pair_colors()`; it *reads* `src/tui.c` as text, passed as an argument at 760, 764 and 770. A `palette.json` artifact replaces both, but the second is a parse of C source and the first is an API call | sloth |
| C6 | intelligence hand-kept in `src/*.c` and generated into `build/web/` from `web/data/` | Confirmed, and **wider than §1's list**: §3.1 and §3.2 above. The five generators are `oui_gen.c` (784), `btsig_gen.c` (797), `vendorkb.c` (826), `alertkb.c` (813) and `alertasm.c` (844); all five write into `build/web/` and none is committed | comint |
| C7 | slothweb has no version; the bundle reports `SLOTH_VERSION` | Confirmed. `WEB_VERSION_DEF` (726) `sed`s `SLOTH_VERSION` out of `include/sloth.h` into `-DSLOTHWEB_BUILD_VERSION`; the envelope is `web/src/web_bundle.c`, whose `bundle_schema` field is at `:599` and `:695` | dash |
| C8 | one `install` target refusing without `./slothweb`; **two** systemd units; one `sloth` user | **Differs.** `packaging/systemd/` holds **three** units — `sloth-sensor.service`, `slothweb.service`, `sloth-ble-scan.service` — plus `sloth-sensor.service.d/` and `sloth.sysusers.conf`. The refusal is `Makefile:1489`, the staleness check `:1490`. `sloth-ble-scan` has no home in #184's three-repo split | each |
| C9 | one suite, one CI matrix; sloth publishes golden fixtures: `tests/replay/golden.jsonl`, a golden `sloth.db`, **sample pcaps** | **Differs.** `tests/replay/` holds `golden.jsonl`, `gen_replay.c` and `normalise.sh`. There are **no `.pcap` files tracked anywhere** in the repository, and `agents/AGENTS.md` makes that a rule, not an accident. There is no golden `sloth.db` either — the web tests build one from `src/db_schema.c` at run time, which is C2's mechanism. Also unlisted: the suite is not cleanly one-directional (§2.3) | each |
| C10 | dash ↔ comint: none today | Confirmed; neither repo exists yet (both created private on 2026-11-04) | comint |

---

## 5. Where the grep disagrees with #184 §2

Recorded because #185 makes the two lists matching the acceptance test,
and an undisclosed difference is worse than a disclosed one. None of
these changes the shape of the programme; each changes a stage's content.

1. **The `Makefile` web section is 573–902, not 575–760.** The quoted
   range stops in the middle of the variable block, before every recipe —
   so it excludes the `src/oui.c` read (784), the alert-knowledge
   generator's arguments (814–815), the assessment generator (844–846),
   the `web` and `web-test` link lines (850, 881–887), `WEB_DEMO_DB_SRCS`
   (861) and `-iquote research` (882). Roughly half the coupling is
   outside the range both issues cite.
2. **`rsn_ie.c` is not in `WEB_CORE_SRCS`** (C3). It is a test-only
   dependency, and five other `src/` files share that position
   (`ip_color.c`, `tui_palette.c`, `tui.c`, `view_labels.c`,
   `db_schema.c`). `libsloth-wire` as C3 describes it does not cover
   them, so Stage 3 needs an answer for the test link line as well as the
   binary one.
3. **C4 is two generators, not one.** The alert knowledge bundle has to
   satisfy `alertkb.c` and `alertasm.c`, and the assessments are the
   second one's only input besides the `.def`.
4. **C8 counts two units; there are three.** `sloth-ble-scan.service` is
   assigned to no repository by #184.
5. **C9's sample pcaps do not exist**, and `agents/AGENTS.md` forbids
   adding them. #185 item 4 lists "the sample pcaps the web tests use" as
   contract-artifact content; there is nothing to pack. The golden
   `sloth.db` does not exist either and would have to be *built* by `make
   contract` from the DDL, which is what #185 item 4 says — worth
   separating from "publish what we have".
6. **The intelligence list in §1 item 3 is incomplete.** Nine further
   tables in `src/` meet its own definition (§3.2), two of which
   (`src/dot11_ie.c`'s `k_oui`, `src/wifi_freq.c`'s `PLAN`) already
   compile into `slothweb` through `WEB_CORE_SRCS` — so a pack and
   `libsloth-wire` both have a claim on them.
7. **Two of the named tables are empty or absent.** The BLE watchlist
   ships zero rows; the #151 known-stack table does not exist. Stage 1's
   byte-parity proof has nothing to compare for either.
8. **"The 277-entry vendor research KB" is 276 entries.**
   `web/data/vendors/` holds 277 `.md` files, one of which is
   `COVERAGE.md` — which the generator skips by name
   (`Makefile:700`) and which states the count itself.
9. **The coupling is not one-directional.** `tests/` reaches into `web/`
   from eight places (§2.3), three of them `#include` of slothweb source.
   #184 §2 has no row for it and §1 asserts the one-way version.

---

## 6. What Stage 0 leaves open

- Which of §3.2's nine tables move to `sloth-comint` and which stay. The
  programme's definition covers them; its stage briefs do not mention
  them.
- Where `sloth-ble-scan.service` lives after the split (C8).
- Whether `libsloth-wire` carries only `WEB_CORE_SRCS` or also the six
  test-only `src/` files (C3, §5 item 2). The second is larger and
  includes `tui.c`, which is the TUI.
- The fate of the three `tests/fuzz/fuzz_web_*.c` harnesses at Stage 4.

---

## Related pages

- [[architecture]] — the system map these three boxes come from.
- [[pack-schema]] — the v1 pack manifest and file set this inventory feeds.
- [ADRs 0001–0007](adr/README.md) — the decisions #184 records.
- [[slothweb]] — what the `web/` half is and does.
- [[sqlite-schema]] — `sloth.db`, C2's artifact.
- [[jsonl-schema]] — the record stream, C1's artifact.
- [[research-corpus]] — the corpus that stays with the rules (ADR 2).
- [[attack-hardware-fingerprints]] — why the #151 known-stack table is not in the tree.
- [[vendor-research]] — the format of the 276 vendor entries.
