---
name: contract
description: The sensor's contract artifact - what `make contract` puts in dist/sloth-contract-<version>.tar, how to verify it, the versioning rule, and the decisions taken building it (#185 item 4)
type: reference
---

# Contract artifact

**Summary**: `make contract` builds `dist/sloth-contract-<SLOTH_VERSION>.tar`,
the one file a repository split off this one (`sloth-mesh`, the
presentation repository; `sloth-comint`, intelligence) builds and tests
against instead of reaching into this tree (#184 §2 C1–C5 and C9, #185
item 4). It carries `libsloth-wire.a` with its headers and pkg-config
file, the database schema as the daemons print it, the JSONL record
contract, the TUI palette as data, the alert knowledge bundle and the
golden fixtures, with a `MANIFEST.json` and a `SHA256SUMS`. It is
reproducible: two builds of one commit with one toolchain are the same
bytes. `make contract-check` proves that and reads the archive the way a
consumer would. On a `v*` tag the release workflow attests it and
attaches it to that tag's GitHub release.

**Sources**: `Makefile` (contract section: `CONTRACT_*`, `contract`,
`contract-check`, `WEB_CORE_SRCS`), `tools/contract.sh`,
`tools/contract_db.c`, `tests/contract/check.sh`,
`tests/contract/consumer.c`, `src/db_schema.c` (`db_schema_print()`),
`src/main.c` and `src/rf/rf_args.c` (`--print-schema`),
`web/tools/palette.c` (`json` mode), `src/alerts/rules_table.c`,
`src/alerts/rules_table_rf.c`, `.github/workflows/release-attest.yml`,
`.github/workflows/ci.yml` (`replay` job), `tools/gate.sh`,
[ADR 0001](adr/0001-three-repos.md) (Rulings since),
[ADR 0004](adr/0004-libsloth-wire.md), [ADR 0007](adr/0007-versioning.md),
issues #184 and #185.

**Last updated**: 2026-11-17 (`dot11_data_status_t` in its own header; `dot11_data.h` no longer ships, *Gaps*), 2026-11-16 (no host data in the alert bundle: the assessments and research documents are redacted, and `make contract-check` refuses a MAC address outside `tests/contract/allowed-macs.txt` or a home-directory path), 2026-11-16 (#185 review: the checks now also cover the outer checksum, JSON validity, the copies against the tree, `palette.json`, `alert-daemons.tsv`, an empty golden database and the declared-but-undefined functions; *Gaps*; migrated databases; the release step's order and tag check), 2026-11-16 (#185 item 4: first version, contract format 1)

---

## What is in it

One directory, `sloth-contract-<version>/`:

| Path | What | Contract row |
|---|---|---|
| `lib/libsloth-wire.a` | the leaf parsers slothweb links, compiled from exactly `WEB_CORE_SRCS` (`dot11_frame.c`, `radiotap.c`, `wifi_freq.c`, `dns_wire.c`, `dot11_ie.c`, `netstr.c`, `rf_model.c`) | C3 |
| `include/sloth-wire/*.h` | each of those sources' public header, the leaf headers they include (`dot11_data_status.h`), and `sensor_health.h` for the one hook (below), which declares functions the archive does not define (*Gaps*) | C3 |
| `lib/pkgconfig/sloth-wire.pc` | `pkg-config --cflags --libs sloth-wire`; relocatable through `${pcfiledir}`, so the unpacked directory can sit anywhere | C3 |
| `schema/schema.sql` | `sloth-wifi --print-schema`: the DDL both daemons create a new `--db` with, and the `meta` row stamping `DB_SCHEMA_VERSION` (a migrated file differs in column order: *Gaps*) | C2 |
| `jsonl/jsonl-schema.md` | [[jsonl-schema]] as in the tree at that commit (`SLOTH_JSONL_VERSION`) | C1 |
| `palette/palette.json` | what `web/tools/palette.c` reads out of the TUI today, as data: each mirrored colour pair's xterm-256 index and hex, the monitor-row pair, the brand table and the Google letter sequence | C5 |
| `alerts/include/sloth_alerts.def`, `alerts/docs/views/alerts.md`, `alerts/docs/wiki/alerts.md`, `alerts/docs/wiki/alert-remediation.md`, `alerts/docs/wiki/alert-assessments/*.md`, `alerts/research/**/*.md`, `alerts/research.db` | the alert knowledge bundle, at their tree paths under `alerts/` | C4 |
| `alerts/alert-daemons.tsv` | which daemon raises each kind: `ty`, `kind`, `raised_by` (`sloth-wifi`, `sloth-rf` or `both`) | C4 |
| `fixtures/golden.jsonl` | `tests/replay/golden.jsonl`, the replay golden | C9 |
| `fixtures/sloth.db` | an empty database built from `schema.sql` | C9 |
| `MANIFEST.json` | contract format, versions, commit, date, toolchain, and every other file's path, size and SHA-256 | — |
| `SHA256SUMS` | `sha256sum -c` form, every file but itself | — |

Beside the tar, `dist/sloth-contract-<version>.SHA256SUMS` holds the
tar's own checksum; that and the tar are the release assets.

## Verifying a copy

```sh
sha256sum -c sloth-contract-<version>.SHA256SUMS
gh attestation verify sloth-contract-<version>.tar --repo SpaceTrucker2196/sloth
tar -xf sloth-contract-<version>.tar
cd sloth-contract-<version> && sha256sum -c SHA256SUMS
PKG_CONFIG_PATH=$PWD/lib/pkgconfig pkg-config --cflags --libs sloth-wire
```

`make contract-check` (`tests/contract/check.sh`) does every step
above except the attestation, which needs the network and a release, on
every CI run (the `replay` job) and in `make gate`. #185 named this test
`tests/test_contract.c`; it is a shell check run by its own target, not
part of `make test`, because it needs the built daemons, `make contract`
itself (twice) and `pkg-config`, none of which the unit-test binary
has. What it checks:

1. `sloth-wifi --print-schema` and `sloth-rf --print-schema` are the same
   bytes, and are `schema/schema.sql`.
2. `sloth-contract-<version>.SHA256SUMS` verifies the tar; the tar holds
   one directory named for it; `SHA256SUMS` verifies and lists exactly
   the files present; `MANIFEST.json` is valid JSON (SQLite's strict
   `json_valid()`) whose path, size and SHA-256 agree with every file and
   list exactly the files present, and its `sloth_version`,
   `jsonl_version` and `db_schema_version` are the tree's. The copied
   files (`jsonl-schema.md`, `golden.jsonl`, the headers, the whole alert
   bundle) are the tree's, byte for byte, and the bundle holds exactly
   the tracked assessments and research documents. `palette.json` is
   valid JSON, its `ip_colors` is `IP_NUM_COLORS`, and every token has a
   name, an xterm index 0–255 and a `#rrggbb` hex. `alert-daemons.tsv`
   lists `sloth_alerts.def`'s kinds in order with `ty` 0..n-1, and its
   per-daemon totals are the `rules-wifi` / `rules-rf` count markers
   `tools/docs_counts.sh` keeps.
3. `tests/contract/consumer.c` compiles with only `sloth-wire.pc`'s flags
   (from a temporary directory, so no header of this tree can be found)
   and decodes a radiotap header and an 802.11 beacon built byte by byte
   per the specifications, as `tests/test_beacon_snoop.c` builds frames.
   It also feeds a cut element list to both element walks that report
   an overrun and counts the archive's outbound call from each.
   `sloth-wire.pc`'s `Version` is `sloth_version`. The functions the
   shipped headers declare (read with GCC's `-aux-info`) less those
   `libsloth-wire.a` defines (`nm`) are exactly
   `tests/contract/declared-not-defined.txt` (*Gaps*).
4. `schema.sql` loads into an in-memory SQLite, inserts nothing but its
   `meta` row, and its `schema_version` is the MANIFEST's;
   `fixtures/sloth.db`'s `sqlite_master` equals that load's, it is
   `auto_vacuum=INCREMENTAL`, and no table holds a row but `meta`'s one.
5. A second `make contract` under `umask 077`, `TZ=Pacific/Chatham` and
   `LC_ALL=C.UTF-8`, at least a second later, gives the same bytes
   (`cmp`). The checkout's path is not varied there; two clones of one
   commit at different paths, under different umasks, time zones and
   locales, were checked by hand to give the same tar (#185 review).

Each check was seen red under a mutation of the thing it guards before
it was claimed (`agents/AGENTS.md`, "A test that asserts absence…"):
the two daemons printing different text; a file changed or added after
`SHA256SUMS`; a wrong size in, or a file missing from, `MANIFEST.json`;
a wrong `jsonl_version`; `schema.sql` edited after the daemon printed
it; a shipped header including an unshipped one (`bytes.h`); a shipped
header including `sloth.h` (red earlier, at the archive's own compile,
which has no `include/` on its path); the radiotap rate decode wrong;
the overrun hook not called; the `.pc` version wrong; the version row
off by one; an extra table in the golden database; no `--mode`
normalisation; no fixed `--mtime`; a stray second top-level entry. And,
for the checks the review added: `palette.json` missing its closing
brace; a trailing comma in `MANIFEST.json`; a `sessions` row in, and
`auto_vacuum=NONE` on, the golden database; `SENSOR_SOURCE_DOWN`
attributed to `sloth-rf` alone; `jsonl-schema.md` copied from the wrong
file; one tracked assessment left out of the bundle; a kind renamed in
`alert-daemons.tsv`; a byte appended to the tar after its checksum; a
prototype added to a shipped header, and an entry dropped from the
pinned list; the second overrun site's hook call removed; the time zone
written into `MANIFEST.json`. `tools/contract.sh` refuses to build when
`git ls-files` fails or lists no assessment or no research document,
rather than shipping a bundle without them.

## Versioning

Per [ADR 0007](adr/0007-versioning.md), each seam keeps its own version
and the artifact names them all; nothing here has a version of its own
except the layout:

- `contract_format` (`MANIFEST.json`) is the archive's layout: which
  paths exist and what they mean. It starts at **1**. Adding a path is
  compatible and does not move it; moving, renaming or removing one, or
  changing a file's meaning, is a new format, and that is an external
  contract break: a stop-and-ask (`agents/dark-factory.md` §4.3).
- `sloth_version` is `SLOTH_VERSION` and names the archive.
- `jsonl_version` is `SLOTH_JSONL_VERSION`, with the bump rule in
  [[jsonl-schema]] *Versioning*.
- `db_schema_version` is `DB_SCHEMA_VERSION`, whose every bump ships its
  migration (`agents/AGENTS.md`).
- `libsloth-wire`'s headers are an API (ADR 0004): renaming one of their
  functions is a stop-and-ask, not a refactor. The library has no number
  but `sloth_version`; a consumer pins the archive.

## Decisions

The owner ruled that the artifact is published as GitHub release assets
on `sloth` ([ADR 0001](adr/0001-three-repos.md), Rulings since) and
delegated the remaining contract choices. These are those choices, each
with its reason.

1. **The archive is exactly `WEB_CORE_SRCS`.** That is what slothweb
   links today, so "the page and the sensor link the same parsers" stays
   checkable as a list compare. The six test-only `src/` files of
   [[architecture-split]] §5 item 2 are not in it; two of them are now
   covered by other contents (`db_schema.c` by `schema.sql`,
   `tui_palette.c` / `tui.c` by `palette.json`), and `rsn_ie.c`,
   `ip_color.c` and `view_labels.c` remain without an answer (open,
   below).
2. **The fault hook is the consumer's.** `dot11_ie.c` calls
   `sh_parse_fault_note()` when an element walk overruns, and sloth
   defines it in `sensor_health.c`, which needs `sloth.h`. The archive
   does not define it; the consumer does, as slothweb does today in
   `web/src/web_sh_stub.c` and `tests/contract/consumer.c` does in the
   check. [ADR 0004](adr/0004-libsloth-wire.md) says the archive should
   define the seam rather than borrow it; a stub member inside the
   archive would mean the archive is no longer `WEB_CORE_SRCS`, so this
   is recorded as the alternative chosen against. Its type and
   declaration come from the shipped `sensor_health.h`, sloth's whole
   header, which also declares functions the archive does not define:
   **gap** (*Gaps*), stated rather than fixed by a trimmed copy that
   could drift. No shipped header includes `sloth.h` (checked: the
   archive's own compile has no `include/` on its path, and the
   consumer's has only the unpacked directory).
3. **Fixed compiler flags for the archive** (`CONTRACT_CFLAGS`: `-O2
   -std=c99 -fPIC`, warnings, no `-g`, the tree's path mapped away),
   not the tree's `CFLAGS`: a sanitizer or a hardening flag of this
   build would become a link requirement of every consumer. Warning
   flags from `EXTRA_CFLAGS` still apply, so `-Werror` reaches it.
   `-fPIC` lets a consumer put it into a shared object. The flags are
   recorded in `MANIFEST.json` without the path.
4. **`schema.sql` is printed by the daemon** (`--print-schema`, both
   binaries, one function: `db_schema_print()` in `src/db_schema.c`),
   not copied from the source, so the published DDL is what the binary
   runs. It is the schema statements in `db_open()`'s order and the
   `meta` row `check_version()` stamps; the PRAGMAs are storage
   settings and are named in its comment, not emitted. A `WITH_SQLITE=0`
   build prints the same text: `db_schema.c` is compiled unconditionally.
   sloth records its version in `meta.schema_version`, not SQLite's
   `user_version`, so that row is what the check reads.
5. **The golden `sloth.db` is `schema.sql` applied by SQLite**
   (`tools/contract_db.c build`, with `auto_vacuum=INCREMENTAL` as
   `db_open()` sets it before the first table), not created by running
   a daemon: a daemon's own file has a `sessions` row stamped with the
   wall clock and a WAL journal, so no two would be the same bytes, and
   a WAL file needs its `-shm` to be read. It is deterministic for one
   SQLite version; the file header carries the version of the library
   that wrote it, which is why `MANIFEST.json` records `toolchain.sqlite`.
   A small C tool rather than the `sqlite3` shell, which CI's runner
   does not have.
6. **Reproducibility is per toolchain.** Sorted entries, every mtime
   `SOURCE_DATE_EPOCH` (default: the HEAD commit's time), owner and group
   0 by number, modes normalised to `u=rwX,go=rX` whatever the umask,
   `ar` in deterministic mode, everything rebuilt from scratch each run.
   The archive's objects depend on the compiler and the golden database
   on SQLite, so the claim is "same commit, same toolchain": the
   toolchain is in `MANIFEST.json`, and a consumer comparing two builds
   compares those first. `git_dirty` says when the tree had uncommitted
   changes; a release is built from a clean checkout of the tag.
7. **The alert bundle keeps its tree paths** under `alerts/`, so each
   generator's arguments (`web/tools/alertkb.c`, `web/tools/alertasm.c`)
   are the same paths with a prefix. Tracked files only (`git ls-files`),
   so a scratch file under `research/` never ships. The committed
   `research.db` is shipped as committed.
8. **Which daemon raises each kind** is generated, by the model
   `tools/docs_counts.sh` and `tests/test_docs_consistency.c` already
   hold the count markers to: `sloth-rf`'s table has one row per kind
   (`rule_<kind>`); a kind it shares with `sloth-wifi`'s table is
   `both`; every other kind in the shared list is `sloth-wifi`'s. The
   generator refuses a `sloth-rf` row that names no kind.
9. **No sample pcaps (C9).** None exist, and `agents/AGENTS.md` ("No pcap
   fixtures") forbids adding them; C9 ships without them. The replay
   golden is the record-level fixture, and the consumer's hand-built
   beacon is the frame-level example.
10. **The release's checksum file is named for the tar**
    (`sloth-contract-<version>.SHA256SUMS`), so it never collides with
    the `SHA256SUMS` of the binaries the owner attaches by hand
    ([[release-checklist]] step 9). The workflow attaches to the tag's
    release, creating it as a **draft** when it does not exist yet, so
    the notes and the publish step stay the owner's; step 9 says to
    publish that draft rather than create a second release. The job
    first refuses a tag that is not `v` + `SLOTH_VERSION`, and builds the
    contract *before* its `-Werror` build, so the daemons it checksums
    and attests are that build's and not a relink by `make contract`.
11. **`palette.json` is the sensor's half only.** The light-theme
    variants are computed against `web/ui/theme.css`, which belongs to
    the page, so they are not in it.

## Gaps

- **Host data (closed 2026-11-16).** The alert bundle is a release
  asset, so it carries nothing a sensor learned about itself or the
  devices around it. The assessments that quoted the reference host's
  own managed-card MAC (`MY_NETWORK_RECON`), the addresses it heard
  (`FRAG_AMSDU`, `FRAG_EAPOL_RELAY`), its database snapshot's home path
  (`FRAG_*`) and the sensors' names (`research/papers/rssi-distance-estimation.md`)
  now say "AP-1", "STA-1", "its own managed card", "a snapshot of its
  database", "one sensor". `make contract-check` fails on any MAC-shaped
  string in the bundle's text files that is not in
  `tests/contract/allowed-macs.txt` (documentation placeholders, the
  802.1X group address, the UNSW public dataset), and on any `~/` or
  `/home/` path. `research.db` is not scanned as bytes: its text is the
  research documents' (it is compared with the tree's file, and the gate
  fails when `research-index` would change it), and its record headers
  hold `~/` by coincidence. Both refusals were seen red: a heard BSSID
  put back into `FRAG_AMSDU.md`, and a `~/` path appended to it. The
  same addresses remain in this repository's history and in issue #180;
  the rule covers what a release asset ships.
- **Declared, not defined.** `sensor_health.h` declares 16 functions
  `libsloth-wire.a` does not define, so a consumer calling one compiles
  and then fails to link. It is shipped whole for the one hook
  (decision 2): that is deliberate, not a defect to close. The exact
  list is `tests/contract/declared-not-defined.txt`, and
  `make contract-check` fails if it grows or shrinks.
  `dot11_data.h` was the other header in that list until 2026-11-17
  (11 functions, the data-frame helpers of `dot11_data.c`), shipped only
  because `dot11_frame.h` included it for `dot11_data_status_t`. The
  owner chose to split the enum into `dot11_data_status.h` rather than
  add `dot11_data.c` to the archive, so the archive stays exactly
  `WEB_CORE_SRCS` and `dot11_data.h` no longer ships. The header set
  changed while contract format 1 had no published release, so the
  format number stays 1.
- **Migrated databases.** `schema.sql` is what a *new* file gets. A file
  a daemon migrated from an older version has the same tables, columns
  and indexes, but `ALTER TABLE … ADD COLUMN` appends a column where the
  current `CREATE TABLE` has it in the middle (`beacon_aps.akm_bits`,
  `probe_clients.presence`), so the column order and `sqlite_master`'s
  text differ. A consumer names columns; it never reads them by
  position or compares the `CREATE` text. `schema.sql`'s header says the
  same.

## Not done, and open

- **`make install-dev`** ([ADR 0004](adr/0004-libsloth-wire.md)) is not
  written: the archive is consumed from the unpacked directory through
  `${pcfiledir}`, which needs no install step.
- **`rsn_ie.c`, `ip_color.c`, `view_labels.c`**: slothweb's tests link
  them and the archive does not carry them (decision 1).
- **No consumer reads the artifact yet.** slothweb still builds from this
  tree; moving its generators and tests onto the archive is #184 Stage 3.
- **The release step has not run.** It runs on the next `v*` tag; read
  that run's log before publishing ([[release-checklist]]).

## Related pages

- [[architecture-split]] — the coupling inventory and the C-rows this
  artifact ships.
- [[release-checklist]] — where the artifact is attached and verified.
- [[cli-reference]] — `--print-schema`.
- [[jsonl-schema]] — C1, shipped inside.
- [[sqlite-schema]] — C2, the schema `schema.sql` prints.
- [[pack-schema]] — the other versioned file set of the programme (C6).
- [ADR 0004 — libsloth-wire](adr/0004-libsloth-wire.md)
- [ADR 0007 — versioning](adr/0007-versioning.md)
