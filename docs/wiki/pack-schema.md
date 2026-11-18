# Intel pack schema, v1 (DRAFT)

**Summary**: The shape of a `sloth-comint` intelligence pack — the
manifest's fields, the file set a v1 pack carries, and the rule that a
published pack never changes. **This is a v1 draft for Stage 1 to build
against, not an implemented format**: no pack exists, `sloth-comint`
holds a README only, and nothing in this tree reads a manifest. Stage 1
is free to correct it against what it finds; Stage 0's job was to write
down a target precise enough to disagree with.

**Sources**: issue #184 §2 C6 and §3 Stage 1, decision 3 (recorded as
[ADR 0003](adr/0003-intelligence-is-files.md)), owner rulings on #184 §5
of 2026-11-04; `web/data/SOURCE.md`, `web/data/btsig/SOURCE.md`,
`web/data/vendors/COVERAGE.md`, `docs/wiki/vendor-research.md`;
`Makefile` lines 652–715 and 776–847 (the five generators);
`src/oui.c`, `src/dot11_ie.c`, `src/wifi_oui_attacker.c`,
`src/camera_vendor.c`, `src/vendor_watchlist.c`,
`src/tool_fingerprint.c`, `src/ble_watchlist.h`;
`docs/wiki/architecture-split.md` §3 for the measured row counts.

**Last updated**: 2026-11-05

---

## 1. What a pack is, and what it is not

A pack is a **versioned directory of source data with a manifest**. It is
the unit `sloth-comint` publishes and that `sloth` and `sloth-dash` each
vendor a pinned snapshot of, so both build and run offline
([ADR 0003](adr/0003-intelligence-is-files.md)).

A pack is **not** compiled artifacts. Generators turn a pack into C
tables — one generator per consumer — and those tables are build output,
never committed, exactly as `build/web/` is not committed today. A pack
contains the data and its provenance; it contains no `.c`, no `.a`, and
no index built for one consumer's lookup.

A pack is also **not** a feed. Nothing in a sloth build fetches one.
`make update-oui` and `make update-btsig` already work this way — they
copy from a given directory and never reach the network — and that
property is the one a pack has to keep.

---

## 2. The manifest

One file at the pack root, `manifest.json`. Every field is required
unless marked optional; a pack with a missing or malformed field is
refused rather than partially loaded, the way
`ble_watchlist_set_table()` refuses a row with no source
(`src/ble_watchlist.c:50`).

### 2.1 Pack-level fields

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | integer | the version of **this format**. `1` for everything described here. A consumer that does not know the value refuses the pack rather than guessing which fields it understands |
| `pack_version` | string | the version of **this pack's content**, semantic (`MAJOR.MINOR.PATCH`). A major bump means a consumer's generator may need changing; a minor means rows were added; a patch means rows were corrected |
| `pack_name` | string | which pack this is, so one installation can hold several (`ieee-registry`, `btsig`, `vendor-research`, `attacker-ouis`, …) |
| `build_time` | string | RFC 3339 UTC, when the pack was assembled. Informational: it is not the data's date — each file carries its own retrieval date (§2.2) |
| `files` | array | one entry per file, §2.2. Order is the manifest's own; a consumer must not depend on it |
| `notes` | string, optional | free text for a human reading a diff |

`pack_version` is the string a finding reports. Per #184 C6, JSONL
`sensor_health` and every alert whose rule consulted a table carry
`intel_pack` as a version **and a hash** — the model is the `inventory`
content hash alerts already carry. The hash is the manifest's own
SHA-256, which covers every file hash in it.

### 2.2 Per-file fields

| Field | Type | Meaning |
|---|---|---|
| `path` | string | pack-relative, forward slashes, no `..` and no leading `/`. A consumer rejects anything else without reading it |
| `sha256` | string | lowercase hex of the file's bytes as committed. This is the field that makes a pack verifiable; a mismatch is a refusal, not a warning |
| `bytes` | integer | the file's length, so a truncated copy fails before it is parsed |
| `rows` | integer, optional | the row count the publisher counted, for the files that have rows. `web/data/SOURCE.md` and `web/data/btsig/SOURCE.md` already record this per file and their tests hold the committed bytes to it |
| `source_url` | string | where the bytes came from. For a file written by hand rather than fetched, the document it was written from |
| `retrieved` | string | `YYYY-MM-DD`, when the bytes were obtained from `source_url`. Not when the pack was built, and not when the registry last changed a row — `web/data/SOURCE.md` is explicit about that distinction and the manifest keeps it |
| `licence` | string | the terms the source publishes under, as the source states them |
| `format` | string | how to parse it: `csv-ieee-registry`, `csv-value-name`, `md-vendor-entry`, `csv-rows` |

Three properties the hashes must have, each from something `web/data/`
already does:

- **The hash is of the file as committed**, not of whatever was
  downloaded before conversion. `web/data/btsig/SOURCE.md` records the
  upstream YAML hashes separately, in prose, because the CSVs are the
  YAML through a converter. A v1 manifest does the same: `sha256` is the
  pack's file; an upstream hash, if there is one, goes in `notes`.
- **A hash that nothing checks is decoration.** `web/tests/test_oui.c`
  and `web/tests/test_btsig.c` fail when a committed CSV's hash does not
  match its `SOURCE.md` row, which is why those hashes are true. A pack
  needs the equivalent test in `sloth-comint` and a verify step in each
  consumer's build.
- **No hash of the manifest inside the manifest.** The manifest's own
  SHA-256 is what `intel_pack` reports, computed over the file by whoever
  reads it.

---

## 3. The file set a v1 pack carries

Grouped as the publishing workflows already group them, because the
refresh tool and the provenance file are per group. Row counts are
today's committed data, from each `SOURCE.md` and from
[architecture-split.md](architecture-split.md) §3 — they are what a v1
pack has to be able to represent, not a target.

### 3.1 IEEE Registration Authority registries

From `web/data/`, provenance in `web/data/SOURCE.md`, refreshed by
`web/tools/update_oui.sh`. Taken from Debian's `ieee-data` package;
the IEEE refuses scripted download.

| File | Registry | Rows today | `format` |
|---|---|---|---|
| `oui.csv` | MA-L, 24-bit blocks | 39 630 | `csv-ieee-registry` |
| `mam.csv` | MA-M, 28-bit blocks | 6 451 | `csv-ieee-registry` |
| `oui36.csv` | MA-S, 36-bit blocks | 7 064 | `csv-ieee-registry` |
| `iab.csv` | IAB, the retired 36-bit blocks | 4 575 | `csv-ieee-registry` |

### 3.2 Bluetooth SIG assigned numbers

From `web/data/btsig/`, provenance in `web/data/btsig/SOURCE.md`,
refreshed by `web/tools/update_btsig.sh` from a given directory of the
SIG's YAML. Only the value and name columns are kept.

| File | Table | Rows today | `format` |
|---|---|---|---|
| `company_identifiers.csv` | company identifiers | 4 057 | `csv-value-name` |
| `service_uuids.csv` | 16-bit service UUIDs | 76 | `csv-value-name` |
| `appearance_values.csv` | appearance values | 342 | `csv-value-name` |

### 3.3 Vendor research entries

From `web/data/vendors/`, one Markdown file per researched OUI holder,
written by hand from cited sources; the format and rules are
[vendor-research](vendor-research.md). **276 entries** today —
`web/data/vendors/` holds 277 `.md` files, of which `COVERAGE.md` is not
an entry and is skipped by name (`Makefile:700`). Each entry's `source_url`
is the document it was written from; `format` is `md-vendor-entry`.

`COVERAGE.md` travels with them: it records which of the reference host's
registry names have an entry and which are pending, and
`web/tests/test_vendorkb.c` holds the entries to it.

### 3.4 Attacker and device-identity rows now hand-kept in `src/`

These are the rows #184 §1 item 3 names, measured in
[architecture-split.md](architecture-split.md) §3.1. They are rows in C
today; in a pack they are `csv-rows` files with the same columns the C
struct has, and a generator writes the C back.

| Pack file | From | Rows today | Columns |
|---|---|---|---|
| `attacker_ouis.csv` | `src/wifi_oui_attacker.c` — `kHak5Ouis` (2) and `kEspressifOuis` (11) | **13** | OUI, family, note |
| `camera_vendors.csv` | `src/camera_vendor.c` `g_cam_oui` | **455** | OUI, vendor, registry assignee string, mixed-vendor flag |
| `camera_server_brands.csv` | `src/camera_vendor.c` `g_cam_server_brands` | **9** | brand token |
| `camera_services.csv` | `src/camera_vendor.c` `g_cam_svcs` | **3** | DNS-SD service, label, camera-specific flag |
| `camera_setup_ssids.csv` | `src/camera_vendor.c` `g_camera_setup_ssid_pats` | **4** | SSID prefix, label, brand |
| `surveillance_endpoints.csv` | `src/vendor_watchlist.c` `kEndpoints` | **4** | domain, vendor, family |
| `tool_fingerprints.csv` | `src/tool_fingerprint.c` `TOOL_SIGNATURES` | **1** | id, vendor-IE hash, interval, rates, require and forbid flags, confidence cap, name, evidence, version |
| `oui_builtin.csv` | `src/oui.c` `g_oui` — the fallback table slothweb's generator reads when no registry CSV is present | **117** | OUI, vendor |
| `vendor_ie_ouis.csv` | `src/dot11_ie.c` `k_oui` | **16** | OUI, vendor |

Two entries on #184's list have no rows to carry, and v1 has to represent
that honestly rather than ship an empty file that reads as "nothing to
find":

- **`ble_watchlist.csv`** — the BLE watchlist ships **zero** rows
  (`src/ble_watchlist.c:5–9`). The schema exists
  (`src/ble_watchlist.h`), the validating setter exists, and
  `research/bluetooth/ble-watchlist-categories.md` lists four candidate
  categories with what each still needs. A v1 pack carries the file with
  a header and no rows; a consumer treats zero rows as "no claim", which
  is what `ble_watchlist_match()` already returns.
- **`known_stacks.csv`** — does not exist. #151 is open, waiting on
  owner-supplied rig captures, and plan #145's second ruling forbids a
  fingerprint row without a primary source
  ([attack-hardware-fingerprints](attack-hardware-fingerprints.md)). The
  pack schema reserves the file name and v1 ships no such file.

`tool_fingerprints.csv` inherits a rule from the table it replaces:
every row carries an `evidence` string naming the capture and the
firmware version, and a row without one is unverified and capped at `med`
confidence. The pack format must carry `evidence` as a required column,
or the move loses the only thing that makes those rows re-checkable.

### 3.5 Candidates not in #184's list

[architecture-split.md](architecture-split.md) §3.2 found nine further
tables in `src/` that meet ADR 3's own definition of intelligence —
`src/captive_portal.c`'s connectivity-check sentinels and phishing-kit
needles, `src/ble_flood.c`'s advertisement-spam families,
`src/ip_owner.c`, `src/services.c`, `src/reg_table.c`'s regulatory rows
and `src/wifi_freq.c`'s band plan. Whether they move is open (ADR 3).
This draft does **not** reserve file names for them: a reserved name for
a table nobody decided to move reads as a decision, and that decision is
the owner's.

---

## 4. A published pack is immutable

Once a pack version is published, its bytes never change (#184 §2 C6).
A correction is a **new version**, never an edit:

- A row corrected is a patch bump. A row added is a minor bump. A column
  or file added or removed, so that a generator must change, is a major
  bump.
- A pack version is never re-published with different content. A
  consumer that pinned `1.2.0` and verified its hashes must get the same
  bytes forever, or the pin means nothing and `intel_pack` on an alert
  names something unreproducible.
- Withdrawing a pack version is allowed; rewriting it is not. A withdrawn
  version stays withdrawn — the replacement has a new number.

This is the same discipline the repository already applies to every
recorded value: schema migrations are additive and never rewrite a
recorded value in place (owner ruling 2026-10-21, `agents/AGENTS.md`),
and `LEDGER.md` rows are append-only. The reason is the same in all three
cases: a stored artifact that can change retroactively makes every report
quoting it unverifiable.

The practical consequence for Stage 1: `make pack` writes
`dist/sloth-intel-pack-<ver>.tar`, and the golden pack committed beside
it is a fixed input the parity tests run against (#184 §3 Stage 1
items 3 and 4). If the golden pack has to change, the version changes
with it.

---

## 5. What Stage 1 has to settle

Named here so they are not mistaken for settled:

- Manifest encoding. JSON is assumed above because the
  `sloth-comintd` routes are HTTP and `sloth-dash` already parses JSON;
  a C99 consumer with no JSON library may prefer the `key: value` shape
  the repository uses elsewhere.
- Whether one pack carries every group in §3 or each group is its own
  pack. `pack_name` exists for the second; the per-group refresh tools
  and provenance files point the same way.
- The verify step's home: a library both consumers link, or a check each
  generator does.
- Which of §3.5's tables are in scope (ADR 3's open ruling).
- Whether `comint.db` is built from a pack or is the pack's source. #184
  §3 Stage 1 puts a `comint.db` DDL in `schema/` and a loader in
  `tools/`, which implies built from, but does not say it.

---

## Related pages

- [ADR 0003 — intelligence is files](adr/0003-intelligence-is-files.md) — the decision this format serves.
- [ADR 0007 — versioning](adr/0007-versioning.md) — where the pack schema version sits among the others.
- [[architecture-split]] — the measured tables and row counts this draft is built from.
- [[vendor-research]] — the entry format for §3.3.
- [[attack-hardware-fingerprints]] — why `known_stacks.csv` is absent.
- [[mac-randomisation]] — what an OUI lookup can and cannot say.
- [[jsonl-schema]] — where `intel_pack` will be reported.
