# sloth web UI: alert triage and the FRRS emitter record

**Working name:** `frrs` (the module), `SlothFrrs` (its namespace)
**Applies to:** `web/` (slothweb) only. `src/` is untouched.
**Status:** specification for the owner to read, 2026-10-27; slices
F0-F4 built 2026-11-01, review fixes 2026-11-02, F5's vendor KB hook
(§4.2) wired 2026-11-02; the RSSI series (Q7, answered 2026-11-02)
built 2026-11-02. Where the build departs from the body, §14
says how and why, and wins; §12 says which default each open question
took until the owner answers it.
**Companions:** `docs/web-ui-spec.md` (the UI spec and its rulings
table), `docs/web-visual-spec.md` (the glyphs), `docs/wiki/slothweb.md`,
`docs/wiki/capture-scope.md`.

> **Rulings this document depends on, and the one it reverses.**
>
> | Topic | Ruling | Effect here |
> |---|---|---|
> | Read-only | `docs/web-ui-spec.md` rulings table, 2026-10-21: "No POST, PUT, DELETE and no control endpoint, ever". | **Reversed in part by the owner's request of 2026-10-27** (quoted in §0): triage and TACDB are operator state and need a write. The write surface is POST only, to slothweb's own store only, and `--web-read-only` (§5.7) restores the 2026-10-21 surface byte for byte. "slothweb never writes `sloth.db`" (§13.7 of the UI spec) stands. |
> | Charter | `MISSION.md` §2: passive; the one absolute is no injection onto a monitored segment. | Nothing here sends a frame or resolves a name. §9 lists what the record cannot say because of it. |
> | Access | The allow list is the trust boundary (W0). | It stays the trust boundary for writes too: there is no login. §5.6 says what "by" means without one. |
> | Location | Another session's slice (`loc-alert`, `loc-drawer`, `window.SlothLocation`). | Left untouched; the record says "no location axis" where FRRS would have one (§4.2). |
> | Store migrations | Owner ruling 2026-10-21: additive, one `BEGIN IMMEDIATE`, a test on a previous-version file including the failure that leaves it unchanged. | slothweb.db v5 → v6 (§3.6). |

## 0. What this document is, and what it was built from

The owner asked (2026-10-27, verbatim):

> on each alert record add buttons for triaging alerts such as, false,
> noise, incident. following recommended. Gather information with this
> structuer following COMINT FRRS: Frequency Resource Record 1. BEI:
> Background Environment Information 2. SCS: Spectrum Certification
> System 3. EC/S: Equipment Characteristics/Space 4. TACDB: platform
> lists, sorted by nomenclature, which contain links to the C-E
> equipment complement of each platform, with links to the parametric
> data for each piece of equipment, military unit lists and their
> subordinate units with equipment used by each unit.

and added, approving the mapping in §1 ("looks good"):

> COMINT, which is defined to be communications among people, will
> reveal some or all of the following: 1. Who is transmitting 2. Where
> they are located, and, if the transmitter is moving, the report may
> give a plot of the signal against location 3. If known, the
> organizational function of the transmitter 4. The time and duration
> of transmission, and the schedule if it is a periodic transmission
> 5. The frequencies and other technical characteristics of their
> transmission 6. If the transmission is encrypted or not, and if it
> can be decrypted. If it is possible to intercept either an originally
> transmitted cleartext or obtain it through cryptanalysis, the
> language of the communication and a translation (when needed). 7. The
> addresses, if the signal is not a general broadcast and if addresses
> are retrievable from the message. These stations may also be COMINT
> (e.g., a confirmation of the message or a response message), ELINT
> (e.g., a navigation beacon being activated) or both. Rather than, or
> in addition to, an address or other identifier, there may be
> information on the location and signal characteristics of the
> responder.

Both passages are the Wikipedia *Signals intelligence* article's
("Electronic order of battle" lists the five Joint Spectrum Center
technical databases FRRS, BEI, SCS, EC/S and TACDB beside the location
database; "Communications intelligence" lists the seven disclosures,
cited there to JP 1-02). That article was fetched and checked on
2026-10-27; it is the one public source this document could reach.

**What could not be verified this session.** The Standard Frequency
Action Format (SFAF, MCEB Pub 7) and the NTIA *Manual of Regulations
and Procedures for Federal Radio Frequency Management* Chapter 9
(the frequency assignment data items) are the public field models the
owner's structure descends from. Neither text was reachable (NTIA's
publication pages answered 404/403; the search budget was spent), so
§1 borrows their **field names** where they fit — *emitter*, *station
class*, *emission designator*, *equipment nomenclature*, *platform*,
*unit*, *equipment characteristics*, *supplementary details* — and
quotes **no item numbers**. Anyone who has MCEB Pub 7 or NTIA Chapter 9
to hand should check §1's third column; it is listed as open question
Q12.

Everything else here is from the repository as of `c5650a3`:
`src/jsonl.c` (what sloth emits per emitter), `src/db_schema.c`
(what `sloth.db` keeps), `docs/wiki/jsonl-schema.md`,
`docs/wiki/sqlite-schema.md`, `docs/wiki/rf-distance.md`,
`docs/wiki/capture-scope.md`, `web/src/web_store.{c,h}` (the store's
migration convention), `web/src/web_routes.h`, `web/src/web_http.h`,
`web/src/web_query.h` (the parameter parser's strictness),
`web/src/web_alerts.h`, `web/src/web_devices.h`, `web/src/web_live.h`,
`web/src/web_scope.h`, `web/ui/app.js`, `web/ui/glyph.js`,
`web/ui/index.html`, `web/README.md`.

### 0.1 The two things being built

1. **Triage.** Every alert row, everywhere one is drawn, gets five
   buttons: *false*, *noise*, *incident*, *known* (green; owner
   request 2026-11-03) and *follow recommended*.
   The state is kept in slothweb's own store, every change appends a
   row (so every change is reversible by another), with an optional
   note, a timestamp, and who. Rows are filterable by state; the
   open-alerts tile shows triaged-out counts separately and never
   silently drops them.
2. **The FRRS emitter record.** For every emitter sloth hears (a Wi-Fi
   station, a BSSID, a BLE advertiser) and for the emitter an alert
   names, a record in five groups: BEI (the RF environment around it),
   SCS (certification and compliance posture), EC/S (observed
   parametrics), TACDB (the operator's platforms, equipment and units),
   and **Report**, the owner's COMINT seven items, built only from what
   sloth already records and naming the sloth source of every field.

Nothing here adds a record to sloth, a column to `sloth.db`, or a
frame to the air.

## 1. Vocabulary: FRRS and SFAF names mapped onto sloth

| FRRS group | What it is in the DoD model (per §0's source) | SFAF name borrowed | What it is here | Where it shows (§6) |
|---|---|---|---|---|
| **Frequency Resource Record** | The record of one assignment: who, where, what equipment, on what frequency, with what emission. | *emitter*, *station class*, *emission designator* | One **emitter record**: a Wi-Fi STA MAC, a BSSID, or a BLE address (+ address type). *Station class* is sloth's role for it: AP, client, MLD, BLE advertiser. *Emission designator* is the PHY generation and channel width sloth decoded (§4.3). | the alert page, the device drawer, the TACDB tab |
| **BEI** Background Environment Information | The RF environment the assignment sits in. | *supplementary details* | The channel's occupancy and co-channel networks (the channel mix), the regulatory domain seen on the air, interference indicators (`RF_DEGRADED`), time-of-day presence, and the site baseline / anomaly state (§4.1). | alert page, drawer |
| **SCS** Spectrum Certification System | Equipment certification (DD Form 1494 / J/F-12) and compliance. | *equipment nomenclature* | Certification data from the vendor research KB (`web/data/vendors/`: the registrant's entry's FCC grantee codes, wired 2026-11-02) and sloth's own compliance findings for the emitter: `COUNTRY_ABSENT`, `TPC_ABSENT_HIGH_BAND`, `DFS_MASKING`, cipher / MFP / WPA3 posture (§4.2). | alert page, drawer |
| **EC/S** Equipment Characteristics/Space | The parametric data of each piece of equipment. | *equipment characteristics* | The emitter's observed parametrics: bands, widths, PHY generation, ciphers and AKMs, MFP, TX power / TPC, rates, vendor IEs, WPS; for BLE: PHY, advertising interval, TX power, appearance (§4.3). | alert page, drawer, TACDB platform view |
| **TACDB** | Platform lists by nomenclature → each platform's C-E equipment complement → each equipment's parametrics; unit lists with subordinate units and their equipment. | *platform*, *unit*, *nomenclature*, *equipment complement* | Operator-kept **platforms** (a phone, a laptop, an AP, a camera), each with its **equipment complement** (the emitters it owns, each linking to its EC/S), under **units** (site → room / vehicle / person) with subordinate units. Auto-suggested from sloth's correlations, confirmed by the operator, exportable (§4.4, §7, §8). | the TACDB tab |
| **Report** (the owner's addendum) | COMINT's seven disclosures. | — | Identity, signal and radio, function, timing, technical characteristics, protection posture, peers (§4.5), each field with its sloth source and "not observed" when absent; "no location axis" and "sloth decrypts nothing" stated in the UI. | alert page, drawer, TACDB platform view |

Two terms are used throughout:

- **emitter**: `(kind, addr)` with `kind` one of `sta` (a Wi-Fi client
  MAC: `probe_clients`, `pnl_clients`, `assocs.sta_mac`, `wifi_stas`,
  `devices` with a monitor source), `bssid` (`beacon_aps`, `wifi_aps`,
  `assocs.bssid`, `wifi_mld.mld_mac`), `ble` (a BLE address with its
  `addr_type`, from the `ble_device` stream record). An IP address is
  **not** an emitter: it is a lease a peer holds, and appears in the
  Report's *peers* and *identity* only.
- **finding**: one alert key as `sloth.db` records it (one row per
  finding since schema v8, #170) — the thing triage attaches to (§3.1).

## 2. The operator's questions this answers

`docs/web-ui-spec.md` §1's four questions gain two:

5. **Have I already judged this?** An alert the operator called noise
   last week should say so wherever it is drawn, and should not inflate
   the open count while never leaving it.
6. **What is this emitter, physically, and whose is it?** Not "which
   vendor" (M4 answers that) but the radio: what it can do, how it is
   configured, what it talks to, when it is here, and which platform
   and unit the operator has filed it under.

## 3. Data model

### 3.1 Triage

**States.** `untriaged` (no decision; the default and the absence of
rows), `false` (the rule fired on something that is not what it
detects), `noise` (what the rule detects, but expected here), and
`incident` (what the rule detects, and it matters), and `known`
(known good — expected traffic from a friendly or neutral emitter (the FRRS/EW affiliation sense: friend, or neutral per MIL-STD-2525's green); triaged out like false/noise, never an incident; added 2026-11-03 at the owner's request, "a Green tag for known
or a sigint term for known good traffic"). The decided states are the
owner's words; `untriaged` is reached again by an explicit *clear*,
which is itself a row.

`known` is stored as 4, appended after `incident` so the stored values
0..3 keep their meaning. Nothing in slothweb.db rejects 4 (the
`state` column has no `CHECK`; the route and the import validate the
word against the state table, and the read clamps anything outside it
to `untriaged`), so it needs **no schema step**: an older build reading
a 4 shows the alert untriaged, the safe direction, and the row is kept
as written.

**Subject.** A triage row attaches to a **finding**, named
`d<rowid>` where `rowid` is the smallest rowid of the finding's key in
`sloth.db`'s `alerts` table (its first row; a v8 file has one, an older
file many, and the first never changes as rows accrete). A stream
incident (`s<handle>`, `web_live.h`) is resolved to its finding by
binding its key as a **predicate** (`SELECT MIN(rowid) FROM alerts
WHERE key = ?`), which is how `web_alerts.c` already reads a key: the
key's text is never a result column and is never stored (it can carry a
username). An incident sloth has not yet written (the next `--db` tick)
or that no `sloth.db` can hold (no `--sloth-db`) is accepted under its
stream handle with `finding` NULL; the store thread re-tries the
resolution each tick and sets `finding` **once**, from NULL (§3.6
on why this is not a rewrite). Beside the subject every row carries a
**descriptor** — `type`, `addr` (the finding's `match_ip`, or the MAC a
Wi-Fi rule's key names, canonical), `port`, `first_seen` — so an
exported file can be re-attached on another sensor or after a
`sloth.db` rebuild or `--db-compact-alerts` by descriptor when the rowid
no longer matches (the fallback match is exact on all four). Q1 asks
whether the owner prefers the descriptor as the primary key.

**Row.** Appended, never rewritten (but `finding`, set once, and
`folded`, a count); the current state is the newest row of the
subject.

| Column | Type | Bound | Meaning |
|---|---|---|---|
| `id` | INTEGER PK | | |
| `subject` | TEXT | 32 | `d<rowid>` or `s<handle>` as received |
| `finding` | INTEGER | | the rowid once resolved, else NULL |
| `type` | INTEGER | 0..`ALERT_TYPE_COUNT`-1 | descriptor |
| `addr` | TEXT | 45 | descriptor; canonical (`web_key_ip` / `web_key_mac`), `""` when the finding names none |
| `port` | INTEGER | 0..65535 | descriptor |
| `first_seen` | INTEGER | | descriptor: the finding's first row's |
| `state` | INTEGER | 0 untriaged, 1 false, 2 noise, 3 incident, 4 known | anything else read as untriaged |
| `prev_state` | INTEGER | | what the newest row said before this one (0 for the first) |
| `via` | INTEGER | 0 manual, 1 recommended, 2 import | how the state was chosen |
| `basis` | TEXT | 96 | for `via` 1: the assessment's own words that recommended it (slothweb's copy of the front-matter value, not operator text) |
| `note` | TEXT | 240 | operator text, optional |
| `by` | TEXT | 32 | operator text, optional (§5.6) |
| `peer` | TEXT | 45 | the connection's peer address, canonical |
| `ts` | INTEGER | | the server's clock at the write; an imported row's, the file's (at most 300 s ahead of this clock) |
| `folded` | INTEGER | | rows of this alert's history folded away and counted here (below) |
| `claim_by`, `claim_peer` | TEXT | 32, 45 | an imported row's `by` and `peer` as its file said them: claims, shown "imported, claimed …"; the row's own `peer` is the importer and `who` is empty |

Every TEXT column is valid UTF-8 with no control byte, cut to its bound
on a code-point boundary at validation (not at storage: an over-long
value is refused, §5.4). No column can hold a credential: `addr` is an
address, `basis` is slothweb's own copy, and `note` / `by` are
operator-typed — `test_store.c`'s guardrail (no column named for a
credential word, nothing from the stream stored as text) is extended to
assert that no stream string reaches this table (§10).

**Bounds.** `WEB_FRRS_TRIAGE_CAP` 20,000 rows, `WEB_FRRS_HIST_PER` 64
rows per alert, of them at most `WEB_FRRS_IMPORT_PER` 8 imported.
Triage rows are operator state: like the baselines and episodes they
count towards `--web-max-mb` and are **never dropped by the ceiling**.
No bound refuses an operator's write that changes the current state:

- *One alert past 64 rows* folds: its first row and its newest are
  kept, the oldest between them deleted, and their number added to the
  first row's `folded`; the history says "N older folded". An import
  past 8 of its own rows on one alert folds its oldest imported rows
  the same way, so a file can never fill an alert's history before its
  operator does.
- *The table at 20,000* folds superseded rows (an alert's current row
  never): imported ones first, then those of alerts whose newest row is
  older than 7 days (closed or aged out), then the oldest, a batch of
  1 % at a time so the scan (81 ms over a full table on the reference
  host) runs once per 200 writes; each folded row's count moves to its
  alert's newest row. An import makes room among imported rows only.
  With nothing superseded left a decided state is `507 triage_full`;
  a **clear is always taken** (the row it supersedes folds at once, so
  the table stays at its cap).
- *A write identical to the current state with no new note* is a
  `200` with `"unchanged":true` and no row: a double click, or a clear
  of an untriaged alert, never spends history.

`/api/health` `frrs` reports `triage_rows`, `triage_cap`,
`triage_folded` and `triage_unchanged`; `/api/frrs/summary` carries
`rows`, `cap` and `near_cap` (from 90 %), and the open-alerts tile then
says the store is near its cap and that superseded rows fold. Q2 (fold
or refuse) is answered for now by the review of 2026-11-02 (§12.1).

**"Follow recommended."** The recommendation for an alert type comes
from its research assessment, `docs/wiki/alert-assessments/<TYPE>.md`
(being written in parallel), whose front matter carries
`false_positive_risk`, `noise_verdict` and `severity_assessment`. The
mapping, checked against the vocabulary the batch actually writes (the
72 files of `b1fbc2a`: `noise_verdict` begins `not seen` 43, `noisy`
14, `quiet` 10, `very noisy` 5; `false_positive_risk` begins `low`,
`medium` or `high`; `severity_assessment` begins `agree` 60 or `too
high` / `too low` 12):

| Front matter | Recommended state | `basis` |
|---|---|---|
| `false_positive_risk` beginning `high` **and** `noise_verdict` beginning `noisy` or `very noisy` | `noise` | `false_positive_risk high; noise_verdict: <the line>`, cut to 96 bytes |
| an assessment that does not meet that bar | none: the button reads **no automatic triage: <false_positive_risk's first words>** and does nothing (`why_none` `no_automatic_triage`); the front matter is shown beside it as advice | |
| no file, no front matter, or no directory | none: **no recommendation yet** (`why_none` `no_assessment`) | |

`noise_verdict` describes the **counting artefact** on the reference
host — how often the rule fired, mostly per-evaluation re-firing of one
standing condition — not whether an alert is real. FRAG_PLAINTEXT is
"very noisy" (20.5 million fires on one key) with `false_positive_risk:
low`: a real finding re-counted; SMB1_USE is "noisy in count, quiet in
findings", also `low`. Neither gets `noise`. Of the 72 assessed types
eight meet the bar (BEACONING, CAPTIVE_PORTAL, EVIL_TWIN_PROXIMITY,
MY_NETWORK_RECON, PM_FORGE, RECURRING_TRANSIT, SURV_CLOUD_SNI,
WPA_DOWNGRADE).

The assessments judge a **rule**, not an alert. `false_positive_risk:
high` says the rule is often wrong — ARP_SPOOF and WPA_DOWNGRADE are
among the 13 types that say it — not that the alert on screen is, and a
real ARP spoof marked `false` by one click would be dimmed in every
list; so it recommends nothing and is shown beside the buttons.
`severity_assessment` (`agree`, `too high`) judges the severity level,
not whether the alert is real, so it never recommends `incident`.
Nothing ever recommends `false`, nor `known`: whether an emitter is
the operator's own or expected is a fact about this site no assessment
of a rule can know. A mixed `noise_verdict` is decided by
its first words. Q3 asks the owner whether either of the other two
should ever recommend. Two sources, one
interface (`web_frrs_recommend(type, out)`): the compiled table
`web/src/web_alertasm.{c,h}` once the other session's generator lands
(one `#include` and one call), and until then a runtime reader of
`<dir>/<TYPE>.md`'s front matter with `dir` from `--web-assessments DIR`
(§5.7), default unset, which means every type answers "no
recommendation yet"; `slothweb.service` passes the copy `make install`
puts in `$(PREFIX)/share/sloth/alert-assessments`. The reader opens `<dir>/<TYPE>.md` with `TYPE`
taken from `sloth_alerts.def` (never from the request), reads until
the front matter closes and at most 32 KiB (`WEB_FRRS_ASSESS_MAX`; the
longest real front matter, PM_FORGE's, is 4,823 bytes, past the 4 KiB
first built), and parses only the three keys.

### 3.2 TACDB: units, platforms, emitters

Three tables, each row soft-deleted (`deleted` 0/1) so a delete is a
reversible change like any other, and each with `created`, `updated`
(server clock) and `origin`.

**`tacdb_unit`** — the organisational tree.

| Column | Bound | Meaning |
|---|---|---|
| `id` INTEGER PK | | |
| `parent` INTEGER | NULL root | the superior unit; depth at most `WEB_FRRS_UNIT_DEPTH` (4: site → building/floor → room/vehicle → person; Q4) |
| `name` TEXT | 64 | operator text, unique among the live children of one parent (ASCII case-insensitive) |
| `kind` INTEGER | 0 site, 1 area, 2 room, 3 vehicle, 4 person, 5 other | |
| `note` TEXT | 240 | |
| `origin` INTEGER | 0 operator, 1 import | |
| `created`, `updated` INTEGER, `deleted` INTEGER | | |

**`tacdb_platform`** — a physical thing that carries equipment.

| Column | Bound | Meaning |
|---|---|---|
| `id` INTEGER PK | | |
| `unit` INTEGER | NULL unfiled | the owning unit |
| `nomenclature` TEXT | 64 | the platform's name, unique among live platforms; operator-typed, or auto `"<vendor> <class> <last two octets>"` (Q5 on the format) |
| `class` INTEGER | 0 unknown, 1 phone, 2 laptop, 3 ap, 4 iot, 5 camera, 6 wearable, 7 vehicle, 8 infrastructure, 9 other | suggested from sloth: `devices.is_ap` → ap; `device_class` camera → camera; BLE `appearance` category (watch, HID) → wearable / iot; `pnl_clients.os_fp` → phone / laptop |
| `vendor` TEXT | 64 | the OUI table's label at creation (slothweb's own string), or operator text |
| `note` TEXT | 240 | |
| `confirmed` INTEGER | 0 suggested, 1 confirmed | a suggestion the operator accepted becomes 1; a platform the operator typed is born 1 |
| `origin` INTEGER | 0 operator, 1 import, 10 + rule for a suggestion (§7) | |
| `created`, `updated`, `deleted` | | |

**`tacdb_emitter`** — the equipment complement: which emitters a
platform owns. The EC/S parametrics are **not copied here**; they are
read from `sloth.db` and the ledger (§3.3) when shown, so the TACDB
never goes stale against what sloth sees.

| Column | Bound | Meaning |
|---|---|---|
| `platform` INTEGER | | |
| `kind` INTEGER | 0 sta, 1 bssid, 2 ble | §1's emitter kinds |
| `addr` TEXT | 17 (+ `/<type>` for BLE: 19) | canonical lower-case colon MAC; BLE `aa:bb:cc:dd:ee:ff/1` carries `addr_type` |
| `role` INTEGER | 0 primary, 1 mld-link, 2 rotation (a randomised address the platform used), 3 vap (a BSSID family member), 4 other | |
| `label` TEXT | 32 | operator text ("work laptop wifi") |
| `confirmed`, `origin`, `created`, `updated`, `deleted` | | as the platform's |
| PRIMARY KEY (`platform`, `kind`, `addr`); a live `(kind, addr)` belongs to **one** platform (an index with `WHERE deleted = 0`) | | |

**`tacdb_dismiss`** — a suggestion the operator declined, so it is not
offered again: `(rule, a, b, ts)` with `a`, `b` the two canonical
addresses the rule joined (`b` `""` for a one-address rule).

**Bounds.** `WEB_FRRS_UNITS` 512, `WEB_FRRS_PLATFORMS` 2,048,
`WEB_FRRS_EMITTERS` 8,192, `WEB_FRRS_DISMISS` 4,096 live rows; and,
since a delete keeps its row, twice each counting deleted rows, so
create-then-delete cannot grow a table without end. Operator state,
never dropped by the ceiling; a write at either bound is `507
tacdb_full` (a restore adds no row and meets only the live one).

### 3.3 The parametric ledger (in memory, not persisted)

Much of EC/S and BEI is in the stream and **not** in `sloth.db`:
`beacon`'s `operating_width`, `primary_channel`, `secondary_offset`,
`channel_source`, `wps_manufacturer` / `wps_model_name` /
`wps_model_number`, `vendor_ies_hash`, `ie_order_hash`,
`tbtt_jitter_us`, `rssi_min_60s` / `rssi_max_60s`, `fp_flags`, the
`est_dist_*` fields; the whole `wifi_regulatory` record; `wifi_mld`'s
link list; `wifi_assoc_req`'s `supported_rates`, `listen_interval`,
`capability_info`; `seqnum_correlation`'s evidence fields; the whole
`ble_device` record; `tls` SNI and the cleartext-protocol records per
source IP.

slothweb keeps the **latest** of each per emitter in bounded LRU
tables, the way `web_ident.c` keeps names: `WEB_FRRS_LEDGER_BSSID`
1,024 BSSIDs (beacon + regulatory + mld), `WEB_FRRS_LEDGER_STA` 2,048
stations (assoc_req + pnl + seqnum partner list of 4), `WEB_FRRS_LEDGER_BLE`
1,024 advertisers (one row per `(addr, addr_type, sensor)` as the record
is keyed), `WEB_FRRS_LEDGER_IP` 512 addresses (the last 8 distinct TLS
SNIs as 64-bit hashes **and** the last 8 as text cut to 64 bytes — the
text is shown, the hash dedups; the cleartext protocol set as bits:
http, cleartext_cred by protocol, smb1, snmp v1/v2c, ldap anonymous
bind, telnet/ftp when sloth records them). Evictions are counted on
`/api/health` (`frrs.ledger_evictions`). The ledger is lost on restart
and refilled by the stream's full re-broadcast on connect
(`jsonl-schema.md`, #47) — so "not observed" after a restart means "not
in the last snapshot pass", and the Report says which (§4.5, the
`since` member). It is written by the ingest thread and read by the
HTTP thread under one mutex, like `web_ident`.

Every string in it came off the socket and is hostile: cut on a
code-point boundary at its bound, leaves only through `web_jw_str()`,
and is never stored to disk — the ledger is the one place a stream
string lives in frrs, and it is memory.

### 3.4 What is read from `sloth.db` (allow-listed, read-only)

Per emitter, through the existing M4 reader and its column allow-list
(`web_slothdb.h`): `beacon_aps`, `beacon_ap_ssids`, `ssid_akm_history`,
`wifi_aps`, `wifi_stas`, `probe_clients`, `pnl_clients`, `pnl_ssids`,
`assocs`, `assoc_reqs`, `btm_requests`, `wifi_merged`, `devices`,
`arp`, `dhcp_leases`, `top_hosts`, `mdns_services`, `nbns_names`,
`seqnum_correlations`, `karma_candidates` (the evidence columns, not
`last_identity`), `sensors`, `alerts` (the finding's rows: predicate on
key, `type`, `sev`, `first_seen`, `last_seen`, `count`, `reopens`,
`match_ip`, `match_port`), and the flow tables by IP (`ssh_flows`,
`rdp_flows` less the cookie, `smb_sessions`, `snmp_flows` less the
community, `ldap_events`, `kerb_events` less the preauth counts, as the
allow-list already has them). New columns the reader needs that the
allow-list lacks today: `beacon_aps.beacon_ms`, `.pairwise`,
`.group_ciph`, `.akm`, `.mfp`, `.has_wps`, `.wps_state`, `.wps_locked`,
`.phy`, `.downgrade_flags`, `.akm_bits`, `.has_qbss`, `.qbss_stations`,
`.qbss_chan_util`; `assoc_reqs.*` (none secret: suite identifiers,
rates, a hash); `wifi_merged.*`; `seqnum_correlations.*`;
`pnl_clients.os_fp`, `.phy`, `.phy_confirmed`. `test_slothdb.c`'s
column test is extended with each; none is TEXT holding a peer-chosen
string except `beacon_aps.pairwise/group_ciph/akm/phy/enc`
(sloth's own labels) and `pnl_clients.os_fp` (sloth's own label).

### 3.5 The scope of each datum (`web_scope.h`)

Emitters of kind `sta`, `bssid` and `ble` are Monitor datums; a
device's IP, ARP, DHCP, mDNS, NBNS, flows and TLS are Local. The TACDB
rows are operator state and carry no scope. §8 says how the views
behave.

### 3.6 slothweb.db v5 → v6

One additive step, `STEP_V6_SQL`, in `web_store.c`'s `STEPS[]`, under
the 2026-10-21 rule: plain `CREATE TABLE` (an object of that name
already in the file fails the step and leaves it at v5), one `BEGIN
IMMEDIATE`, its own stamp. Tables: `triage`, `tacdb_unit`,
`tacdb_platform`, `tacdb_emitter`, `tacdb_dismiss`, and the indexes
`triage_subject (subject, id)`, `triage_finding (finding, id)`,
`triage_desc (type, addr, port, first_seen)`, `tacdb_emitter_addr (kind,
addr) WHERE deleted = 0` (unique), `tacdb_platform_nom (nomenclature)
WHERE deleted = 0` (unique), `tacdb_unit_parent (parent)`.
`WEB_STORE_SCHEMA` becomes 6 and the compile-time check that the chain
reaches it holds.

Tests, as `test_store.c` has them for every step: `test_v5_file_is_
migrated` (a v5 file as the chmix slice left it, with chmix rows,
brought to v6, every row as it was, the new tables empty) and
`test_v5_failed_step_leaves_file_unchanged` (a v5 file already holding
the name `triage_subject` as an index on `minute`: stays v5, keeps that
index and every row, the error names "unchanged from v5"; seen red with
the migration's ROLLBACK replaced by COMMIT, as its predecessors were).

**`finding` set once from NULL** (§3.1) is not a migration and is not a
rewrite of a recorded value: the recorded value is the subject the
operator triaged; `finding` is slothweb's resolution of it, recorded
when known. `test_frrs.c :: test_finding_is_set_once` asserts a second
resolution attempt changes nothing (the statement is `UPDATE triage SET
finding = ? WHERE subject = ? AND finding IS NULL`).

## 4. The derivations: every field, its sloth source

Each field below is rendered as **value**, its **source** (the sloth
record or table and column, exactly as named here), and when absent the
word **not observed** with the source it would have come from. A field
whose source is the ledger (§3.3) also carries `since`: the time of the
record it came from. Nothing is computed that sloth does not already
compute; the one exception, the beacon interval's regularity, is
sloth's own `tbtt_jitter_us`.

### 4.1 BEI: the environment around the emitter

| Field | Source | Notes |
|---|---|---|
| Channel and band | `beacon.channel` + `channel_summary.band` for the channel (`ap_band_label()`); a client's from `probe_clients.channel` / `assocs.channel` | |
| Channel occupancy, measured | `channel_summary.ctrl_total/ctrl_rts/ctrl_cts/ctrl_ack/ctrl_blockack` for the channel; the channel mix (`chmix`, slothweb.db v5) for the share of frames per transmitter over the last hour | the owner's "channel occupancy" |
| Channel occupancy, self-reported | `beacon.qbss_stations`, `beacon.qbss_chan_util` (`beacon_aps.has_qbss`) | an AP's own QBSS Load, beside the measured one |
| Co-channel networks | `beacon_aps` rows with the same `channel`, count and the top 8 by `signal_dbm` (SSID, BSSID, enc) | |
| Regulatory domain seen | `wifi_regulatory.country`, `.env`, `.country_present`; the site's consensus: the modal `country` over `beacon_aps` on the air (the ledger) | "the regulatory domain seen" |
| Interference indicators | open or recent `RF_DEGRADED` findings; the channel's `wifi.deauth` series and `DEAUTH_FLOOD` episodes (`/api/wifi/deauth`) | |
| Time-of-day presence | `dev.present` baseline's 168 hour-of-week cells (`/api/baseline`) and the 24 h strip (`/api/device/{mac}`'s `presence`) | the same glyphs the drawer draws |
| Site baseline / anomaly state | the emitter's open and recent episodes (`/api/anomalies` keyed by the MAC), the channel's `wifi.ap_count` and `wifi.ctrl_total` against their bands | |
| Monitor coverage | `sensors` (which radios, their state), `wifi_merged.seen_by` / `best_sensor` for the emitter, `sensor_health.hop_channels` / `hop_silent_channels` | how much of the environment the sensor could hear |

### 4.2 SCS: certification and compliance posture

| Field | Source | Notes |
|---|---|---|
| Vendor (registry) | the OUI table (`/api/lookup`'s `oui` block: block, registry, vendor) | |
| Certification: FCC grantee | `certification_fcc`: the vendor research KB (`web/data/vendors/`, `web_vendorkb_lookup()` on the registry's Organization Name for the address's block): the entry's `fcc_grantee` values as written, each with its `[n]`, and the Sources lines those numbers name; `src` names the entry's file. `v` is null with a `why` for an address in no block, a registrant with no entry, an entry with no grantee code, and a registrant that is one of the entry's *affiliates* (a separate company, whose codes the entry's are not). Wired 2026-11-02 | FCC ID and product, and the WPS `wps_manufacturer` + `wps_model_name` key, are not wired: the KB documents a vendor, not a product |
| Country element | `wifi_regulatory.country_present`, `.country`, `.env`, `.triplets_truncated`, `.malformed_country`; finding `COUNTRY_ABSENT` on the BSSID | |
| TPC | `wifi_regulatory.tpc_present`, `.tpc_tx_power_dbm`, `.tpc_link_margin_db`, `.power_constraint_present`, `.power_constraint_db`; finding `TPC_ABSENT_HIGH_BAND` | |
| 6 GHz regulatory info | `wifi_regulatory.he6_present`, `.he6_reg_info_name` | |
| DFS | finding `DFS_MASKING` on the BSSID; whether the channel is a DFS channel (the band plan `src/wifi_freq.c` names; slothweb carries the channel list as a constant table, held by a test to that file) | |
| Cipher / AKM / MFP posture | `beacon_aps.enc`, `.pairwise`, `.group_ciph`, `.akm`, `.akm_bits`, `.mfp`, `.downgrade_flags`; `ssid_akm_history` rows for the BSSID (transition mode vs regression, #74); findings `WPA_DOWNGRADE`, `WEAK_TLS` as applicable | |
| WPS | `beacon_aps.has_wps`, `.wps_state`, `.wps_locked`; `beacon.wps_config_methods`, `.wps_device_pwd_id` | |
| Compliance findings, all | every finding of the emitter whose type `web_scope_alert()` tags Monitor and whose technique is empty (the posture kinds, `agents/AGENTS.md`'s second exception list) | the list is the `.def`'s, not this document's |

### 4.3 EC/S: the emitter's parametrics

Wi-Fi AP (`bssid`):

| Field | Source |
|---|---|
| Bands and channels | `beacon.channel`, `.primary_channel`, `.secondary_offset`, `.operating_width` (20/40/80/160/320), `.channel_source`; `beacon_ap_ssids` (every SSID; the VAP family) |
| PHY generation | `beacon_aps.phy` (HT / VHT / HE / EHT labels as sloth writes them) |
| Beacon interval | `beacon_aps.beacon_ms`; `beacon.tbtt_jitter_us` + `_samples` (regularity) |
| Cipher suites and AKMs | `beacon_aps.pairwise`, `.group_ciph`, `.akm`, `.akm_bits` (suite type numbers, 00-0F-AC) |
| MFP | `beacon_aps.mfp` (0 none / 1 capable / 2 required) |
| TX power / TPC | `wifi_regulatory.tpc_tx_power_dbm`, `.power_constraint_db`; `est_ptx_source` says which the distance estimate used |
| Vendor IEs | `beacon.vendor_ies_hash`, `.ie_order_hash`, `.ie_order_count`, `.fp_flags` (shown as hashes: a fingerprint, not decoded) |
| WPS | as §4.2 |
| Multi-Link | `wifi_mld.mld_mac`, `link_count`, `link_<n>_mac` / `_id`, `links_truncated` |
| Steering | `btm_requests` (req_count, imminent_count, candidates count) |
| Supported rates | `assoc_reqs.supported_rates` of its clients (the AP side is not decoded by sloth: *not observed*, source `beacon` has no rates field) |

Wi-Fi client (`sta`):

| Field | Source |
|---|---|
| Randomised address | the locally administered bit; `pnl_clients.mac_random`, `assocs.sta_random` |
| PHY generation | `pnl_clients.phy` + `.phy_confirmed`; `assoc_reqs.phy` |
| OS fingerprint | `pnl_clients.os_fp` (sloth's label) |
| Requested AKM / cipher / MFP | `assoc_reqs.akm_bits`, `.pairwise_bits`, `.requested_mfp`, `.downgrade_flags`, `.prev_akm_bits`, `.prev_mfp` |
| Supported rates, listen interval, capability | `assoc_reqs.supported_rates`, `.listen_interval`; `wifi_assoc_req.capability_info` (ledger) |
| Vendor IEs | `assoc_reqs.vendor_ie_hash` |
| Link rates (the card's own) | `wifi_stas.tx_rate_kbps`, `.rx_rate_kbps` — Local scope, the managed card's station dump |
| Probe cadence | `probe_clients.frame_count`, `probe_client.burst_frames` / `burst_span_ms` / `flood`; `dev.frames` series |
| Preferred networks | `pnl_ssids` (the SSIDs; **shown as a count with the list folded**: the deanonymisation question, `sqlite-schema.md`) |
| Sequence-number trail | `seqnum_correlations` rows naming the MAC, with `confidence`, `fwd_gap`, `window_start/end` — rendered with `mac-randomisation.md`'s sentence: a hypothesis about a radio, never an identification of a person |

BLE (`ble`):

| Field | Source |
|---|---|
| Address type | `ble_device.addr_type` (public / random / resolved identity / anonymous) |
| PHY | `ble_device.primary_phy`, `.secondary_phy`, `.ext_adv`, `.adv_sid` |
| Advertising | `.last_pdu`, `.pdu_mask`, `.adv_count`, `.sampled`, `.channel`; the interval is **not** a field sloth emits — *not observed*, source `ble_device` carries counts, not an interval (Q6: ask sloth for one) |
| TX power | `.tx_power` (the AD type or the extended header; `est_ptx_source` says which) |
| Appearance, services, manufacturer | `.appearance`, `.uuid16`, `.svc_data_uuid16`, `.mfr_id` (Company ID), `.mfr_subtype`, `.hid`, `.flags` |
| Name | `.name`, `.name_complete` |
| Watch category | `.watch_category` |

The BLE rows depend on slothweb holding `ble_device` records, which it
does not today (`web_scope.c` tags them; nothing keeps them). The
Bluetooth tab is another session's slice; the ledger's BLE table (§3.3)
is frrs's own and takes the record straight from the ingest hook, so
the two do not wait on each other and neither owns the other's table.

### 4.4 TACDB: the operator's filing

Read from §3.2's tables: the unit tree, each unit's platforms, each
platform's emitters, each emitter's EC/S (§4.3, read live). The
auto-suggestions (§7) are shown beside the confirmed rows, marked.

### 4.5 Report: the seven disclosures, from a passive sensor

Shown on every emitter and every alert (for the emitter the alert
names). Each item states its limit in the UI, in these words.

| # | Item | Fields and sources | The limit, stated |
|---|---|---|---|
| 1 | **Identity** | address (canonical); randomised or fixed (the LA bit, `pnl_clients.mac_random`); vendor + registry (OUI table) and the research entry (`web/data/vendors/`, hook); names seen (`devices.hostname`, `dhcp_leases.hostname`, `mdns_services.host`, `nbns_names.name`, `passive_ptr`, `ble_device.name`, each with its source and time, as `/api/device` has them); the TACDB nomenclature and unit when filed | "an address, not a person" (`mac-randomisation.md`) |
| 2 | **Signal and radio** | RSSI last (`beacon_aps.signal_dbm` / `probe_clients.signal_dbm` / `assocs.signal_dbm` / `ble_device.rssi`), best (`wifi_merged.best_rssi`, `ble_device.rssi_best`), 60 s spread (`beacon.rssi_min_60s/max_60s`); sloth's distance estimate (`est_dist_m`, `est_dist_band`, `est_dist_trend`, `est_ptx_source`, with `rf-distance.md`'s caveat); which radio heard it (`wifi_merged.sensor_mask/best_sensor` + `sensors`, `ble_device.iface/adapter`); channel / band; the signal-vs-time series: RSSI against time from `rf.rssi.sta` / `rf.rssi.bssid` / `rf.rssi.ble` (Q7, answered 2026-11-02: kept, bounded; §14), and `dev.frames`, `dev.present` by their `/api/series` query | **"no location axis: a single passive sensor has no bearing and no position; `est_dist_*` is a distance estimate from signal strength, not a location"**. The location slice's elements are another session's (`loc-alert`, `loc-drawer`); this section places none of its own |
| 3 | **Function** | TACDB unit and platform (operator), device class (`devices.device_class`, `is_ap`, camera identity, BLE `appearance`), role (AP / client / MLD / advertiser; `karma_candidates` evidence when a candidate) | "function is the operator's filing or sloth's class; sloth does not infer organisational function" |
| 4 | **Timing** | first / last seen (the earliest and latest over every table naming the emitter, each named); the 24 h presence strip and hour-of-week cells; observed periodicities: beacon interval (`beacon_aps.beacon_ms`), BLE advertising count and sampling (`ble_device.adv_count`, `.sampled`; no interval, §4.3), probe cadence (`probe_client.burst_*`, `frame_count` deltas), the `dev.present` baseline's warm cells as "usually present at" | |
| 5 | **Technical characteristics** | §4.3's EC/S | |
| 6 | **Protection posture** | open / WEP / WPA2 / WPA3 (`beacon_aps.enc`), cipher / AKM / MFP (§4.2), transition mode (`ssid_akm_history`), cleartext protocols seen from the peer's IP (the ledger's protocol bits; `cleartext_creds` rows **as counts and protocol only**, never the username), TLS SNI seen (the ledger's last 8), QUIC / HTTP presence | **"sloth decrypts nothing (MISSION §2): 'language' here means the protocols observed on the wire, and whether they were in the clear"** |
| 7 | **Peers** | associations STA ↔ BSSID (`assocs`, `assoc_reqs`, `eapol` progress as sloth grades it); ARP / IP peers (`arp`, `devices.ip`); DNS names queried (**counts per client** from `web_ident`'s DNS join — sloth's `dns` record names the sender only, and slothweb keeps qname hashes, so the names themselves are *not observed* here; Q8); top-host flows (`top_hosts`, the flow tables by IP); BLE connection attempts (`btcap_connect_ind` is a sensor total — per-peer attempts are *not observed*, source `ble_device` has none); and for each peer that is itself an emitter sloth saw, its own signal fields (item 2) as a one-line sub-record | "peers are addresses sloth saw frames between; sloth reads no message body" |

## 5. The API

### 5.1 Reads (GET, as every route today)

All take `scope=` like the other `/api` routes (§8). Parameters are
validated whole before anything is read, with the strictness of
`web_query.h` (bounded lengths, exact enumerations, canonical
addresses), a refusal a `400` with a reason word of slothweb's own.

| Route | Parameters | Answer |
|---|---|---|
| `/api/frrs/triage?ids=` | 1..100 alert ids (`s…`/`d…` as the alert routes give them), comma-separated | `{"triage":{"<id>":{"state":"noise","ts":…,"via":"manual","note":"…","by":"…","history_n":3,"finding":"d1234"}}, "missing":[…]}`; an id with no rows is in neither map (untriaged) |
| `/api/frrs/triage/history?id=` | one alert id | the subject's rows, newest first, each as above plus `prev_state`, `basis`, `peer` |
| `/api/frrs/summary` | | `{"open":{"total":n,"untriaged":n,"false":n,"noise":n,"incident":n,"known":n,"out":n},"all":{…},"writes":true,"read_only":false,"recommendations":"compiled"|"dir"|"none"}` — the open counts are over the stream's open incidents (what the tile counts), by their current triage |
| `/api/frrs/recommend?type=` | an alert type name or number | `{"type":"…","state":"noise"|null,"basis":"…","front_matter":{…},"source":"compiled"|"dir"|"none"}` |
| `/api/frrs/report?kind=sta|bssid|ble&addr=` | a canonical address (BLE with `/type`) | the §4 record: `{"emitter":{…},"bei":{…},"scs":{…},"ecs":{…},"tacdb":{…},"report":{…},"since":…}`; every field `{"v":…,"src":"beacon_aps.beacon_ms"}` or `{"v":null,"src":"…"}`; capped at 32 KiB, lists cut with `_more` |
| `/api/frrs/report/alert?id=` | an alert id | the same, for the emitter the alert names (a MAC in its key, else the device holding `match_ip`), plus `"finding"` |
| `/api/frrs/tacdb` | `q=` (the device query grammar's free text, `vendor:`, `mac:`, `name:` terms apply to platforms), `unit=`, `sort=nomenclature|updated|unit|emitters`, `dir=`, `limit=`, `offset=` | `{"units":[tree],"platforms":[{id,nomenclature,class,vendor,unit,confirmed,origin,emitters:[{kind,addr,role,label,last_seen,scope}],updated}],"more":…}` |
| `/api/frrs/tacdb/platform?id=` | | one platform with each emitter's §4.3 and §4.5 |
| `/api/frrs/suggest` | `limit=` | the §7 suggestions not yet confirmed or dismissed |
| `/api/frrs/export` | | the §8 file, `Content-Disposition: attachment` |

### 5.2 Writes (POST only)

| Route | Body | Effect |
|---|---|---|
| `POST /api/frrs/triage` | `{"id":"d1234","state":"noise","note":"…","by":"…"}` or `{"id":"…","state":"recommended"}` | appends a row (none, `"unchanged":true`, when the state is the current one and no new note comes with it); `state` `untriaged` clears; `recommended` resolves §3.1's table and refuses `409 no_recommendation` when it yields none |
| `POST /api/frrs/tacdb/unit` | `{"op":"create","parent":null,"name":"…","kind":"site","note":"…"}` / `{"op":"update","id":1,…}` / `{"op":"delete","id":1}` / `{"op":"restore","id":1}` | |
| `POST /api/frrs/tacdb/platform` | `{"op":"create","nomenclature":"…","class":"phone","unit":1,"vendor":"…","note":"…","emitters":[{"kind":"sta","addr":"…","role":"primary","label":"…"}]}` / `update` / `delete` / `restore` / `{"op":"confirm","suggest":"<token>"}` | `confirm` takes a suggestion token from `/api/frrs/suggest` (slothweb's own, the rule and the addresses hashed with the process nonce, so a stale token is refused) |
| `POST /api/frrs/tacdb/emitter` | `{"op":"add","platform":1,"kind":"ble","addr":"…/1","role":"primary","label":"…"}` / `move` / `remove` / `restore` | a live `(kind, addr)` on another platform is `409 emitter_owned` naming it |
| `POST /api/frrs/tacdb/dismiss` | `{"suggest":"<token>"}` | |
| `POST /api/frrs/import` | the §8 file | merges; `{"mode":"merge"|"check"}` where `check` validates and reports without writing |

Every write answers `200` with the stored row (or rows) as the read
routes render it, so the page redraws from the answer and never from
what it sent.

### 5.3 The write path, in order

Every POST passes these in this order; the first that fails answers and
the body is **not parsed** past the point it was needed.

1. **Method.** `web_http.c` admits `POST` beside GET and HEAD. A POST to
   any path but §5.2's is `405` with `Allow: GET, HEAD`. A GET or HEAD
   to a §5.2 path is `405` with `Allow: POST`. Under `--web-read-only`
   every POST is `405` with `Allow: GET, HEAD` before the router, as
   today, and `web_http_response(405)`'s Allow line is read from the
   configuration rather than the literal (its comment "there will never
   be a third method" goes with the ruling it stated).
2. **Peer.** The allow list already decided at `accept()`. The peer's
   address is recorded on the row (§3.1 `peer`).
3. **Host.** `web_http_host_ok()` as every request.
4. **Origin.** The request must carry exactly one `Origin` header whose
   value is `http://` + a host:port that `web_http_host_ok()` accepts
   **and** that equals the request's Host (string equality after
   lower-casing the host part and defaulting the port to 80 on both
   sides). Missing, doubled, `null`, another scheme or another host is
   `403 bad_origin`. slothweb sets no cookie and reads none, so this is
   the whole of its CSRF defence, and it is sufficient: a browser sends
   `Origin` on every cross-site POST and will not let a page forge it.
   `Sec-Fetch-Site`, when present, must be `same-origin` or `none`
   (`403 bad_fetch_site`). `curl` users add `-H 'Origin: http://127.0.0.1:8770'`;
   the README says so.
5. **Rate.** A token bucket per peer address (`WEB_FRRS_RATE_BURST` 10,
   `WEB_FRRS_RATE_PER_MIN` 30; 64 peers tracked, least recent evicted):
   over it `429 rate_limited` with `Retry-After`. The import route
   counts as five.
6. **Content-Type.** Exactly `application/json`, an optional
   `; charset=utf-8` allowed, ASCII case-insensitive; anything else
   `415 bad_content_type`. `Content-Length` is required (`411`); a
   `Transfer-Encoding` header is `400 bad_transfer` (no chunked bodies:
   the length is the bound).
7. **Size.** `Content-Length` over `WEB_POST_MAX` (4,096 bytes; the
   import route `WEB_IMPORT_MAX` 262,144) is `413 body_too_large`
   **before** any body byte is read; the connection is then closed
   (not drained: draining 256 KiB from a hostile peer is the cost the
   bound avoids). The header block stays within `WEB_HDR_MAX`; the body
   is read into a per-connection buffer sized for `WEB_POST_MAX`, and
   the import route into one buffer of `WEB_IMPORT_MAX` held by the
   server and lent to one connection at a time (`503 import_busy`
   otherwise).
8. **Parse.** The stream decoder (`web_jsonl.c`'s reader: depth,
   fields, UTF-8, duplicate keys, overlong forms) parses the body with
   depth ≤ 3 and ≤ 64 members. Not an object, or an unknown member,
   is `400 bad_body` / `400 unknown_member` naming the member.
9. **Validate.** Every member by its type and bound (§3.1, §3.2):
   strings valid UTF-8 with no control byte, no bidirectional
   embedding or isolate control (U+202A–U+202E, U+2066–U+2069:
   invisible, they reorder what a reader sees; `400 bad_text`) and at
   most the bound in
   bytes (`400 too_long` naming the member), enumerations exact,
   addresses canonical through `web_key_mac` / `web_key_ip`, ids in the
   alert routes' own shape (`ALERT_ID_RE`), integers in range. Nothing
   is cut to fit: an over-long value is refused.
10. **Resolve.** The subject (§3.1) or the platform / unit / emitter
    rows named; `404 no_such_alert`, `404 no_such_platform`,
    `409 emitter_owned`, `409 unit_depth`, `409 duplicate_name`.
11. **Write.** The HTTP thread hands the validated row to the store
    thread through a bounded queue (`WEB_FRRS_QUEUE` 64) and waits up
    to 250 ms on a condition variable; the store thread, which owns the
    only read-write connection (`web_store.h`: "writes come only from
    the store thread"), writes it in one transaction and answers. A
    full queue or a wait that times out is `503 store_busy`; a store
    error `500 store_error` with slothweb's own sentence. No store
    (`WITH_SQLITE=0`, or `--store` refused) is `503 no_store`: triage
    needs the file.
12. **Answer.** `200` and the stored row(s) (§5.2). Every string in the
    answer goes through `web_jw_str()` like every other.

The in-memory triage map (current state per subject, loaded at open,
updated on each write, `WEB_FRRS_TRIAGE_CAP` entries) is what the read
routes and the `triage=` join (§5.4) consult, so no read route opens a
cross-file join.

### 5.4 `triage=` on `/api/alerts`

Following the `scope=` convention (`web_routes.h`): without it the
answer is byte for byte as today; with it (`any` included) every row
carries `"triage":{"state":…,"ts":…,"via":…}` (`state` `"untriaged"`
when no row) and the answer carries `"triage_counts":{…}` over the
rows the filters matched. Values: `any`, `untriaged`, `false`, `noise`,
`incident`, `known`, `triaged` (any of the four), `out` (`false`,
`noise` or `known`: what the tile shows as triaged-out). The filter is applied inside the
bounded read, like the others (`scan` counts rows that match). The same
parameter on `/api/history/alerts` and on `/api/device/{mac}` (its
`alerts` list) and `/api/alert` (the one alert) behaves the same.
`/api/live` is **not** changed: the tile's triaged-out counts come from
`/api/frrs/summary` (§6.1), so the tick and the live route stay as the
tests have them.

### 5.5 Rendering rule

Every stored string — `note`, `by`, `basis`, `name`, `nomenclature`,
`vendor`, `label` — leaves the server through `web_jw_str()` and
reaches the DOM through `textContent` only. `frrs.js` has no
`innerHTML`, no `insertAdjacentHTML` and no attribute built from a
value; `test_frrs.c` pins the served script to contain none of those
tokens (the same mechanism `test_glyph.c` uses to pin `glyph.js`).

### 5.6 Who is "by"

slothweb has no accounts. A triage row records the **peer address**
the write came from (always) and the **`by` text** the operator typed
(optional, 32 bytes, kept per browser in the prefs store as
`frrs.by` so it is typed once). The page shows both: "noise · by jeff ·
from 127.0.0.1 · 2026-10-27 14:02". Neither is an identity; the
allow list is the trust boundary, and `docs/wiki/slothweb.md` and the
README say so beside the flag. Q9 asks whether that is enough or a
shared token for writes (`--web-write-token`, sent as a header) should
come with this slice.

### 5.7 Flags

| Flag | Effect |
|---|---|
| `--web-read-only` | No POST route exists: every POST is `405` `Allow: GET, HEAD` before the router, exactly the surface before this slice; `/api/frrs/summary` and `/api/health` say `"writes":false`, the page draws no triage or TACDB button and the TACDB tab says why. The read routes (`/api/frrs/*` GET) stay. Default **off** (writes on) for an admitted peer; Q10 asks whether the default should be read-only when `--web-allow-remote` is given. |
| `--web-assessments DIR` | Where to read `<TYPE>.md` front matter for "follow recommended" until the compiled table exists (§3.1). Default unset; `slothweb.service` passes `/usr/local/share/sloth/alert-assessments`, where `make install` puts `docs/wiki/alert-assessments/*.md` (not its generated `README.md`). A DIR that is not there means "no recommendation yet", as unset; something there that is not a directory is refused (exit 2). |
| `--web-frrs-cap N` | `WEB_FRRS_TRIAGE_CAP` override, 1,000..100,000. Optional; may be dropped if the owner prefers one knob fewer (Q11). |

`--strict` does not imply `--web-read-only`: strict is about where the
bind and the peers are; read-only is about what an admitted peer may
do. The README's Security section says both in one sentence.

### 5.8 `/api/health`

An additive `"frrs"` member, last: `{"writes":true,"triage_rows":n,
"triage_subjects":n,"triage_pending":n,"triage_folded":n,"tacdb":{"units":n,
"platforms":n,"emitters":n,"dismissed":n},"ledger":{"bssid":n,"sta":n,
"ble":n,"ip":n,"evictions":n},"rate_limited":n,"refused":{"origin":n,
"content_type":n,"size":n,"body":n},"recommendations":"none"}`.

## 6. The UI

### 6.1 Where each thing appears

| Place | Triage | FRRS |
|---|---|---|
| Overview, latest alerts (`#alerts` list, `alerts()`) | a state chip at the row's end and the four buttons on hover/focus; a triaged-out row is dimmed, never removed | — |
| Overview, open-alerts tile (`t-alerts`) | a second line, `k-alerts-triaged` (new element): "3 noise · 1 false triaged out" from `/api/frrs/summary`; the big number stays the open count as today, so nothing is silently dropped; clicking the second line opens `#alerts?state=open&triage=out` | — |
| Alerts page (`v-alerts`) | a `triage` select (`al-triage`, kept as `ctl.al-triage`; `#alerts?triage=noise` in the address wins, as every filter does), a `triage` column in the dt table (sortable), the buttons per row; the search box accepts `triage:noise` as a term and `frrs.js` moves it into the select | — |
| History, alerts in the range (`h-alerts`) | chip and buttons per row | — |
| The device drawer, "alerts naming it" (`itemList` rows) | chip and buttons per row | `frrs-drawer` (new container after the drawer's sections, before the location slice's `loc-drawer`): the §4 record, folded by group, BEI and Report open by default |
| The alert page (`v-alert`) | a triage panel (`frrs-alert-triage`, new section after `ad-title`): current state, the four buttons, the note and by fields, and the history (a dt table `frrs-triage-hist`) | `frrs-alert` (new container after the page's own sections, before the evidence slice's `ev-alert`): the record for the emitter the alert names |
| The TACDB tab (`v-tacdb`; `nav-tacdb` after Lookup, its label digit the next free one when it merges — the Bluetooth tab is adding a button in parallel, and the digits are labels, not key bindings) | — | §6.3 |

The "follow recommended" button carries the recommendation in its
label ("follow recommended: noise") when there is one, is disabled
with "no recommendation yet" when there is none, and on click writes
`state: recommended`. The state chip's colours are the severity
tokens the page has (`sev0` for noise, `sev1` for false, `sev2` for
incident); `known` is green (`tri-known`, the theme's `--tri-known`,
which is the TUI's bright phosphor `--tui-bright`, lightened for the
cream theme to 4.5:1 by palette.c), the affiliation colour of a
friendly or neutral emitter. Its button's title says what it means.

Triaged-out rows (`false`, `noise`, `known`) are **dimmed, not hidden**, in
every list unless the viewer filters them out; the count line always
says how many are dimmed ("12 rows, 4 triaged out").

### 6.2 The module and its hooks

Everything is in `web/ui/frrs.js`, one IIFE on `window.SlothFrrs`,
embedded by the same build step as `glyph.js` and hashed into the CSP.
It touches `app.js` only through named hook points, each one call,
each guarded (`if (window.SlothFrrs) SlothFrrs.x(...)`) so the page
works with the module absent, and each named in the commit message so
the three parallel slices can merge:

| Hook point (in `app.js`) | Call | Why there |
|---|---|---|
| `alerts(list)`, after the loop | `SlothFrrs.decorateAlertRows($("alerts"), list)` | the Overview's latest alerts |
| `alertsDraw()`, after the rows are placed | `SlothFrrs.decorateAlertRows($("al-rows"), AL.rows)` | the Alerts page |
| `alertsQuery(off)`, on the path | `SlothFrrs.q(path)` (adds `triage=` from the select, as `scoped()` adds `scope=`) | the filter |
| `histAlerts()`, after the loop | `SlothFrrs.decorateAlertRows($("h-alerts"), HS.alerts)` | History |
| `openDrawer(mac)`, after the anomalies | `SlothFrrs.mountDrawer(mac, j)` | the record and the drawer's alert rows |
| `alertPage(j)`, at the end | `SlothFrrs.mountAlert(j)` | the triage panel and the record |
| `overview()`, after the tiles | `SlothFrrs.tile()` | the triaged-out line |
| `show(v, p)`, the view dispatch | `if (v === "tacdb") SlothFrrs.tacdb(p)` | the tab |
| `main()`, once | `SlothFrrs.init({ getJSON, DataTable, el, ipSpan, ssidSpan, macVal, stamp, shortStamp, prefGet, prefSet, keyColor, SCOPE: function () { return SCOPE; }, go, openAlert, openDrawer })` | the module borrows the page's helpers rather than copying them |

`index.html` gains: the `nav-tacdb` button (after Lookup), the
`v-tacdb` view, the `frrs-alert-triage`, `frrs-alert` and `frrs-drawer`
containers, the `k-alerts-triaged` line in the tile, the `al-triage`
select, and `<script>` for `frrs.js`. Every id is new; no existing id
or attribute is edited. `VIEWS`, `NAV`, `PARAMS` and `DB_VIEWS` each
gain `"tacdb"` (one entry each; `PARAMS.alerts` gains `"triage"`).

Hook points **for the other slices**, exposed by this module:
`SlothFrrs.mountBundle(container, kind, id)` on the TACDB platform view
(`bundle-btn-tacdb`, one per platform header) calls
`SlothBundle.mount(container, "platform", id)` when `window.SlothBundle`
exists; the drawer and alert containers are placed so `ev-alert`,
`ev-drawer`, `loc-alert` and `loc-drawer` keep their stated positions
(`frrs-alert` before `ev-alert`; `frrs-drawer` after the drawer's own
sections and before `loc-drawer`).

### 6.3 The TACDB tab

Three panels, all dt tables (sortable, resizable, their settings kept
as `table.tacdb-units`, `table.tacdb-platforms`, `table.tacdb-emitters`):

1. **Units** — the tree as an indented table (name, kind, platforms,
   emitters, last seen); a row selects the unit and filters the
   platforms; buttons: new unit, rename, move, delete / restore.
2. **Platforms, by nomenclature** — nomenclature, class, vendor, unit,
   equipment (the emitter count with kind glyphs), last seen (the max
   over its emitters), confirmed / suggested; a row opens the platform
   view; the search box takes the device grammar's terms; buttons: new
   platform, file under unit, delete / restore, export, import.
3. **Suggestions** — §7's, each with its rule, its evidence sentence
   and *confirm* / *dismiss*.

The **platform view** (a drawer-like panel in the tab, `frrs-platform`)
lists the equipment complement; each emitter row opens its EC/S (§4.3)
and its Report (§4.5) inline, with a link to the device drawer; the
header carries `bundle-btn-tacdb` (the evidence bundle slice's hook).

The tab's note line says, always: "operator data: not captured, not
scoped; the evidence under each emitter is". And, under the Report of
every emitter: "no location axis · sloth decrypts nothing".

### 6.4 Kept settings (`web/README.md` "Kept settings")

`ctl.al-triage`; `frrs.by`; `table.tacdb-*` (through `DataTable()`);
`frrs.tacdb.unit` (the selected unit); `frrs.open` (which record groups
are unfolded, a bit per group). `test_prefs.c`'s rule (every control
kept or listed) is satisfied by listing each.

## 7. Auto-suggestion rules

Computed on request from `sloth.db` and the ledger; stored only when
confirmed (as platform + emitter rows with `origin` 10 + rule) or
dismissed (`tacdb_dismiss`). Each suggestion names its rule, the two
addresses, a confidence word (sloth's own where it has one) and the
evidence sentence, and never says "is the same device": it says "may
be one platform".

| Rule | Reads | Suggests | Evidence sentence |
|---|---|---|---|
| S1 sequence-number trail | `seqnum_correlations` with `confidence` ≥ 60 and `fwd_gap` ≤ 64 (`mac-randomisation.md`'s limits) | `mac_a` and `mac_b` as one platform, the later-seen as `rotation` | "sequence counter continued across the change (confidence N of 90, a ranking not a probability)" |
| S2 MLD affiliation | `wifi_mld` (ledger) | `mld_mac` as the platform's primary, each `link_<n>_mac` as `mld-link` | "advertised as links of one Multi-Link Device" |
| S3 BSSID family | `beacon_aps` rows whose BSSIDs differ only in the low nibble of the last octet **and** share `vendor` and `channel` or `beacon_ms`, or `beacon_ap_ssids` with several SSIDs on one BSSID | the BSSIDs as one platform of class `ap`, role `vap` | "same OUI block, adjacent addresses, same channel: one AP's virtual BSSIDs" (also what `karma_candidates` reads, so a KARMA candidate is **not** suggested: its evidence is shown instead) |
| S4 BLE rotation hint | `ble_device` rows the stream marks as linked (`--ble-rotation-hints`, `sensor_health.ble_rot_hints` > 0; the link is in sloth's `[*]` estimate, not a field — so this rule waits on a field and is **off** until one exists; Q6) | | |
| S5 Wi-Fi + IP | `devices.mac` with `ip`, `arp` — not a platform suggestion (one MAC) but fills the platform's identity | | |
| S6 station + card | `wifi_stas.mac` equal to a `probe_clients.mac` / `assocs.sta_mac` | one emitter seen in both scopes: the platform is shown in both | "the host's own card and the air heard the same address" |

Suggestions are listed in confidence order, at most 200, and a pair
dismissed stays dismissed until either address is next seen with new
evidence (a later `last_seen` than the dismissal's `ts`).

## 8. Import / export

One JSON document, `slothweb-tacdb-1`:

```json
{"format":"slothweb-tacdb","version":1,"exported":1792627199,
 "sensor":"slothweb on <host>, store <path>",
 "units":[{"id":1,"parent":null,"name":"home","kind":"site","note":"","deleted":false}],
 "platforms":[{"id":7,"unit":1,"nomenclature":"Apple phone 3f:9a","class":"phone",
   "vendor":"Apple, Inc.","note":"","confirmed":true,"origin":"operator",
   "emitters":[{"kind":"sta","addr":"aa:bb:cc:dd:3f:9a","role":"primary","label":""},
               {"kind":"ble","addr":"c4:…:01/1","role":"primary","label":""}]}],
 "triage":[{"descriptor":{"type":"SMB1_SESSION","addr":"192.0.2.10","port":445,"first_seen":1792000000},
   "history":[{"state":"noise","prev_state":"untriaged","via":"manual","note":"the NAS","by":"jeff",
               "peer":"127.0.0.1","ts":1792627000}]}]}
```

Export carries everything, deleted rows included (`deleted:true`), so
another sensor restores the same state. Import validates the whole file
to §3's bounds first (`"mode":"check"` stops there and reports), then
merges: units and platforms match by name / nomenclature under the
same parent (ids are not carried across), emitters by `(kind, addr)`
(an emitter already on another platform here is reported, not moved),
triage by descriptor (a finding this `sloth.db` has by descriptor gets
the history appended with `via` import, in order, newest `ts` winning
the current state; one it lacks is kept pending by descriptor and
attached when a matching finding appears). Nothing is deleted by an
import. The report names every row merged, skipped and why. §14 says
where the build departs: live rows only, the header and `end` checks,
the parent-first merge, and the rule that a name alone is not a device.

## 9. What it never does

- Writes `sloth.db`, or anything but `slothweb.db`.
- Sends a frame, a query or a packet: the record is built from what
  sloth already recorded; the FCC data is a file the operator put in
  `web/data/vendors/`.
- Feeds triage back to the sensor as suppression: sloth's rules are
  not changed by a web click (Q13 asks whether an export the operator
  carries to sloth's `--suppress` is wanted later).
- Claims a location: no bearing, no position, no plot (§4.5 item 2).
- Decrypts, or claims to: §4.5 item 6's sentence is in the UI.
- Stores a stream string: the ledger is memory; the tables hold
  addresses, numbers, slothweb's own words and operator text.
- Identifies a person: the correlation rules suggest platforms and say
  so in `mac-randomisation.md`'s words.

## 10. Tests

`web/tests/test_frrs.c`, `test_store.c` (v5 → v6), `test_http.c` (POST
admitted, methods table), `test_routes.c`, `test_alerts.c` (`triage=`),
`test_prefs.c` (the new controls), `test_tables.c` (the new dt tables),
`test_readme.c` (the README's new flags and routes). Hand-built request
bytes and hand-built rows, as the suite does everywhere.

**Every absence assertion is seen red under a named mutation and the
source restored byte-identical**, per `agents/AGENTS.md`; the mutation
is named in the test's comment:

| Assertion | Mutation that makes it red |
|---|---|
| a cross-origin POST is refused (`Origin: http://evil.example`, Host `127.0.0.1:8770`) | the Origin/Host equality replaced by `1` |
| a POST with no `Origin` is refused | the "missing" branch removed |
| an oversize body is refused before it is read (`Content-Length: 4097`, 0 body bytes sent; the test asserts the connection is closed with 413 and no further `recv`) | `WEB_POST_MAX` compared with `>=` 1 MiB |
| a GET to a write path writes nothing (`GET /api/frrs/triage?id=…&state=noise` → 405, the store unchanged) | the method check on the write paths removed |
| `--web-read-only` makes every POST 405 with `Allow: GET, HEAD` | the flag's branch removed |
| a `Content-Type: text/plain` body is refused | the check removed |
| an unknown member is refused | the member allow-list replaced by accept-all |
| a note of 241 bytes is refused and 240 accepted | the bound off by one |
| a note is stored as typed and rendered as text (a `<b>` in it reaches the DOM as five characters) | `web_jw_str` replaced by `web_jw_raw` on `note` |
| no stream string reaches the triage or tacdb tables (a run with an SSID of `' OR 1=1--` and a hostname carrying markup: neither byte sequence in the file) | the ledger's SSID copied into `basis` |
| the credential guardrail (a `CLEARTEXT_CRED` key with a username: the username in no slothweb.db byte and no response body) | the key text stored as `subject` |
| the rate limit refuses the 11th write in a second and admits one after 2 s | the bucket's refill made infinite |
| the v5 failed step leaves the file unchanged | ROLLBACK replaced by COMMIT |
| `finding` is set once | the `AND finding IS NULL` removed |
| a triaged-out row is dimmed, never dropped: `/api/alerts?state=open` row count equals the count without `triage=` | the filter applied when `triage=any` |
| the open-alerts tile's number is the open count and the triaged-out line sums to at most it | — (a value assertion) |
| the served `frrs.js` contains no `innerHTML`, `insertAdjacentHTML`, `document.write` or `on[a-z]+=` | a token added to the script |
| `/api/frrs/report` says `"no location axis"` and `"sloth decrypts nothing"` in its fixed members, and no member named `lat`, `lon`, `location`, `bearing`, `plaintext` or `decrypted` exists | the string removed; a `lat` member added |
| every §4 field in the answer names a `src` that is a table.column of `sloth.db`'s DDL, a JSONL record field in `src/jsonl.c`, a slothweb series, or a hook name — the test reads both files | a `src` misspelt |

**Screenshots.** Headless Chromium against `slothweb-demo` (dark and
light, 1280 and 360 px) of: the Alerts page with the triage column and
a filtered state, an alert's page with the triage panel and the record,
the drawer with `frrs-drawer`, the TACDB tab with a suggestion and a
confirmed platform; to the scratchpad `frrs-shots/`, never committed.
The demo gains a `wifi_regulatory`, a `wifi_mld` and a `ble_device`
record and a seqnum pair so the record has something to show.

## 11. Documentation shipped in the same change

- this file;
- `docs/wiki/slothweb.md`: a "Triage and the FRRS record" section (the
  model in brief, the write surface and its rules, the flags, a pointer
  here), the milestones list, Last updated folded;
- `docs/wiki/cli-reference.md`: `--web-read-only`, `--web-assessments`,
  (`--web-frrs-cap`);
- `web/README.md`: the Command line table (the flags), Routes (every
  §5 route with request and response shapes, the write path's order and
  each refusal's status and word, the `curl` example with `Origin`),
  Security ("GET and HEAD only" becomes "GET, HEAD and, unless
  `--web-read-only`, POST to the triage and TACDB routes, which write
  slothweb.db only; the Origin rule; the allow list is still the only
  gate"), Kept settings (§6.4), Tests;
- `docs/wiki/log.md`: one entry;
- `docs/wiki/index.md`: a line for this spec under slothweb.

## 12. Open questions for the owner

- **Q1 Subject key.** `d<rowid>` (the finding's first row) with a
  descriptor fallback (§3.1), or the descriptor `(type, addr, port,
  first_seen)` as the primary key, which survives a `sloth.db` rebuild
  and `--db-compact-alerts` but collides when one type fires twice on
  one address in one second?
- **Q2 Per-subject history cap.** Fold the oldest beyond 64 rows per
  finding (counted), or refuse the 65th change?
- **Q3 Assessment vocabulary.** Answered in part by the batch itself
  (§3.1 lists what the 72 files write), and the mapping now reads that
  vocabulary: `noise` only where `false_positive_risk` is `high` and
  `noise_verdict` `noisy` / `very noisy`, nothing else recommends. Still open: should `false_positive_risk:
  high` ever recommend `false` (it is a verdict on the rule; 13 types
  carry it, ARP_SPOOF among them), and should anything ever recommend
  `incident` (`severity_assessment` judges the level, not the alert)?
  And is a mixed verdict ("noisy in count, quiet in findings") noise?
- **Q4 Unit depth.** Four levels (site → area → room/vehicle →
  person) as proposed, or unbounded?
- **Q5 Nomenclature.** Auto-name `"<vendor> <class> <last two
  octets>"` ("Apple phone 3f:9a")? Or SFAF-style upper-case tokens
  ("APPLE-PHONE-3F9A")? Unique per store is assumed.
- **Q6 BLE fields sloth does not emit.** The advertising interval and
  the rotation link are shown as *not observed* because `ble_device`
  carries neither; should a sloth-side slice add them (`adv_interval_ms`
  as sloth's median inter-report gap; `rot_link` as the linked address
  when hints are on)?
- **Q7 RSSI over time.** *Answered by the owner, 2026-11-02: "Keep,
  bounded" — slothweb stores RSSI per emitter at 1-minute resolution
  for 30 days, capped by its existing key limits, so the report can
  plot it.* Built as `rf.rssi.sta`, `rf.rssi.bssid`, `rf.rssi.ble`
  (§14). The question as first asked: the Report's "signal-vs-time
  series" was `dev.frames` / `dev.present`; a `dev.rssi` series (per
  MAC and per BSSID, the median per bucket) would make it a signal
  series, at the cost of keys under `--web-max-keys`.
- **Q8 DNS names queried.** slothweb keeps qname **hashes** per
  client (`web_ident`), deliberately; the Report therefore shows
  counts, not names. Keep that, or keep the last N names per client in
  the ledger (memory only)?
- **Q9 "by" without authentication.** Peer address + typed name
  (§5.6), or add `--web-write-token` (a shared header) with this slice?
- **Q10 Read-only default.** Writes on by default for every admitted
  peer, as specified; or read-only by default whenever
  `--web-allow-remote` is given, so a LAN exposure is read-only unless
  the operator says otherwise?
- **Q11 `--web-frrs-cap`.** Keep the knob or fix the cap at 20,000?
- **Q12 SFAF names.** §1's third column borrows SFAF / NTIA Chapter 9
  field names from memory, with no item numbers; neither text was
  reachable this session. Someone with MCEB Pub 7 or the NTIA Manual
  should check them, and say whether item numbers in the UI are wanted
  at all (they would read as decoration to anyone outside that world).
- **Q13 Suppression feedback.** Triage never changes the sensor
  (§9). Is an export the operator can carry to sloth (a suppress list
  by type and address) wanted as a later slice?
- **Q14 Type-level triage.** A finding is triaged one at a time. Is
  "apply to every open alert of this type" (one row per finding, one
  click) wanted?
- **Q15 Imported triage.** An import may bring at most 1,000 triage
  rows in one file, fill at most half the table (10,000 rows) with
  imported rows, and hold at most 8 imported rows of one alert, so no
  file can leave the operator unable to triage. Is half right, and is a
  full sensor's export (up to 20,000 rows) worth carrying whole?
- **Q16 Deleted TACDB rows.** A delete keeps its row (reversible), and
  deleted rows count toward a bound twice each cap. There is no purge:
  at that bound a create is refused until something is restored. Is a
  purge of deleted rows (irreversible, and said so) wanted?

### 12.1 The defaults taken until the owner answers

Each the conservative choice: the one that loses no operator state,
claims nothing sloth did not record, and widens no surface.

| Q | Default built |
|---|---|
| Q1 | `d<rowid>` of the finding's first row, the descriptor kept on every row and used to re-attach an import; a stream incident sloth has not written is filed under its handle and gets its finding once, from NULL. |
| Q2 | **Fold** (review of 2026-11-02): an operator's change is never refused for room. Past 64 rows an alert keeps its first row and its newest, the folded counted on the first; at 20,000 rows the oldest superseded rows fold, imported first (§3.1). The refusal first built left an alert with a long history, or a full store, unable to be triaged at all — clearing included. |
| Q3 | `noise` only for `false_positive_risk` `high` **and** `noise_verdict` `noisy` / `very noisy` (eight types); anything else assessed is "no automatic triage", the front matter shown as advice; nothing recommends `false` or `incident` (§3.1). `noise_verdict` alone, first built, recommended `noise` for FRAG_PLAINTEXT and SMB1_USE, whose `false_positive_risk` is `low`: the verdict is about the count, not the alert. |
| Q4 | Four levels; a fifth is `409 unit_depth`. |
| Q5 | `"<vendor> <class> <last two octets>"`, the vendor the OUI table's first word, or `randomised` for a locally administered address; unique among live platforms. |
| Q6 | *not observed*, the reason named in the field (`ble_device` carries no interval and no rotation link). |
| Q7 | Answered 2026-11-02 ("Keep, bounded"), no longer a default: `series_rssi` carries the series (§14). Until then the field said "not a series slothweb keeps". |
| Q8 | Counts, not names. |
| Q9 | No token: peer address plus the typed name. |
| Q10 | Writes on for every admitted peer; `--web-read-only` to remove them. |
| Q11 | The knob dropped: 20,000 rows, fixed. |
| Q12 | Unchanged: field names borrowed, no item numbers. |
| Q13, Q14 | Not built. |
| Q15 | 1,000 per file (more is `413`, nothing merged), 10,000 imported in all, 8 imported per alert (the oldest folded). |
| Q16 | No purge; refused at twice the cap. |

## 13. Slices

| # | Content | Gate |
|---|---|---|
| F0 | this spec | commit |
| F1 | store v6 + migration tests; the triage table, map and queue; `web_http.c` POST with the §5.3 path through step 9; `--web-read-only`; `POST /api/frrs/triage`, `/api/frrs/triage`, `/history`, `/summary`; `triage=` on the alert routes; `frrs.js` triage chips, buttons, select, tile line, alert-page panel; README, wiki, log | the whole build surface (`agents/AGENTS.md`), screenshots |
| F2 | `/api/frrs/recommend` with the directory reader and `--web-assessments`; "follow recommended" live | same |
| F3 | the ledger; `/api/frrs/report` and `/report/alert`; `frrs-alert` and `frrs-drawer`; the allow-list columns | same |
| F4 | TACDB tables, routes, tab, platform view, `mountBundle` hook; suggestions S1–S3, S6; export / import | same |
| F5 | the vendor KB hook (§4.2), wired 2026-11-02 with `web/data/vendors/`; the compiled assessment table once `web_alertasm.h` exists | same |

## 14. As built (2026-11-01, review fixes 2026-11-02 twice), where it departs from the body

| § | The body says | Built | Why |
|---|---|---|---|
| 3.1 | column `by` | column `who`, `by` in every JSON body | `BY` is an SQL keyword. |
| 3.1 | fold beyond 64 per subject | folded as the body says (the first row kept and counting the fold), 8 imported per alert, and the table's cap folding superseded rows too (§3.1, Q2) | Built first as a refusal (`507 history_full`, `507 triage_full` for ever); the review of 2026-11-02 found an alert with 64 imported rows could no longer be triaged by its operator, and a full store never again. |
| 3.1, 5.3 step 11 | the store thread writes, through a queue | the HTTP thread writes over its own read-write connection to slothweb.db (`web_store_open_aux()`), one short `BEGIN IMMEDIATE` per request, WAL and a 250 ms busy timeout between it and the store thread | One HTTP thread, writes rare and small: a queue and a condition variable bought nothing a busy timeout does not, and added a thread hand-off to every click. `web_store.h` names it as the one exception to "the store thread writes". |
| 3.1, 5.3 | an in-memory map of current states | none: every read is an indexed query on the store | 20,000 rows at most; the indexes (`triage_subject`, `triage_finding`, `triage_desc`) answer in microseconds and there is no second copy to keep in step. |
| 3.3 | ledger sizes 1,024 / 2,048 / 1,024 / 512 | 512 BSSIDs, 1,024 stations, 512 BLE rows, 256 addresses, 64 channels | The structs carry more than the body costed; the bound is what matters and evictions are counted. |
| 5.1 | `/api/frrs/triage?ids=` (1..100), `/api/frrs/triage/history`, `/api/frrs/tacdb/platform` | `/api/frrs/states?ids=` (1..16), `/api/frrs/history`, `/api/frrs/tacdb/view` | A GET to a write path is `405 Allow: POST`; a read path must not share a write path's name. Sixteen ids fit the query bound (512 bytes) at the longest id. |
| 5.2 | the platform body carries an `emitters` array; the import's mode is a member | one emitter per create (`emitter_kind`, `emitter_addr`, `emitter_role`, `emitter_label`), more by `tacdb/emitter`; `?mode=check\|merge` on the import's path, `check` the default | The body is parsed by the stream's flat decoder (one object, no nesting): the decoder's limits are the body's limits. |
| 5.3 step 7 | import bound 262,144 bytes | 8 MiB | An export carries the triage history: 20,000 rows at their bounds do not fit 256 KiB. The import buffer is made for the length promised, one import at a time (`503` for a second). |
| 5.4 | `triage=` on `/api/alerts`, `/api/history/alerts`, `/api/device`, `/api/alert` | on `/api/alerts`; History, the drawer and an alert's page ask `/api/frrs/states` for the ids they drew | Those three answers are unchanged byte for byte; the page needs the states only where it draws them. |
| 5.7 | `--web-frrs-cap` | dropped | Q11. |
| 6.2 | hooks in `alerts()`, `alertsDraw()`, `histAlerts()`, `overview()` | one hook in `alertLink()` covers every linked alert row (the Overview, History, the drawer, an alert's page); `alertRow()` gets the Alerts page's cell; the tile line is refreshed by the module's own 10 s timer | Fewer hooks in fewer functions, and a list redrawn by its own sort keeps its chips. The seven hook points: `alertLink` → `SlothFrrs.link(li, id)`, `alertRow` → `SlothFrrs.cell(a, row)`, `alertsQuery` → `SlothFrrs.q(p)`, `show` → `SlothFrrs.show(v, VP)`, `openDrawer` → `SlothFrrs.mountDrawer(mac, j)`, `alertPage` → `SlothFrrs.mountAlert(j)`, `main` → `SlothFrrs.init({...})`. |
| 7 S1 | `seqnum_correlations` with `confidence` ≥ 60 and `fwd_gap` ≤ 64; the later-seen as `rotation` | as written, and only that: a `sloth.db` row the stream has given no confidence for is **not** suggested; the primary and the rotation are taken from the stream's `a_is_earlier` | `sloth.db` keeps the absolute `gap`, which has no direction (`sloth.h` on `seqnum_correlation_t`): a counter that went backwards is not one radio. A fallback on it, first built, was the "small gap = same device" rule #94 retired. |
| 7 S2 | `mld_mac` primary, each link `mld-link` | one kind for the whole MLD: a BSSID when the MLD address or any link has beaconed, else a station, for every pair and at confirm | Decided per link, an AP MLD whose links had not all beaconed was filed as a BSSID by one confirm and a station by the next: two platforms for one device. |
| 7 S3 | BSSIDs differing only in the low nibble of the last octet, sharing `vendor`, and `channel` or `beacon_ms` | as written but **and** channel: the first five octets and the last's high nibble equal (16 characters), `vendor` equal (NULL matching NULL: sloth names the vendor from the OUI, which those characters share), the same channel; the interval raises the confidence | 100 TU is nearly every AP's interval: on the demo's eight BSSIDs the body's rule made 28 pairs. The first build compared five octets only (a /40 of 256 addresses). |
| 8 | one JSON document | JSON Lines (`slothweb-tacdb.jsonl`): a header line, one line per unit, platform, emitter, dismissal and triage row, an `end` line | The flat decoder again; and a file cut short is told by its missing `end`. |
| 8 | export carries deleted rows; units and platforms match by name | the export carries **live** rows only, units parents first; the import refuses a file whose first line is not the header, whose `end` is missing, is not last, counts other than the file's lines, or says `complete:false`; units merge once their parent has, whatever the file's order; a platform whose unit did not merge is skipped (`unit_not_merged`), never re-filed under no unit; a platform whose nomenclature a live platform here has is that platform only when one of its emitters is already filed on it, else skipped (`duplicate_name`); triage lines meet each alert's 64 and 8 imported, at most 1,000 per file (`413 too_many_triage` beyond, nothing merged) and 10,000 imported in all (Q15); a triage line no newer than its alert's newest row here is skipped (`already_here` when identical, else `older_than_here`), so a file never puts an older decision over a later one and the same file twice merges nothing; `?mode=check` runs the merge in its transaction and rolls it back, so it reports every skip a merge would (a unit cycle's `parent_not_merged` among them) and what would merge | Deleted rows made the file grow with every create-then-delete and were then dropped by the import anyway. A name is not a device: auto names are numbered in each sensor's own order and "laptop" is anyone's. A headerless file first built began the merge and never ended it, leaving the write connection's transaction open until restart. |
| 3.2 | bounds on live rows | and twice each counting deleted rows (Q16) | A soft delete keeps its row. |
| 3.2 | restore | a unit's restore checks the depth again; a platform's restore needs its unit live (`409 unit_deleted`) | A move counts live subunits only, so a deleted child could come back at depth 5; a platform could come back into a deleted unit the tree no longer shows. |
| 4.5 item 2 | the signal-vs-time series `dev.frames`, `dev.present` | `series_presence`, `series_frames`: no value, the field's `why` names the `/api/series` query. `series_rssi` (Q7, owner ruling 2026-11-02): the last 24 h of the emitter's `rf.rssi.*` series from the fine tier (store and ring merged, as `/api/series` merges them) in 48 cells of 30 min, each the mean of its samples, with `min_dbm`, `max_dbm`, `last_dbm`, `last_t`, `samples` and `history`, the `/api/series` query of the minute tier; `v` null and "no samples" when there is none. The alert page and the drawer draw it as a text sparkline (the TUI's glyphs and heat ramp, `glyph.level`) with min and max | A series' name shown as a value read as observed data, so presence and frames stay references; the RSSI series is embedded because the operator asked to see the signal plotted in the Report. Half-hour cells keep the answer small (48 values) whatever the emitter's rate. |
| 12 Q7 | a `dev.rssi` series per MAC and per BSSID, the median per bucket, 1-minute resolution for 30 days | three gauges, `rf.rssi.sta` (`probe_client.signal_dbm` by `mac`), `rf.rssi.bssid` (`beacon.signal_dbm` and `assoc.signal_dbm` by `bssid`; an assoc row's signal is the AP's frames) and `rf.rssi.ble` (`ble_device.rssi` by `addr`, `has_rssi` 1), each sampled from a record whose `last_seen` is within 10 s of its `ts`; the existing tiers unchanged, so the minute tier keeps `--web-retain-days` (30 by default), the fine tier 24 h and the hour tier 400 days; the device class's keys, bounded by `--web-max-keys` with its eviction and counted on `/api/health` as every device key is; Monitor's scope; the bucket's mean with its min and max, not the median; not scored by the anomaly engine's A1 | One metric per kind, keyed by the MAC, shares the key slot `dev.present` already holds for the address, where a kind-prefixed key would cost a second slot of the same 512 for every emitter. The rollup keeps sum, count, min and max per bucket, not samples, so a median would need a per-bucket sample store for every series; the mean with its spread is what the tiers already hold. A record re-sent with an old `last_seen` carries an old signal, so sampling it every pass would draw a flat line for an emitter that left. A walk past the sensor is not an anomaly, and no rule was asked for. The value is a receiver's own report (radiotap, HCI), not a calibrated measurement, and the Report says so. |
| 5.7 | the page draws no button under `--web-read-only` | and a page loaded before the restart maps the plain `405` to "read-only" | `--web-read-only` takes the routes away before the router, so its 405 is not JSON. |
| 6.1 | the buttons on hover/focus in each row | a linked alert row holding the buttons is `role="group"` (Enter or a click still opens it), not `link`; at phone width the Alerts page's button line is held to the screen and repeats the state the scrolled-off column holds | Buttons inside a link are not exposed by a screen reader; the cell's overflow rule clipped the line at 360 px. |
| 8 | the import inside the request | one transaction, every statement prepared once, the table's counts read once and kept in step (the first build counted the whole table twice per triage line: 5,000 lines held the HTTP thread about 21 s); measured by `test_import_time_over_socket`, 1,000 lines into a store of 15,000 rows, in the gate run quoted in the 2026-11-02 commit | The HTTP thread is single; the per-file bound and the per-line cost are what bound how long a `/api/health` waits behind an import. |
| 5.3 step 7 | the body read within the timeout | the timeout from the headers, plus the promised length at 16 KiB/s (`WEB_BODY_MIN_BPS`) | An 8 MiB import over a slow link needs minutes; a fixed 10 s cut it off, and a drip below the floor is still cut at its bound. |
| 6.1 | "follow recommended" | "no automatic triage: <risk>" when an assessment does not meet §3.1's bar; at 480 px and under the button's label is the short one ("no rec. yet", "no auto: low"), and the Alerts page's button line is held inside the table's scroll box (`100vw - 72px`), so at 393 px no button is cut off (re-screenshot 2026-11-02: the line wraps, "no auto: medium" whole) | The long label ran off a phone's screen, and the line, held to `100vw - 48px`, ran under the scroll box's clip. |
| 10 | absence assertions and their mutations | as listed in `web/tests/test_frrs.c` and `test_store.c`, each seen red in a copy of the tree with the source compared by hash afterwards | |

## 15. Anomaly triage and links (2026-11-11)

The owner's words: "add ability to add triage notes like we have on
alerts for anomalies. allow them to be related where possible".

### 15.1 One mechanism, a second kind of subject

An anomaly (`web_anomaly.h`: slothweb's own finding, rules A1 to A10)
is triaged by §3.1's rows and §5's routes, generalised rather than
copied: `POST /api/frrs/triage`, `/api/frrs/states` and
`/api/frrs/history` take an anomaly's id where they took an alert's,
and `web_frrs.c`'s lookup, write, folding, cap and history code runs
unchanged on it. A separate table and route for anomalies was the
alternative; it would have been a second write path to keep as narrow
as the first, a second cap, and two histories that drift. Nothing in
the `triage` table had to change (slothweb.db's steps are `CREATE`
only, and none was needed).

| | Alert | Anomaly |
|---|---|---|
| id on the wire | `d<rowid>` / `s<handle>` | `a` + 16 hex digits (`tid` in the episode's JSON) |
| `subject` | `d<first rowid>` (or the handle) | the id |
| `finding` | the rowid once resolved | NULL |
| `type` | the alert type, 0 or more | -1 |
| `addr` | the finding's address | the id again |
| `port` | the finding's | 0 |
| `first_seen` | the finding's first row's | the `first_seen` of the episode the row was written on (0: none held) |

`type` -1 keeps the two apart: §3.1's descriptor match wants a type of
0 or more, so an alert's read never returns an anomaly's row or the
reverse, and the id in `addr` keeps two anomalies whose episodes began
in the same second (the minute pass stamps every candidate alike) from
reading as one descriptor to the retention's "superseded" test.

**What the id names.** The **finding**: every episode of one (rule,
metric, key), by FNV-1a 64 of the rule's name, the metric's name and
the key. §3.1 attaches an alert's triage to its finding, which is every
incident of its key, reopens included (`web_alertdb.h`); this mirrors
that deliberately, so a device marked `known` stays known the next time
the same rule fires on it. The episode's own `id` is not usable (it
restarts at 1 once every saved episode has aged out), and (kind, metric,
key, episode start) would lose every decision at each new episode,
which the alert side does not do. Because anomaly episodes are further
apart than an alert's incidents, a row also records its episode, and
the read marks the current state `carried` when it was decided on
another episode than the one held now; the page says so; a write of
the same state then is a row, not "unchanged". A triaged-out state
dims the card whether carried or not, the mark kept on it; a carried
`incident` never dims (owner ruling 2026-11-11, after the first build
left a carried card undimmed).

**Collisions.** The hash is unsalted (its inputs are in the answer
anyway) and FNV is invertible, so a sender who picks its MAC could aim
an id at another anomaly's. `anom_subject` keeps (rule, metric, key)
per id, written at the first triage or link; an id whose engine episode
disagrees with it is `409 id_collision` on every route.

**Not held.** The engine keeps a closed episode 24 h. After that the id
resolves from `anom_subject` (`"held":false`): the history is read and
can still be cleared. An id in neither is `404 no_such_anomaly`.

**No recommendation.** The assessments judge sloth's alert rules;
`"recommend":null`, and `state:"recommended"` is `409
no_recommendation`.

### 15.2 Links

`relation(id, a_kind, a_id, a_label, b_kind, b_id, b_label, note, who,
peer, ts)`, unique on `(a_kind, a_id, b_kind, b_id)`, indexed on the
`b` end. Kinds: 0 alert (id its subject), 1 anomaly, 2 device (a
canonical MAC), 3 BLE advertiser (`addr/type`, the TACDB's emitter
form; not the anonymous type 255; held while the ledger has a row of
it). A pair is an anomaly with anything, or an alert with a device or
a BLE advertiser (owner ruling 2026-11-11); alert to alert, device to
device and a thing to itself are `400 bad_pair`. `POST /api/frrs/relate`
`{"op":"add","from","to","note","by"}` resolves both ends against what
exists (the alert routes' own resolution; an anomaly in the engine or
in `anom_subject`; a device sloth.db, the latest pass, the ledger or an
anomaly's key holds) and writes one row, or answers the row that is
there when the pair exists in either direction; `{"op":"remove","from",
"link"}` deletes one, only when `from` is one of its ends. Bounds:
8,192 rows, 32 naming one finding, `507 links_full` past either. The
labels are slothweb's words (an alert type's name and its descriptor's
address, never its key; an anomaly's rule, kind and key), kept so a
link outlives its ends: `GET /api/frrs/related?id=` lists a finding's
links from either end with `"held"` false for an end that has left
sloth.db or the engine.

### 15.3 Candidates

Never automatic, never stored. For a finding held now and about a MAC
or an IP address, `/api/frrs/related` offers up to eight others about
the same MAC or address whose `[first_seen, last_seen]` overlaps its
own or lies within `WEB_REL_WINDOW_S` 600 s, edges inclusive: ten
minutes is the longest look-back of any anomaly rule (A7, A8), so an
episode can trail its cause by that much. Sources: the engine's
episodes by key; the stream's incidents (a MAC in the key, or
`match_ip`); `web_sdb_alerts()`'s newest 32 for the MAC or address,
under the request's budget. A candidate is resolved to its finding
before it is offered, so the stream's and sloth.db's names of one alert
are one candidate and a linked one is not offered again. Wording: "same
device" or "same address", "overlapping in time" or "within 10
minutes", and one fixed sentence that it is not established; no word of
cause.

### 15.4 What was not built

- The TACDB export and import carry alerts' triage only.
- Alert-to-alert and device-to-device links.
- SSIDs and hosts (an IP address with no MAC) as link ends (an SSID
  takes a plain note since 15.5; it is still no link end).
- The capture scope does not filter candidates or links (operator
  state, like the TACDB).
- Triage chips on the presence strip's episode marks (the Anomalies
  view's table form has them since the follow-up of 2026-11-11).

### 15.5 Plain notes (2026-11-11, as built)

Owner request 2026-11-11 ("an openclaw agent will need to read the
data thru an mcp and add notes to anomalies, devices, and other
observations and devices"). A finding's note is its triage note
(15.1); a plain note (`web_notes.h`) is for the subjects that are not
findings: a device, a BLE advertiser, an SSID, a GNSS satellite, an
aircraft, an APRS station. It has no state. It is a row (kind,
subject, text, who, peer, via, ts) in `note` (slothweb.db v10), never
changed; a retraction is another row naming it, as a clear is a row.
A subject's id is validated whole to its kind's format and the
subject must be held when a note is added. Bounds: 64 rows a subject,
20,000 in all; only retracted notes fold; `507 notes_full` otherwise.
The write is `POST /api/frrs/note`, the eighth path of 5.2, behind
5.3's checks unchanged.

`via` gains a fourth value, `agent` (3), recorded on triage rows,
links (`relation.via`, v10) and notes alike. It is decided by the
write path's gate from the request's authentication and never from
its body ([[slothweb-mcp]] has the design).

