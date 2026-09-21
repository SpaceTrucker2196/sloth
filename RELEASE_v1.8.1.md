# sloth v1.8.1 — FragAttacks, WPA3 downgrade, and cited sources

Weekly patch release. Five issues closed (#73, #74, #75, #76, #80) plus
three buildable slices of #77, which stays open. Fourteen new detectors,
the in-tree research corpus that backs them, and a JSONL overflow fix
that matters if you run with `-o` or the data socket.

Suite went **6687 → 8358 assertions**. Alert types **48 → 62**. Views
**33 → 35**.

---

## Upgrade notes

**No schema bump — `DB_SCHEMA_VERSION` stays 4.** An existing v4 `--db`
file opens as-is and gains one new table, `ssid_akm_history` (#74),
via `CREATE TABLE IF NOT EXISTS`. New alert types are appended to the
end of the enum, so every persisted `alerts.type` value is unchanged.

**JSONL is additive only.** New fields on `beacon`: `wps_manufacturer`,
`wps_model_name`, `wps_model_number`, `wps_serial`, `ie_order_hash`,
`ie_order_count`, `tbtt_jitter_us`, `tbtt_jitter_samples`,
`tbtt_jitter_resets`. Nothing removed, renamed or re-typed.

**CLI is additive only.** New: `--version` / `-V`, `--with-research`.

**License.** The repository now ships `LICENSE` — Sloth Source-Available
License 1.0 (#79): non-commercial, no derivatives, no enterprise or
law-enforcement use; packaging of unmodified source for distro
repositories is permitted. Earlier tags carry no license file.

---

## Security fix — JSONL stack overflow (1f108a8)

Every JSONL builder advanced with `off += snprintf(...)`. A record that
filled the buffer pushed `off` past `LINEBUF`, the remaining-size
calculation wrapped, and the next write landed out of bounds on the
stack. **Attacker-reachable**: SSID history, WPS strings and probed
SSIDs are chosen by the transmitter, and `json_escape` expands a control
byte sixfold. An AP cycling escape-heavy SSIDs crashed sloth whenever
`-o` or data-socket output was on.

All appends now go through a clamped `appendf()`. `LINEBUF` 2048 → 8192
(measured worst cases: beacon 4529 bytes, PNL 3436) and
`EMIT_XFORM_MAX` 2560 → 16384, so hostile records emit whole rather than
truncated to invalid JSON. **Upgrade if you use JSONL output.**

---

## New detectors

**FragAttacks family** (#75, Vanhoef 2021) — nine alert types:

| Alert | CVE | Signal |
|---|---|---|
| `FRAG_PLAINTEXT` | CVE-2020-26140 / -26143 | plaintext data after key install, per (BSSID, STA), ordered |
| `FRAG_BCAST` | CVE-2020-26145 | plaintext broadcast fragment on a protected BSS |
| `FRAG_CACHE` | CVE-2020-24586 | reassembly straddles a (re)association |
| `FRAG_MIXED` | CVE-2020-26147 | reassembly mixes encrypted and plaintext fragments |
| `FRAG_AMSDU` | CVE-2020-24588 | same CCMP PN replayed with the A-MSDU bit flipped |
| `FRAG_AMSDU_EAPOL` | CVE-2020-26144 | plaintext A-MSDU whose first subframe claims EAPOL |
| `FRAG_MIXKEY` | CVE-2020-24587 | reassembly spans a PTK rotation (M3 with a new ANonce) |
| `FRAG_PN_GAP` | CVE-2020-26146 | encrypted fragments with dPN ≠ dFN |
| `FRAG_EAPOL_RELAY` | CVE-2020-26139 | EAPOL with neither SA nor DA equal to the BSSID |

The A-MSDU attack as originally specified is unobservable (subframe
headers are inside the ciphertext); `FRAG_AMSDU` detects the replay it
requires instead. New **`[c]` FragAttacks view** — per-BSSID counters.

**WPA3 downgrade** (#74) — `SAE_PSK_SPLIT`: one SSID SAE-only on one
BSSID and PSK-only on another, the gap between `EVIL_TWIN`'s branches.
`SAE_PSK_REGRESSION`: one BSSID that sustained SAE-only now advertises
PSK-only, from persisted `ssid_akm_history`. Neither fires on transition
mode — that is `WPA_DOWNGRADE`. Basis: CVE-2023-52424, Dragonblood.

**Action frames** (#76) — `SA_QUERY_FLOOD`: the AP's MFP answer to a
spoofed-disassociation flood, visible even when the flood is not.
`MFP_UNPROTECTED`: unprotected robust action frame on an MFP-required
BSS (CVE-2019-16275). `EVIL_TWIN` gains a **`+btm-steered by <AP>`**
marker, escalating WARN → CRIT, when a Disassociation-Imminent BTM
Request named that twin within 300 s — a marker, not a sixth alert.

**`OPEN_SETUP_AP`** (#80) — WARN on an open SoftAP named like a device
onboarding surface (`SETUP-`, `HP-Setup`, `HP-Print-`, `DIRECT-`,
`roborock-vacuum-`, `NETGEAR_EXT`), behind a hotspot/guest allowlist
checked first. Under-flags on purpose. Basis: NIST SP 1800-36 Vol. A;
Wi-Fi P2P spec v1.5 §3.2.1 (`DIRECT-` mandates WPA2-PSK).

## Tool fingerprints (#74, #68)

ESP32 Marauder and Pineapple MK7 rows land in the formerly empty
signature table, flagged **unverified** — sourced from research, not a
capture. An unverified row caps reported confidence at MED however many
fields agree.

## New data (#77 slices)

Observables only — no thresholds, no alerts, no signatures, because the
attributions #77 asks for have no source verifiable without hardware.

- **WPS vendor strings** — Manufacturer / Model Name / Model Number /
  Serial Number (WFA WPS 2.0 §12).
- **Beacon IE-ordering hash** — element identity and order, bodies
  excluded (IEEE 802.11-2020 §9.3.3.2; Vanhoef et al., AsiaCCS 2016).
- **TBTT jitter** — stddev of the TSF residual against whole Beacon
  Intervals, on the AP's own clock (IEEE 802.11-2020 §11.1.3, §9.4.1.10).

## Research corpus (#73)

Curated per-source documents indexed into SQLite FTS5 (`research.db`,
committed, byte-reproducible). Query layer linked into sloth
(`--with-research` adds citations to `--report`); `make research-mcp`
builds a stdio MCP server over the same functions (not in `all`). New
**`[f]` Research view** — the sources behind each alert kind that has
fired, uncited kinds shown rather than hidden. The content pass took
coverage from 24/60 to 59/60 citable kinds; the coverage guard is now **enforcing** — a new uncited detector
fails the suite.

## Fixed

- `ALERT_KEY_LEN` 96 → 192: on IPv6 flows every cleartext-credential
  user on one flow deduped into a single alert (d7c23f8).
- Build is warning-clean on gcc 13 across all four variants (was 8).
- Research-view citation lookup keyed on the abbreviated display title
  and silently lost matches; now keyed on `alert_type_name()`.

## Known gaps

- #77's per-vendor stack table, two-radio Pineapple correlation and
  verdict scorer need capture hardware.
- Marauder / MK7 fingerprint rows remain unverified until captured.
- The v1.8.0 gaps (chunked portal responses, `--hop` absence, DHCP
  option 114, request bodies) are unchanged.

---

Passive throughout. Nothing here transmits, scans, or modifies kernel
state — see [`MISSION.md`](MISSION.md) §2.
