---
name: pcap-export
description: Per-alert pcap dumps, manual packet-window export, EAPOL per-handshake pcap, the in-memory 802.11 evidence ring — all the ways sloth keeps and writes frames
type: reference
---

# Pcap export

**Summary**: Four pcap-export paths — per-alert from the packet ring (driven by `--pcap-dir`), manual from the packets view (`w` key), per-EAPOL-handshake (driven by `--eapol-dir`), and per-alert **evidence** from the 802.11 evidence ring (driven by `--collect-handshakes` + `--eapol-dir`), the only route from a wireless alert back to the frames that caused it.

**Sources**: `docs/views/packets.md`, `docs/views/alerts.md`, `docs/views/eapol.md`, `src/evidence_ring.h`, `src/evidence_export.h`.

**Last updated**: 2026-10-20 (#92 slices 1+2: the alert engine writes cited evidence frames; the evidence exporter writes temp → fsync → rename, so no partial file is ever left under a final name; review: a name an earlier run used gets a `-N` suffix instead of a per-tick retry). Previously 2026-10-14 (#122).

---

## 1. Per-alert (auto)

- CLI flag: `--pcap-dir DIR`.
- Triggered by [[alerts]] whose rule passes `match_ip` + `match_port`
  to `fire()`.
- Implementation: `src/alert_pcap.c`.
- New dedup key → fresh file `alert_<YYYYmmdd_HHMMSS>_<title>.pcap`
  containing the packets currently in the ring that match. Each dump
  is its own file, created exclusively; two in the same second get a
  `_2`, `_3` … suffix instead of overwriting each other.
- Clearing alerts (`c` in the Alerts view) resets dedup state, so a
  future hit re-arms and opens a new file.

## 2. Manual packet-window export

- `w` in the Packets view (`[4]`).
- Writes a timestamped `ntop_<YYYYmmdd_HHMMSS>.pcap` to cwd containing
  the packet ring, created exclusively at 0600 (same-second exports get
  a suffix). A failed write removes the partial file and the view shows
  `export failed`.
- **"cwd" is literal** (#134). This is the one export path with no
  `--*-dir` flag and no directory validation: the file lands wherever
  the process was started, `O_EXCL|O_NOFOLLOW` so a planted name is
  refused rather than followed, but the directory itself is not
  checked. Under a service manager that is whatever `WorkingDirectory=`
  says — the shipped unit will pin `WorkingDirectory=/var/lib/sloth` (the
  X6 slice of the 2026-10 architecture review; until it lands, set it
  yourself). Started by hand from `/tmp` or `$HOME`, that is where the
  pcap goes. There is deliberately no flag: `src/pcap_write.c` is
  unchanged, and an operator who wants exports somewhere specific
  starts sloth there.
- Useful for ad-hoc carving when you've narrowed via `/` to a flow of
  interest.

## 3. Per-EAPOL-handshake export

- CLI flag: `--eapol-dir DIR`, which requires the `--collect-handshakes`
  opt-in (off by default) and expires on `--handshake-retention` days
  (default 7) — see [[retention]].
- For each completed (BSSID, STA) 4-way handshake, writes:
  - `DIR/eapol.22000` in hashcat 22000 mixed format
    (`WPA*01*…` for PMKIDs, `WPA*02*…` for full handshakes with the
    MIC field zeroed per spec).
  - `DIR/<bssid>_<sta>.pcap` containing the raw 802.11 EAPOL-Key
    frames (M1..M4, no radiotap, DLT 105). Replayable in
    `aircrack-ng -w wordlist.txt -e <SSID> <file>.pcap`, openable in
    Wireshark / tshark. At most 512 bytes per frame are stored; each
    record header reports `caplen` (stored) and `origlen` (as captured)
    separately, so a truncated frame is visible as one.
- Re-completion of the same (BSSID, STA) atomically replaces the prior
  `.pcap` with the freshest capture (temp file + rename); the `.22000`
  file appends.
- **Which data frames reach the collector (#122).** `eapol_observe_dot11()`
  takes its MAC-header length from `dot11_data_header_len()` and its
  BSSID/STA from `dot11_data_addrs()` — both wrappers over the shared
  `dot11_frame_t` view — instead of a private formula. Until #122 the
  private copy added an HT Control field for *every* data frame with
  the Frame Control Order bit set; in a **non-QoS** data frame that bit
  is StrictlyOrdered and no field follows (IEEE 802.11-2020
  §9.2.4.1.10), so such an EAPOL frame had its LLC header read four
  bytes late and the handshake was silently missed. Operator-visible
  effect: StrictlyOrdered non-QoS EAPOL-Key frames now appear in the
  EAPOL view, the `.22000` file and the per-handshake pcap. Pinned by
  `tests/test_eapol_log.c :: test_m1_non_qos_strictly_ordered_is_recorded`
  (mutation-proved against the `has_htc` rule in `src/dot11_frame.c`).

## 4. The 802.11 evidence ring (#92)

An alert on an IP flow can be exported from the general packet ring by
`match_ip` + `match_port`. A wireless alert has neither: a deauth frame
is 802.11 management and carries no IP. Before this existed, every
wireless detection shipped with zero supporting packets, and the general
ring would not have helped — it keeps only `min(caplen, 64)` bytes.

- The ring itself is memory only and has no flag; what reaches disk is
  the alert evidence pcap below, behind `--collect-handshakes`.
- `src/evidence_ring.c` retains the **whole** captured frame including
  the radiotap header, fed from `on_probe_frame()` behind the same
  framing guards as the rest of the monitor path — a frame too short to
  parse cannot be cited by anything, and admitting runts would let an
  attacker flush the ring with 10-byte garbage.
- Budget scales from RAM: ~1 % of `MemTotal`, clamped to
  [2 MiB, 32 MiB] (owner ruling, 2026-09-30). Zero-config. Evictions are
  counted as their own kind, `SH_EVICT_EVIDENCE_FRAME`.
- Each record carries the frame's own capture clock (sec + usec),
  `cap_len` and `orig_len` independently, the radiotap frequency and
  signal, and a `truncated` flag. There is no `time(NULL)` fallback.

### Keyed by event ID, and nothing else

`evidence_ring_note()` returns a monotonic **event ID**, never reused
and never 0. `evidence_ring_get(id, …)` is the only retrieval path: no
IP, no flow, no time window. An ID that was never issued, or whose
record has been evicted, returns −1 — never a different frame. That is
what makes a citation safe to carry on a long-lived alert.

### Which alerts cite frames

The no-IP wireless rules whose triggering frames are monitor frames.
Each detector keeps a small bounded ring of event IDs next to the state
it already keeps and hands it to the alert as `evidence_ids[]` /
`evidence_id_count`; every other rule passes none and reads as an empty
list. `on_probe_frame()` stamps the ID on the decoded frame view
(`dot11_frame_t.event_id`), so frame observers read it from there; the
ones that take bare fields get it through an `_ev` entry point.

| Rule | What it cites | Where the ring lives |
|------|---------------|----------------------|
| `DEAUTH_FLOOD` | the newest distinct deauth/disassoc frames at the (BSSID, victim) | `deauth_victim_t`, 8 |
| `PM_FORGE` (#107) | the contradicting pairs: the PM=1 Null/QoS-Null and the PM=0 data frame that broke it, newest pairs first | `pm_forge_t`, 8 |
| `QUEUE_EVICT` (#107) | the (re)association response or deauth/disassoc that changed the session, then the newest frames of the released burst | `queue_evict_t`, 8 — copied from the pending burst only once it reaches the threshold, so a later change with one stray frame keeps the reported release's citations |
| `AUTH_FLOOD` | the newest Authentication frames to the flooded BSSID inside the window | the module's event ring (512), walked newest first |
| `ASSOC_FLOOD` | the newest (Re)Association Requests to the BSSID inside the window | the module's event ring (256) |
| `BTM_ABUSE` | the newest BTM Requests to the pair that carried Disassociation Imminent — the ones the threshold counts; an ordinary steer is not cited | the BTM event ring (256) |
| `SA_QUERY_FLOOD` | the pair's newest SA Query frames inside the window — the AP's answers, which is what the rule hears | per-pair timestamp ring, one id beside each stamp |

The flood rings were already keyed by frame, so their citations need no
new storage beyond one id per entry: the query walks the same window
the count used, so a cited frame is always one that was counted.

The shared ring is `src/ev_cite.h`: 0 is never stored, an ID already
held is not stored twice (one Null behind two contradictions), and the
list is flattened oldest first.

Two deliberate choices:

- **The newest IDs, not the first.** The ring evicts oldest-first, so a
  thousand-frame flood evicts its own opening frames; citing those would
  leave an alert pointing at records that no longer resolve. The list is
  refreshed on each evaluation for the same reason.
- **Retransmissions cite nothing.** A Retry=1 frame repeating the
  previous sequence number is the same MPDU (IEEE 802.11-2020
  10.3.2.14); the row does not count it as a frame, so it adds no ID.

### Alert → disk: the evidence pcap (#92 slices 1+2)

An alert that cites evidence-ring frames now writes them out.
`dump_new_alert_pcaps()` (`src/alerts/engine.c`) picks the exporter per
incident: `evidence_id_count > 0` goes to `evidence_export_pcap()`,
otherwise a `match_ip` goes to `alert_pcap_dump()` (§1). Before this the
loop skipped any alert without a `match_ip`, so a DEAUTH_FLOOD CRIT —
IDs on the alert, every flag set — wrote zero frames.

- **Gate** (owner ruling 2026-10-08, option B): `--collect-handshakes`
  **and** `--eapol-dir`. Not `--pcap-dir`: a raw 802.11 frame carries
  EAPOL/PMKID material, and an operator who set `--pcap-dir` for IP
  alerts must not start collecting crackable bytes on upgrade. A closed
  gate is not a failure — nothing is counted, nothing retries.
- **Policy**: the same `pcap.min_severity` floor (default CRIT) and the
  same per-key `pcap.key_cooldown_secs` (default 3600) as §1, on the
  same per-key side row. A WARN deauth flood (not your BSSID) writes
  nothing until it escalates; a key that re-fires inside the cooldown
  names the file its earlier incident wrote.
- **Name**: `<incident_id>-<event_id>-<RULE>.pcap`, e.g.
  `22bdad5846ecd3fb-13-DEAUTH_FLOOD.pcap` — the incident (#98), the
  first evidence-ring event ID it cites, and the alert kind. Inside
  `--eapol-dir`, so it inherits 0600, symlink-safe creation and the
  `--handshake-retention` sweep (evidence expires on the handshake
  clock — caveat 3 of the ruling). The name is unique within one
  process only — `incident_id`'s sequence and the evidence-ring IDs
  both restart at launch — so a restart that re-fires the same key in
  the same wall second (an RTC-less sensor booting to a saved clock)
  can rebuild a name an earlier run left inside the retention window.
  The export then commits under `<stem>-2.pcap`, `-3` … up to `-99`
  (a `-`, not `--pcap-dir`'s `_`, because the rule slug already holds
  underscores) and reports the name it used; the earlier file is never
  touched. Only when all 99 are taken is it a failure, and that one is
  terminal: counted once, the incident done. Until the #92 review the
  first collision was refused and retried every tick for the incident's
  life — a full write, fsync and unlink per tick, a failure counted per
  tick, and `sensor_health` re-emitted per tick through
  `storage_failures`.
- **Content**: DLT 127 (radiotap + 802.11), every cited frame the ring
  still holds, each with its own capture time and caplen/origlen. IDs
  that have aged out are skipped; if **all** have, no file is written
  and the incident is done (nothing to retry) — unless it also has a
  `match_ip` and `--pcap-dir` is set, in which case it falls back to the
  §1 writer, which may still hold its packets. No detector sets both
  today.
- **Outcome on the alert**: `pcap_path` (the full path, or the bare name
  if it would not fit in 255 bytes — never a truncated path) and
  `pcap_write_failures`, on the `alert.*` lifecycle events
  ([[jsonl-schema]]). A failed write leaves `pcap_dumped` at 0 and
  retries next tick, as §1 does. The failure is also counted with the
  EAPOL export's own (`eapol_export_failures()`: one stderr line, the
  `[e]` view count, the `!persist` badge); a closed gate is not. The
  first event to carry `pcap_path`
  is the one after the export: `alert.create` goes out before the
  export runs in the same tick.
- **Not covered**: the `storage.min_free_*` floors are checked by the
  `--pcap-dir` writer only, not by this one.

**No partial file under a final name** (slice 2). The exporter writes
`.<name>.tmp` (`O_EXCL`, same pinned dirfd), fsyncs it, closes it, and
then — under the EAPOL module's lock, only if nothing is at `<name>` —
`renameat()`s it into place and fsyncs the directory. Every failure
path (header write, buffer allocation, a record mid-file, fsync, close,
commit, an existing name) unlinks the temp, so `<name>` is either a
complete export or absent. Until slice 2, three of those paths only
closed the descriptor and left a zero-length or truncated file under
the final name. A temp left by a crash is cleared before the next
export of that name and is in any case a dotted `.tmp`, which the
retention sweep already expires. Pinned per path by
`tests/test_evidence_alert.c` through a fault seam
(`evidence_export_test_fault()`), not a full disk.

### Still open on #92

- **A hashed per-session manifest** over every file under `--eapol-dir`
  and `--pcap-dir` (slice 3).
- **Citations beyond DEAUTH_FLOOD**, one detector per slice (slice 4).
  Until then every other wireless alert still exports nothing.

## File writer

Each path has its own writer — `src/alert_pcap.c`, `src/pcap_write.c`,
`src/eapol_log.c` — all emitting the classic pcap header (no pcapng) so
the output is portable to every reasonable tool. All three stamp their
file names with `localtime_r()`; `alert_pcap.c` was the last to use the
non-reentrant `localtime()` (CWE-663), fixed in #134 after `pcap_write.c`
had already moved for #95.

Every writer that takes a *directory descriptor* (`--pcap-dir`,
`--eapol-dir`, the evidence export) now refuses a file name that is not
bare: empty, `.`, `..` or anything containing `/` is `EINVAL` before any
syscall (`sfile_open()`, #134). The names are built by sloth today, so
nothing changes in the field; the guard is there for the day a TUI
prompt or the data socket supplies one, so `../` stops at the pin
instead of walking out of it (CWE-22). Operator paths (`--report`,
`--snapshot-out`, `-o`, `--db`) are `AT_FDCWD` and keep their slashes.

## Permissions and failures (#87)

Every one of these files holds captured traffic; the EAPOL ones are
offline-crackable. Modes do not depend on the umask:

| Path | Dir | File | Create mode |
|---|---|---|---|
| `--pcap-dir DIR` | 0700 | 0600 | exclusive, suffixed on collision |
| `w` in Packets | cwd — not checked; pin it with `WorkingDirectory=` | 0600 | exclusive, suffixed on collision |
| `--eapol-dir DIR` | 0700 | 0600 | `eapol.22000` append; per-handshake pcap atomic replace; alert evidence pcap temp + fsync + no-clobber rename |

`--pcap-dir` and `--eapol-dir` are created 0700 when absent. An
**existing** directory must be owned by sloth's effective uid with no
group/other bits and must not be a symlink — otherwise sloth refuses it
at startup and exits non-zero. It never `chmod`s the path. So `--pcap-dir
/tmp` is refused: `/tmp` is shared. Files are opened `O_NOFOLLOW`
relative to the directory descriptor validated at startup, and an
existing file sloth would reuse must itself be private.

Write failures are reported, not swallowed: the first prints one
`sloth: <alert pcap|eapol> export failed: …` line to stderr and every
one is counted (the EAPOL view shows its count). Partial files are
removed — for the evidence export, never created under the final name
at all; a failed per-handshake replace keeps the previous capture.
Details for the handshake export: [`docs/views/eapol.md`](../views/eapol.md#export-handling-87).

## Related pages

- [[alerts]]
- [[wifi-sigint]] — the EAPOL view that drives the handshake export.
- [[architecture]]
