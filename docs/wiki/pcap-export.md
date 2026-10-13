---
name: pcap-export
description: Per-alert pcap dumps, manual packet-window export, EAPOL per-handshake pcap, the in-memory 802.11 evidence ring — all the ways sloth keeps and writes frames
type: reference
---

# Pcap export

**Summary**: Three independent pcap-export paths — per-alert (driven by `--pcap-dir`), manual from the packets view (`w` key), and per-EAPOL-handshake (driven by `--eapol-dir`) — plus a fourth, memory-only path: the 802.11 evidence ring, which retains whole monitor frames and is the only route from a wireless alert back to the frames that caused it.

**Sources**: `docs/views/packets.md`, `docs/views/alerts.md`, `docs/views/eapol.md`, `src/evidence_ring.h`, `src/evidence_export.h`.

**Last updated**: 2026-10-13 (#92 evidence ring, ID keying, and deauth-flood citations).

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

## 4. The 802.11 evidence ring (#92)

An alert on an IP flow can be exported from the general packet ring by
`match_ip` + `match_port`. A wireless alert has neither: a deauth frame
is 802.11 management and carries no IP. Before this existed, every
wireless detection shipped with zero supporting packets, and the general
ring would not have helped — it keeps only `min(caplen, 64)` bytes.

- Memory only. No flag, nothing written to disk by this path.
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

Only the **deauth-flood family** so far. `deauth_victim_t` keeps up to
`DEAUTH_EVIDENCE_IDS` (8) event IDs per (BSSID, victim) aggregate and
`rule_deauth_flood()` stamps them onto the alert as
`evidence_ids[]` / `evidence_id_count`. Every other rule passes none,
and reads as an empty list.

Two deliberate choices:

- **The newest IDs, not the first.** The ring evicts oldest-first, so a
  thousand-frame flood evicts its own opening frames; citing those would
  leave an alert pointing at records that no longer resolve. The list is
  refreshed on each evaluation for the same reason.
- **Retransmissions cite nothing.** A Retry=1 frame repeating the
  previous sequence number is the same MPDU (IEEE 802.11-2020
  10.3.2.14); the row does not count it as a frame, so it adds no ID.

### What is not wired yet

Being explicit, because the gap is the interesting part:

- **Nothing writes evidence frames to disk.** `src/evidence_export.c`
  exists and refuses to write unless `--collect-handshakes` is set,
  creating through the same pinned dirfd and 0600/`O_EXCL` path as the
  EAPOL export — but it has **no production caller**. Today only the
  test suite reaches it.
- **The IDs are not exported.** `evidence_ids` is on `alert_t` and in
  no JSONL record and no `--db` column; the only consumer is C code.
- **No evidence filenames, no manifest, no `storage_error` event.** All
  still open on #92.
- **A failed evidence export leaves a misleading artifact.**
  `src/evidence_export.h` promises "nothing partial is left behind", but
  all three failure paths only `close(fd)`: the file stays under its
  final name, zero-length or truncated. The §"Permissions and failures"
  claim below ("partial files are removed") is true of `alert_pcap.c`,
  `pcap_write.c` and `eapol_log.c`, and **not** of `evidence_export.c`.

## File writer

Each path has its own writer — `src/alert_pcap.c`, `src/pcap_write.c`,
`src/eapol_log.c` — all emitting the classic pcap header (no pcapng) so
the output is portable to every reasonable tool.

## Permissions and failures (#87)

Every one of these files holds captured traffic; the EAPOL ones are
offline-crackable. Modes do not depend on the umask:

| Path | Dir | File | Create mode |
|---|---|---|---|
| `--pcap-dir DIR` | 0700 | 0600 | exclusive, suffixed on collision |
| `w` in Packets | (cwd, not checked) | 0600 | exclusive, suffixed on collision |
| `--eapol-dir DIR` | 0700 | 0600 | `eapol.22000` append; per-handshake pcap atomic replace |

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
removed; a failed per-handshake replace keeps the previous capture.
Details for the handshake export: [`docs/views/eapol.md`](../views/eapol.md#export-handling-87).

## Related pages

- [[alerts]]
- [[wifi-sigint]] — the EAPOL view that drives the handshake export.
- [[architecture]]
