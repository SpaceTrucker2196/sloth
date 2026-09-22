---
name: pcap-export
description: Per-alert pcap dumps, manual packet-window export, EAPOL per-handshake pcap — all the ways sloth writes pcap files
type: reference
---

# Pcap export

**Summary**: Three independent pcap-export paths: per-alert (driven by `--pcap-dir`), manual from the packets view (`w` key), and per-EAPOL-handshake (driven by `--eapol-dir`).

**Sources**: `docs/views/packets.md`, `docs/views/alerts.md`, `docs/views/eapol.md`.

**Last updated**: 2026-09-22 (#87 file permissions).

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

- CLI flag: `--eapol-dir DIR`.
- For each completed (BSSID, STA) 4-way handshake, writes:
  - `DIR/eapol.22000` in hashcat 22000 mixed format
    (`WPA*01*…` for PMKIDs, `WPA*02*…` for full handshakes with the
    MIC field zeroed per spec).
  - `DIR/<bssid>_<sta>.pcap` containing the raw 802.11 EAPOL-Key
    frames (M1..M4 as captured, no radiotap, DLT 105). Replayable in
    `aircrack-ng -w wordlist.txt -e <SSID> <file>.pcap`, openable in
    Wireshark / tshark.
- Re-completion of the same (BSSID, STA) atomically replaces the prior
  `.pcap` with the freshest capture (temp file + rename); the `.22000`
  file appends.

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
