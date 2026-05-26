---
name: pcap-export
description: Per-alert pcap dumps, manual packet-window export, EAPOL per-handshake pcap — all the ways sloth writes pcap files
type: reference
---

# Pcap export

**Summary**: Three independent pcap-export paths: per-alert (driven by `--pcap-dir`), manual from the packets view (`w` key), and per-EAPOL-handshake (driven by `--eapol-dir`).

**Sources**: `docs/views/packets.md`, `docs/views/alerts.md`, `docs/views/eapol.md`.

**Last updated**: 2026-05-25.

---

## 1. Per-alert (auto)

- CLI flag: `--pcap-dir DIR`.
- Triggered by [[alerts]] whose rule passes `match_ip` + `match_port`
  to `fire()`.
- Implementation: `src/alert_pcap.c`.
- New dedup key → fresh file containing the packets that matched.
  Repeat hits on the same key are appended to the same file.
- Clearing alerts (`c` in the Alerts view) resets dedup state, so a
  future hit re-arms and opens a new file.

## 2. Manual packet-window export

- `w` in the Packets view (`[4]`).
- Writes a timestamped `.pcap` to cwd containing the currently visible
  packets (filtered by the current BPF, if set).
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
- Re-completion of the same (BSSID, STA) overwrites the prior `.pcap`
  with the freshest capture; the `.22000` file appends.

## File writer

`src/pcap_write.c` handles all three paths. Standard pcap file header
(no pcapng) so the output is portable to every reasonable tool.

## Related pages

- [[alerts]]
- [[wifi-sigint]] — the EAPOL view that drives the handshake export.
- [[architecture]]
