---
name: sweep-session
description: sloth --sweep LABEL --sweep-minutes N. A time-limited sweep of a room or site, every 2.4 and 5 GHz channel once for an equal time, and a report of every emitter heard against the label's accepted baseline, with what was not swept
type: reference
---

# Sweep session

**Summary**: `sloth --sweep LABEL --sweep-minutes N --hop [--sweep-dir DIR]` runs the preflight, then visits every 20 MHz channel of 2.4 and 5 GHz once, each for an equal share of N minutes, while the BLE source (if one is given) listens throughout. At the end it writes a report of every emitter heard (access points, Wi-Fi clients, BLE advertisers) as **new**, **known** or **missing** against the label's accepted baseline, unknown emitters first and strongest first, cameras, setup-mode devices and hidden-name access points in their own section, the coverage statement (what was swept, for how long, and what was not) and the limits of a sweep. It adds no detector: it packages the inventory sloth already keeps. Receive-only, like every other part of sloth (MISSION §2): only sloth's own monitor radio is retuned, and nothing is transmitted.

**Status**: #249, 2026-11-25 (JSONL 2.16.0). Built in sloth: the flags, the in-process preflight, the sweep plan, the inventory, the comparison, the reports, the `sweep_report` record and the baseline file (snapshot v2). Not built here: the slothweb button that accepts a sweep as the label's baseline (owner ruling 2026-11-25: a sloth-mesh write route behind the write-path ACL); until it exists, accepting is the copy described in § 5. No PDF (no report export exists).

**Sources**: issue #249 (from #241 item 14) and its owner rulings of 2026-11-25; FM 2-0 (17 May 2004) 11-18, page 11-5 (technical surveillance countermeasures: keeping sensitive and restricted areas "clear of any adversary intelligence-placed active or passive electronic sensing, or eavesdropping or collection devices") and chapter 9, 9-4, page 9-2 (Unintentional Radiation Intelligence, a MASINT subdiscipline), both checked against the manual's text in the #249 review; IEEE 802.11-2020 §11.1.3.2 (dot11BeaconPeriod, the dwell floor); Bluetooth Core v5.4 Vol 6 Part B §1.3.2 (BLE address kinds); IEEE 802-2014 §8.2 (the locally administered bit); `src/sweep.h`, `src/sweep.c` (inventory, compare), `src/sweep_cov.c` (coverage), `src/sweep_report.c` (reports, record), `src/sweep_run.h`, `src/sweep_run.c` (the run, the files), `src/wifi_chanhop.c` (`chanhop_init_sweep()`), `src/wifi_snapshot.c` (format v2, `wifi_snapshot_read()`), `src/main.c` (the flags); `tests/test_sweep.c`.

**Last updated**: 2026-11-25 (#249 review: the FM 2-0 citations checked against the manual; an unreadable baseline is refused before the preflight; the exit status; the refusals under `make replay-check`), 2026-11-25 (#249: the page).

---

## 1. Running one

```
sloth --sweep boardroom --sweep-minutes 10 --hop --monitor-iface wlan1 \
      --bt-monitor --db /var/lib/sloth/sloth.db --headless
```

- `--hop` is required (the sweep is a hop plan) and `--cue` is refused: cueing lengthens one channel's dwell on a finding ([[passive-cueing]]), and a sweep gives every channel the same time.
- `--replay` is refused (no radio), and so are the offline commands (`--preflight`, `--handoff`, `--verify`, `--interference-report`).
- The sweep directory is `--sweep-dir DIR`, or the `--db` file's directory. It must exist.
- The `--preflight` checks ([[preflight]]) run in process first; the page goes to stderr and a `fail` exits `2` before anything is opened or a session starts. A warning does not stop the sweep.
- The `--db` session is labelled `sweep:LABEL`.
- A label baseline that is there and cannot be read (not a regular file, not readable) exits `2` before the preflight, like the refusals above. A sweep that did not start, or did not write its inventory or a report, exits `1`; one that wrote them exits `0`. `tests/replay/sweep_cli.sh` (run by `make replay-check`) holds every refusal above to exit `2` with nothing left in the sweep directory.
- Do not run a sweep on a host whose radios a live sensor service is using: the two would compete for the same radios.

The run stops when every radio has finished its one pass, when the time given runs out, or on `q` / a signal; the report says which (`pass`, `time`, `stopped`).

## 2. The plan

`chanhop_init_sweep()`: 2.4 GHz channels 1-13 and 5 GHz 36-64, 100-144 and 149-165 at 20 MHz, 38 channels, DFS channels included (the radio only listens; a driver that will not tune one refuses the retune, and the channel is reported as not swept with its refusal). Each channel gets the same dwell, N minutes / 38, rounded down to the poll interval (a dwell only ends at a poll, so a plan that is not a multiple of it would run long on every channel and the pass would outrun the time) and never under 1024 ms, ten beacon intervals of the default 100 TU. Activity does not move it and no cue applies. With several `--monitor-iface` radios the list is dealt between them ([[multi-radio-sensing]]) and each spreads the whole time over its share.

No 6 GHz: its 59 channels do not fit the plan, and the report names the band as not swept. Sub-GHz is never swept (owner ruling 2026-11-25: Wi-Fi and BLE only).

## 3. What is compared

The inventory is kept for the whole sweep, merged from the state's tables once a poll, so an access point heard on the first channel is still in it at the end though the beacon table ages it out after five minutes.

| kind | source | kept per label | counted only |
|---|---|---|---|
| access point | beacon table (monitor radio) | every BSSID | — |
| Wi-Fi client | probing clients, (re)association requests and responses | universal addresses | locally administered addresses (they change per network) |
| BLE advertiser | the HCI monitor channel or an Ubertooth | public and static random addresses | resolvable and non-resolvable private addresses, anonymous reports |

The BLE row is the owner's ruling of 2026-11-25; the client row applies the same reasoning to Wi-Fi. A counted address is never new or known: a phone's rotated address would otherwise be new at every sweep. The counts are distinct addresses, to 3072; past that the report says "at least".

Each emitter is **new** (not in the baseline), **known**, or, for a baseline row not heard, **missing**. A baseline that holds no clients or BLE (a v1 snapshot) leaves those kinds "not compared". With no accepted baseline every emitter is new.

The cameras / setup mode / hidden names section flags: an address in a camera vendor's own block (a mixed-vendor block is not enough, [[camera-detection]]), a camera vendor's setup SSID, an open `OPEN_SETUP_AP` finding on the BSSID, and an access point whose beacon carried no SSID.

## 4. The report

Files in the sweep directory, all `0600`, the three per-sweep ones created `O_EXCL` (a sweep never replaces another's record):

| file | what |
|---|---|
| `sweep-LABEL.<UTC start>.tsv` | this sweep's inventory, a snapshot v2 file ([[wifi-sigint-techniques]] § snapshot format) |
| `sweep-LABEL.<UTC start>.md` | the report |
| `sweep-LABEL.<UTC start>.json` | the same as JSON |
| `sweep-LABEL.baseline.tsv` | the label's accepted baseline; read, never written by sloth |

The report holds: the start, end, time given and why it ended; the baseline (path and version, or none); counts by kind and status; the new, known and missing tables (kind, address, SSID / name / vendor escaped as the snapshot escapes them, best signal, channel, and for a known access point whose channel or encryption moved, the baseline's); the cameras / setup / hidden section; the coverage statement: every channel of the plan with its measured time (the scheduler's own start-of-dwell to start-of-next accounting), visits, refused retunes, frames and whether it was swept, the channels not swept and the bands not swept (6 GHz and sub-GHz always; 2.4 or 5 GHz when no channel of it was swept); whether the monitor radio and the BLE source were up at the end; and the limits:

- A sweep finds devices that transmit during the sweep in the bands the radios cover. It does not find a device that is off, that stores and sends later, or that uses a wire.
- Each channel is heard for its dwell only.
- 6 GHz and sub-GHz are not swept.
- A device that does not advertise is not found over BLE.
- Rotating addresses are counted, never compared.

The report says nothing about detecting electronics from unintentional radiation: that is research, and it needs a bench measurement with `sloth-rf` before any report makes a claim about it.

One `sweep_report` JSONL record ([[jsonl-schema]]) is written at the end: counts, words and channel numbers, no address, SSID or name.

## 5. Accepting a baseline

A sweep never changes the baseline. Accepting one makes its inventory file the label's `sweep-LABEL.baseline.tsv`; the owner's ruling puts that behind a button in slothweb (sloth-mesh), a write route behind its write-path ACL. Until that is built, the operator accepts by copying the sweep's `.tsv` over the baseline (keeping it `0600`). The next sweep with the label compares against it.

The baseline file is outside sloth.db, so the #239 random-address purge never touches it ([[retention]] § 2e); it holds no private BLE address and no locally administered client address, only their counts.

## Related pages

- [[cli-reference]] — `--sweep`, `--sweep-minutes`, `--sweep-dir`.
- [[preflight]] — the checks a sweep runs first.
- [[wifi-sigint-techniques]] — the snapshot file, v2.
- [[passive-cueing]] — why `--cue` is refused.
- [[multi-radio-sensing]] — how the plan is dealt between radios.
- [[retention]] — § 2e, the baseline's retention.
- [[jsonl-schema]] — `sweep_report`.
