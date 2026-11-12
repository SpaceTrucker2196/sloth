# tools/lab — the #199 bench helpers

Two scripts for the bench in issue #199: w9fjc (dev, Kali) attacks the test
AP we own, beta-site (production) is the sensor under test.

## Hard rules (#199, restated)

Transmit only at equipment we own: the test AP (`sloth-lab`) and our own
clients, never a neighbour's SSID, BSSID or station. Lowest transmit power,
60 s or less per flood or KARMA run, and no deauthentication or
disassociation frames outside the RF shield bag. Before each session open a
slothweb incident on beta-site filtered on the attacker adapter's MAC and the
session window, and close it afterwards as `known`. The attacker adapter stays
out of sloth's capture on w9fjc; check `iw dev` before each session.
Neither script transmits: `lab_capture.sh` only listens, `expect.sh` only reads.

## lab_capture.sh

```
sudo tools/lab/lab_capture.sh [--hw MODEL] [--chipset NAME] [--firmware VER]
     [--max-mb N] [--out DIR] [--dry-run] IFACE TEST "TOOL VERSION" BAND/CHANNEL SECONDS

sudo tools/lab/lab_capture.sh --dry-run --hw "Alfa AWUS036AXML" wlan2 L2 "hostapd 2.10" 5/36 300
```

Runs tcpdump (dumpcap when installed) on IFACE for SECONDS or until the pcap
reaches `--max-mb` (256 MiB default), then writes
`lab/YYYY-MM-DD/<TEST>-<YYYYMMDDTHHMMSSZ>.pcap` and a `.json` sidecar beside it.
`lab/` is git-ignored: captures are never committed. It never changes the
interface's mode, channel, power or link state. Run it as root: it must read a
running sloth's sockets.

It refuses (exit 2, nothing captured) when IFACE is one sloth captures on
(SLOTH_IFACE or an `--iface` in `/etc/default/sloth`, an `--iface` in a running
sloth's command line, or a running sloth's packet socket bound to IFACE; sloth
with no `--iface` takes the first monitor interface `/sys/class/net` lists, so
the sockets are the proof and unreadable sockets are a refusal), when IFACE is
not in monitor mode, when tcpdump/dumpcap, ethtool, python3 or sha256sum is
missing, when the chipset or firmware cannot be named and was not given, or
when the output directory is not writable. `--dry-run` runs every check and
prints the command.

Pass `--hw` with the adapter's real name: sysfs only knows the USB strings
("MediaTek Inc. WiFi"). The chipset comes from the USB id or the driver
(MT7612U for 0e8d:7612 or `mt76x2u`, MT7921AU for 0e8d:7961 or `mt7921u`).
When `ethtool -i` reports no firmware, take it from `dmesg` and pass `--firmware`.

### Sidecar (`sloth-lab-capture/1`, plan #145 ruling 2)

```json
{
  "schema": "sloth-lab-capture/1",
  "ruling": "plan #145 ruling 2",
  "test": "L2",
  "host": "w9fjc",
  "interface": {"name": "wlan2", "ifindex": 7, "mac": "00:c0:ca:..."},
  "hardware": {"model": "Alfa AWUS036ACM", "model_source": "operator",
               "chipset": "MT7612U", "chipset_source": "usb-id",
               "id": "0e8d:7612", "bus": "1-1:1.0"},
  "driver": {"name": "mt76x2u", "version": "6.x", "firmware": "...",
             "firmware_source": "ethtool", "kernel": "6.x"},
  "band_ghz": "5", "channel": 36, "channel_observed": 36,
  "tool": "hostapd 2.10",
  "capture": {"tool": "tcpdump", "version": "tcpdump version 4.99.4",
              "file": "L2-20261114T153000Z.pcap", "bytes": 123456,
              "sha256": "...", "max_bytes": 268435456, "duration_s": 300,
              "stopped_by": "duration"},
  "utc_start": "2026-11-14T15:30:00Z",
  "utc_end": "2026-11-14T15:35:01Z"
}
```

`stopped_by` is `duration`, `size` or `tool-exit`. `channel_observed` is what
`iw dev IFACE info` reported (null without `iw`); a mismatch is warned about,
not refused. Only captures with every field filled go into #151's stack table
or #156's crosswalk.

## expect.sh

```
tools/lab/expect.sh [--from-loopback] http://ADDRESS:PORT INCIDENT TEST
tools/lab/expect.sh http://192.0.2.10:8080 12 L3
```

Reads `/api/alerts?incident=N` (every page) and `/api/frrs/incidents?id=N` on
beta-site's slothweb, takes the alert types in either, and prints PASS/FAIL per
type the matrix row expects, then every type it did not expect. The address is
a literal IP and port; `--from-loopback` binds curl to 127.0.0.1 when run on the
sensor against its own address. Exit 0 PASS, 1 FAIL, 2 usage or fetch error,
3 not judged by alerts (L7 is judged by w9fjc's listener, L8's rotation hints
are estimates).

| Test | Expected (from #199) |
|---|---|
| L1 | nothing; any alert fails |
| L2 | `EVIL_TWIN`; `EVIL_TWIN_PROXIMITY` optional (when moved) |
| L3 | `KARMA_AP` and `KARMA_PROBE_FORGE` |
| L4 | `BEACON_FLOOD` |
| L5 | `PMKID_HARVEST` or `HANDSHAKE_HARVEST` |
| L6 | `ATTACK_PATH` and `ATTACK_TOOL_UA` |
| L7, L8 | not judged (exit 3) |

## Tests

`make deploy-test` runs `tests/deploy/test_lab_tools.sh`: both scripts against
a hand-built `/sys`, `/proc` and `/etc/default/sloth` (`LAB_SYS`, `LAB_PROC`,
`LAB_DEFAULT_SLOTH`) with stub tcpdump and ethtool, so no interface is opened.
