---
source_url: https://www.aircrack-ng.org/doku.php?id=airbase-ng
retrieved: 2026-11-11
topics: [karma, airbase-ng, aircrack-ng, probe-response, rogue-ap]
alert_kinds: [ALERT_TYPE_KARMA_PROBE_FORGE]
citation: aircrack-ng project documentation, "airbase-ng" (wiki page, retrieved 2026-11-11)
---
# airbase-ng: answering every directed probe is one flag

The tool documentation behind `KARMA_PROBE_FORGE` (#187 S2): the
behaviour the 2005 KARMA paper built into a patched driver is a
command-line option of a maintained tool. Quotations are from the
airbase-ng page of the aircrack-ng documentation, retrieved 2026-11-11.

## The options that produce the signal

- **`-P`** (respond to all probes): "This causes the fake access point
  to respond to all probes regardless of the ESSIDs specified." And:
  "Without -P, the old behavior of ignoring probes for non-matching
  ESSIDs will be used."
- **`-C <seconds>`**: "The -P option must also be specified in order to
  use this option." "The wildcard ESSIDs will also be beaconed this
  number of seconds", i.e. "beacon broadcasting of the ESSIDs seen by
  the directed probes."
- **`-e <ESSID>`** limits the answered names: "To limit the supported
  ESSIDs, you can specify '-e <ESSID>' to add an ESSID to the list of
  allowed ESSIDs".
- With no ESSID set, "the beacon will contain 'default' as ESSID, but
  accept all ESSIDs in association requests."

## How that maps to what sloth sees

- `airbase-ng -P` alone: one beaconed name ("default" or the `-e` name)
  and Probe Responses naming whatever stations ask for. KARMA_AP cannot
  see this radio — its beacon history holds one SSID — and
  `KARMA_PROBE_FORGE` is built for exactly it.
- `airbase-ng -P -C N`: the answered names are then *beaconed* too, for
  N seconds. A name that has been beaconed is no longer counted as
  forged (`karma_forged_ssids()` checks the BSSID's whole beacon
  history), so this mode reads as `KARMA_AP`'s beacon fan-out instead,
  and as `KARMA_PROBE_FORGE` only for the answers given before the
  beacon for that name was heard. When both hold on one BSSID the
  forge alert is CRIT (the issue's S1 + S2 joint rule).
- `-y` ("the fake AP will not respond to broadcast probes ... It will
  only respond when the specific AP is uniquely requested") changes
  nothing here: only answers to directed probes are recorded anyway.

## What it does not say

The page gives no timing, rate or count for these answers, so nothing
in the rule's thresholds rests on it. It establishes that the behaviour
is a standard option of a widely packaged tool, which is why a passive
sensor should expect to meet it.
