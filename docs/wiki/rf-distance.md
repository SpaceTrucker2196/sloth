---
name: rf-distance
description: The RSSI distance data point - an estimate from signal strength of how far a transmitter is from the sensor, with its model, its sources of transmit power, its error, and what it is not
type: concept
---

# Distance from signal strength (a data point)

**Summary**: sloth turns the received signal strength of an AP, a
probing client, an association or a BLE advertiser into an **estimate
from signal strength** of how far the transmitter is from the sensor:
metres with an interval, a band (immediate / near / room / building /
far) and a trend (approaching / steady / leaving). Walls and reflections
dominate, and **it is not a location** — one sensor has no bearing, and
the same reading fits a device 3 m away through open air and one 1 m
away behind a body or a block wall. It is a data point and nothing else:
no alert rule reads it.

**Sources**: `src/rf_distance.c`, `src/rf_distance.h`,
`include/rf_track.h`, `research/papers/rssi-distance-estimation.md`
(every number below, cited), `tests/test_rf_distance.c`.

**Last updated**: 2026-10-26 (owner request: "use rf signal strength to
estimate distance as a data point"; sloth side, slothweb display later).

## The model

ITU-R P.1238-10 eq. (1), the site-general indoor loss on one floor,
solved for distance:

    d = 10 ^ ((P_tx − RSSI − (20 log10 f − 28) − offset) / N)

`f` is the channel's centre frequency in MHz (2440 MHz for BLE),
`20 log10 f − 28` the free-space loss at 1 m, `N` the distance power
loss coefficient. Defaults are P.1238-10 Table 2's residential values:

| Radio | `N` (×10) | Knob | Shadow-fading σ (P.1238-10 Table 4) |
|---|---|---|---|
| Wi-Fi 2.4 GHz and BLE | 28 | `rf.path_loss_n_2g` | 8 dB (1.8–2 GHz residential; no 2.4 row) |
| Wi-Fi 5 GHz | 30 | `rf.path_loss_n_5g` | 12 dB (5.2 GHz office; no residential row) |
| Wi-Fi 6 GHz | 30 | `rf.path_loss_n_6g` | 12 dB (no 6 GHz row; the 5 GHz values) |

An office building is closer to N = 30–31, line of sight to 20, a path
through several walls to 40 (P.1238-13 §3.2). Moving `N` moves every
estimate; the knobs are bounded 16..60.

## Where P_tx comes from

Shown in the record as `est_ptx_source`, best first:

| Source | Rows | What it is |
|---|---|---|
| `tpc_report` | AP | the 802.11 TPC Report element: the power the AP used for that frame |
| `country_max` | AP | the Country element's ceiling for the channel, less Power Constraint. **An upper bound** on the power, so the distance is an upper bound too |
| `ble_ext_tx_power` | BLE | TX_Power from the LE Extended Advertising Report header |
| `ble_ad_tx_power` | BLE | the advertiser's TX Power Level AD structure |
| `assumed` | any | nothing announced: AP 20 dBm, Wi-Fi client 15 dBm, BLE 0 dBm. sloth's assumption, and the interval is widened by 6 dB for it |

A probe request names no power, so probe-client estimates are always
`assumed`. An **association row's estimate is the AP's distance**, not
the client's: the (re)association response and EAPOL M3 behind it are
frames the AP sent.

## The RSSI that goes in

The median of the last `rf.median_k` samples (default 8, at most 16)
within 60 s of the newest, so one fade or one reflection does not move
the figure. An RSSI of **0** — what sloth's Wi-Fi rows store for
"unseen" — or the HCI's "not available" is **no sample**, and a row
with no usable sample has **no estimate**, never a 1 m one. A row whose
channel is unknown has no estimate either: computing one at a guessed
frequency would be a second guess on top of the first.

## How far to trust it

The interval shown on the detail panes is the model's σ, the samples'
own spread (MAD × 1.4826) and the assumed-power term combined, then
converted through `N`. At 2.4 GHz with an assumed power that is a
factor of about 2.3 each way: a "27 m" estimate means roughly 12–62 m.

Published measurements are worse than the model alone suggests. Leith
and Farrell (arXiv:2006.06822) measured BLE between phones: a body
turning round changed the level by about 20 dB, the phone's orientation
by about 20 dB, a 15 cm block wall by about 20 dB, and two phone models
at the same spot read differently. 20 dB at N = 28 is a factor of five
in distance. Read the band, not the metres, and treat a change of band
as "something moved or something came between", not as a measurement.

## Bands and trend

| Band | Range | Basis |
|---|---|---|
| immediate | < 1 m | iBeacon's zone, per Zafari et al. (arXiv:1709.01015) |
| near | 1–3 m | the same |
| room | 3–10 m | sloth's cut |
| building | 10–30 m | 30 m: the top of P.1238-13's office NLoS fit range |
| far | > 30 m | outside every indoor range P.1238 fits |

A band changes only once the estimate is 25 % past the boundary, so a
device sitting on one does not flicker. The trend is the slope of the
median RSSI over 30 s (one point per 2 s, at least four spanning 6 s):
approaching at +3 dB per 10 s, held until it falls below +1.5; leaving
mirrors it. Those thresholds are sloth's, not cited.

## Calibration

`--my-bssid AA:BB:… --tune rf.ref_dist_dm=25` says the operator's own AP
is 2.5 m from the sensor. Each poll sloth takes that AP's measured path
loss, compares it with what the model predicts at 2.5 m, and applies the
difference (at most ±20 dB; more is refused as not a gain error) to
every Wi-Fi estimate in the same band. It absorbs the sensor's antenna
and receive gain and any error in the AP's power. It corrects the
offset, not `N`, and not the walls between the sensor and anyone else.
It is never applied to BLE, whose controller is a different receiver.
A calibrated estimate says so (`cal` on the detail panes).

## Where it shows

| Place | Form |
|---|---|
| [7] Probe, [b] Beacons | a `Dist (est)` column, `~27m bldg ↘` (↘ approaching, → steady, ↗ leaving, blank unknown) |
| [*] BLE | `~27m↘` at 100 columns, the full form from 106 |
| [w] Assoc | `AP~m`, the short form: the AP's distance |
| [g] Devices | the full or short form from 108 columns; at 100 the name column keeps its 15 cells and the estimate is on the detail page |
| Detail panes | `~4.5m (2.3-8.8m) room steady, Ptx 20 assumed` |
| JSONL | `est_dist_m` (quantised), `est_dist_band`, `est_dist_trend`, `est_ptx_source` — [[jsonl-schema]] |

## Privacy

This is an estimate of a third party's physical proximity. It is
exported only as the four fields above, quantised (0.5 m below 10 m,
1 m below 100 m, 10 m above), on records that already carried the RSSI
it was computed from. It is not persisted to `--db`, it identifies no
one, and a change-only record is written for a change of band or of an
approaching / leaving trend, never for a change of metres.

## Related pages

- [[jsonl-schema]] — the four fields and where they appear.
- [[cli-reference]] — the five `rf.*` knobs.
- [[ble]] — the BLE advertiser rows.
- [[beacon-detection]] — the beacon table the AP rows come from.
- [[research-corpus]] — `research/papers/rssi-distance-estimation.md`.
