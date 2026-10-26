---
source_url: https://www.itu.int/rec/R-REC-P.1238/en
retrieved: 2026-10-26
topics: [rssi, distance, path-loss, log-distance, indoor-propagation, tx-power, tpc, ble, proximity, data-point]
citation: ITU-R P.1238-10 (08/2019) eq. (1), Tables 2 and 4; ITU-R P.1238-13 (09/2025) §3.1 Table 2; Bluetooth Core Specification Supplement v11 Part A §1.5 (TX Power Level); Bluetooth Core v6.0 Vol 4 Part E §7.7.65.13 (LE Extended Advertising Report, TX_Power); IEEE 802.11-2020 §9.4.2.16 (TPC Report) and §9.4.2.8 (Country); Leith & Farrell, arXiv:2006.06822 (2020); Zafari, Gkelias & Leung, arXiv:1709.01015
---
# Estimating distance from received signal strength

What sloth's `src/rf_distance.c` rests on, source by source, and how far
the estimate can be trusted. It is a **data point**, not a detector: no
alert rule reads it. The summary of the evidence below is that an
RSSI-derived distance is an order-of-magnitude figure indoors — walls,
bodies and reflections move the received level by as much as a tenfold
change in distance does — so sloth reports it as a band with an
interval, never as a location.

Every source here was read first-hand on the retrieval date above,
except the IEEE 802.11 clauses, which are paywalled: their field
semantics are as already summarised, from the standard, in
`research/ieee/802.11-2020-11.8-spectrum-management.md` and
`research/ieee/802.11d-country-element.md`, and were not re-read for
this document. Rappaport's *Wireless Communications* ch. 4, the usual
textbook citation for the log-distance model, was not available to read
and is deliberately not cited; P.1238 states the same model with
measured coefficients, which is the part sloth needs.

## The model: ITU-R P.1238

ITU-R P.1238-10 (08/2019) §3.1, equation (1), gives the site-general
indoor basic transmission loss as

    L_total = L(d0) + N log10(d / d0) + Lf(n)        dB

with `N` the distance power loss coefficient, `d` the separation in
metres (d > 1 m), `d0` = 1 m, `L(d0) = 20 log10 f − 28` for `f` in MHz
(free-space loss at 1 m), and `Lf(n)` a floor-penetration term that is
0 on the same floor. sloth assumes the same floor — it has no way to
know otherwise — and solves for `d`:

    d = 10 ^ ((P_tx − RSSI − (20 log10 f − 28) − offset) / N)

where `P_tx − RSSI` is the measured path loss and `offset` is 0 unless
the operator calibrated (below). The formula in the issue text,
`10^((P_tx − RSSI)/(10 n))`, omits `L(d0)`; at 2.4 GHz that term is
about 40 dB, which would overstate every distance by a factor of
roughly 10^(40/28) ≈ 27, so the implementation keeps it.

### The coefficients sloth defaults to (P.1238-10 Table 2)

| Band | Residential | Office | sloth default `N` |
|---|---|---|---|
| 1.9 GHz | 28 | 30 | — |
| 2.4 GHz | 28 | 30 | **28** (Wi-Fi 2.4 GHz and BLE) |
| 5.2 GHz | 30 (apartment) / 28 (house) | 31 | **30** |
| 5.8 GHz | — | 24 | — |
| 6 GHz | no row | no row | **30**, the 5.2 GHz residential value, extrapolated |

The residential column is the default because a sloth sensor is most
often in a home or small office; `--tune rf.path_loss_n_{2g,5g,6g}`
(×10, so 28 is N = 2.8 × 10) moves each. P.1238 itself: "For the
various frequency bands where the power loss coefficient is not stated
for residential buildings, the value given for office buildings could
be used."

### Shadow fading — the model's own error (P.1238-10 Table 4)

The recommendation states the loss is log-normal about the median with
these standard deviations (dB): 1.8–2 GHz residential **8**, office 10;
5.2 GHz office **12**; 5.8 GHz office 17. There is no 2.4 GHz row;
sloth uses the 1.8–2 GHz residential 8 dB for 2.4 GHz and BLE, and the
5.2 GHz office 12 dB for 5 and 6 GHz (no residential row there).

At N = 28, an 8 dB one-sigma error is a factor of 10^(8/28) ≈ 1.9 in
distance each way: a "5 m" estimate's one-sigma range is about 2.6–9.7
m. At N = 30 and 12 dB it is a factor of 2.5. These are the intervals
`rf_distance.c` reports, widened further by the spread of the samples
and, when the transmit power was assumed, by an assumed-power term.

### The in-force edition changed the form

P.1238-13 (09/2025), the edition in force, replaces the sub-6 GHz rows
of the old Table 2 with a site-general fit `Lb = 10α log10 d + β +
10γ log10 f` (§3.1 Table 2): office NLoS α = 2.39, σ = 5.01 dB, valid
for 4–30 m; office LoS α = 1.47, σ = 3.68 dB, 2–27 m. It keeps the
classic N-form as a site-specific model for mmWave only. sloth uses the
P.1238-10 N-form because it gives residential coefficients per band,
which -13 no longer does; -13's NLoS office fit (equivalent N ≈ 24) is
within the range the `--tune` bounds allow.

Two general observations from both editions (P.1238-13 §3.2) matter for
how the estimate is worded: line-of-sight paths have N around 20,
"propagation around obstacles and through walls adds considerably to
the loss which can increase the power distance coefficient to about 40",
and corridors can be below free space (around 18). The same distance
can therefore present a 20 dB range of path loss depending on what is
in the way.

## Where `P_tx` comes from

What a device says about its own transmit power, best first. Every
source is carried in the record as `est_ptx_source`.

- **802.11 TPC Report element** (tag 35, IEEE 802.11-2020 §9.4.2.16):
  the transmit power the AP used for the frame carrying it, signed dBm.
  `tpc_report`. This is the one Wi-Fi source that is a statement about
  the frame actually received.
- **802.11 Country element** (tag 7, §9.4.2.8), subband triplet
  covering the AP's channel: the regulatory maximum transmit power,
  less the Power Constraint element's local reduction (tag 32,
  §9.4.2.13) when one is present. This is a **ceiling**, not what the
  AP transmits, so the distance it yields is an upper bound and the
  source is `country_max`. Subband triplets step one channel number at
  a time below channel 15 and four above it (the 5 GHz 20 MHz grid);
  that step is the common convention and was not re-read in the clause.
  Because the true power can only be lower, the interval is widened by
  the assumed-power term on the **low side only**, and a ceiling above
  the assumed AP default (20 dBm) is not used at all: US 2.4 GHz allows
  30 dBm where an AP typically sends about 20, and estimating at 30
  would put an AP really at 27 m at 62 m. Never used on 6 GHz, where
  the power limit rides the Transmit Power Envelope instead
  (`research/ieee/802.11d-country-element.md`: "6 GHz is out of
  scope here") and the
  triplets' channel steps are the 2.4 / 5 GHz ones; a 6 GHz AP without
  a TPC Report takes the assumed default until TPE is parsed.
- **BLE extended advertising report TX_Power** (Core v6.0 Vol 4 Part E
  §7.7.65.13): "Range: −127 to +20, Units: dBm; 0x7F Tx Power
  information not available." The controller reports the TxPower field
  of the PDU's extended header (Vol 6 Part B §2.3.4.7). `ble_ext_tx_power`.
- **BLE TX Power Level AD type** (Core Specification Supplement v11 Part
  A §1.5): "indicates the transmitted power level of the packet
  containing the data type. The TX Power Level should be the radiated
  power level", sint8 −127..+127 dBm. The supplement itself gives the
  use: "pathloss = Tx Power Level − RSSI", and says of it:
  "Unfortunately, due to fading and varying antenna, circuit, and chip
  characteristics, these resulting pathloss values will have
  uncertainty. Some of the uncertainty (for example, due to fading) may
  be able to be removed if multiple packets are received from the same
  device." `ble_ad_tx_power`.
- **Assumed** — nothing announced. AP 20 dBm, Wi-Fi client 15 dBm, BLE
  0 dBm. These are sloth's assumptions, not cited figures, which is why
  the source reads `assumed` and the interval is widened by a further
  6 dB (also a sloth choice: the spread between a low-power client and
  a full-power AP is of that order).

A probe request carries none of these elements, so a probe client's
estimate is always `assumed`. The (re)association-response and EAPOL M3
frames behind an `assoc` row are sent by the AP, so that row's estimate
is of the **AP's** distance from the sensor, not the client's.

## Measured error indoors

**Leith & Farrell (2020), arXiv:2006.06822**, measured BLE RSSI between
handsets in real settings for contact tracing. Outdoors, in the open,
with fixed handsets at each distance for ten minutes: "the standard
deviation is around 5dB" for a Pixel 2 pair and "somewhat higher at
around 10dB" for a Samsung Galaxy A10 pair, whose mean level also sat
lower — so two handset models at the same distance read differently.
Rotating a person carrying one handset at 1 m: the signal "varies by
around 20dB as the person rotates". Handset orientation at 1 m: "a
change in received signal strength of around 20dB". A 15 cm blockwork
wall "attenuates the signal by around 20dB"; a plasterboard stud wall
very little. Their summary: "the received signal strength need not
decrease with increasing distance", and "this data suggests that we
cannot reliably distinguish whether people are located less than 2m of
each other" in one walking scenario.

At N = 28, 20 dB is a factor of 10^(20/28) ≈ 5 in distance. **That is
the honest typical error of an RSSI distance indoors: a factor of two
under good conditions, a factor of five when a body, a wall or an
antenna orientation intervenes — and sloth cannot see which.**

**Zafari, Gkelias & Leung, arXiv:1709.01015** (§II-A), a survey: RSS
ranging "suffers from poor localization accuracy (especially in
non-line-of-sight conditions) due to additional signal attenuation
resulting from transmission through walls and other big obstacles and
severe RSS fluctuation due to multipath fading and indoor noise".
Filtering or averaging mitigates the fluctuation; it does not remove the
wall.

## The robust statistic

Because the per-packet fluctuation is ±5 dB or more even line-of-sight
(Leith & Farrell §II), sloth never estimates from one sample when it has
more: it takes the **median of the last K samples** (`--tune
rf.median_k`, default 8, at most 16) inside a 60 s window, and the
**MAD × 1.4826** of those samples as their spread (the normal-consistent
robust standard deviation). The reported interval is the model sigma
(P.1238 Table 4), the sample spread and the assumed-power term combined
in quadrature, converted to metres through the same `N`. One sample
gives an estimate with zero spread, not a refusal; the band and the
interval still carry the model's own error.

An RSSI of 0 dBm, or a sample the radio marked not available (BLE
0x7F), yields **no estimate**, never a 1 m one: 0 is what sloth's Wi-Fi
rows already store for "unseen".

## Bands

| Band | Range | Basis |
|---|---|---|
| immediate | < 1 m | the iBeacon proximity zone "immediate (<1m)", as described by Zafari et al. §III-B |
| near | 1–3 m | iBeacon "near (1-3m)", same source |
| room | 3–10 m | sloth's cut: about one room, and the scale at which the 8 dB interval (×/÷1.9) still separates it from "near" and "building" |
| building | 10–30 m | 30 m is the upper end of P.1238-13 Table 2's office NLoS fit range (4–30 m) |
| far | > 30 m | outside every indoor range P.1238 fits; the model is extrapolating |

A band changes only when the estimate is past its boundary by a margin
and stays past it for 10 s — sloth's hysteresis, so a device sitting on
a boundary does not alternate. The margin is 3 dB or two standard
errors of the median (1.2533 × spread / √samples), whichever is larger,
converted to metres through `N`. A fixed 25 % (about 2.7 dB at N = 28)
was not enough: the median of eight samples at σ 4–6 dB crossed it for
a stationary advertiser several times a minute, and a seeded-noise hour
in `tests/test_rf_distance.c` (10 advertisements/s at σ 6 dB and 1/s at
σ 8 dB, the mean on a boundary) now stays within four records of the
300 s heartbeat. These constants are sloth's, sized by that test, not cited.

The band is what enters the JSONL change-only signature, never raw
metres (`agents/AGENTS.md`, "Change-only emission must bucket its
continuous values"). The trend is written but not signed: a slope over
a few medians enters and leaves approaching / leaving under ordinary
noise one to several times a minute for a device that is not moving
(about 260 trend changes an hour in the 10/s, σ 6 dB case above).

## Trend

Approaching / steady / leaving is the least-squares slope of the
median-RSSI series (one point per ≥ 2 s, 30 s window, at least four
points spanning ≥ 6 s), in dB per 10 s. Enter approaching at +3 dB/10 s
and leave it below +1.5; leaving is the mirror. Those thresholds are
sloth's, not cited: they sit above the ±5 dB per-packet noise only
because the series is of medians. A person turning round moves the
level by 20 dB (Leith & Farrell §III-C), which this reads as a
trend — another reason the output is hedged.

## Calibration

`--tune rf.ref_dist_dm=N` (decimetres) with `--my-bssid` states that
the operator's own AP is N/10 m from the sensor. sloth then takes that
AP's measured path loss, subtracts what the model predicts at that
distance, and applies the difference (bounded ±20 dB) as `offset` to
every Wi-Fi estimate in the same band — absorbing the sensor's antenna
and receive-chain gain and any error in the AP's announced or assumed
power. It is not applied to BLE, whose controller is a different
receiver. One reference point corrects the offset, not `N`, and not the
walls between the sensor and anyone else.

## Privacy

This is an estimate of a third party's physical proximity. sloth emits
only the quantised metres, the band, the trend and the power source on
records that already carried the RSSI it came from; nothing new is
exported, persisted or derived beyond that.

## Related

- `docs/wiki/rf-distance.md` — the operator-facing page.
- `research/ieee/802.11-2020-11.8-spectrum-management.md` — TPC Report
  and Power Constraint.
- `research/ieee/802.11d-country-element.md` — the Country element.
