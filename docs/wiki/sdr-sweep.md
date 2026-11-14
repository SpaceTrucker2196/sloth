---
name: sdr-sweep
description: The SDR sweep - sloth-sdrsweep tunes a receiver the operator dedicated across 0.5-2000 MHz for about a minute (SoapySDR; built for the SDRplay RSPdx-R2) and writes the max-hold spectrum and a peak list; slothweb's Spectrum tab draws it as an isometric waterfall with band and peak labels and has the one button that asks for a run
type: reference
---

# SDR sweep (`sloth-sdrsweep`, the Spectrum tab)

**Summary**: `sloth-sdrsweep` is a separate helper, like
`sloth-ble-scan`: run by `sloth-sdrsweep.service` (a oneshot under its
own account), it opens an SDR through SoapySDR, sweeps it from 0.5 to
2000 MHz in 6 MHz steps for about 60 seconds (each whole sweep is one
time row, three to five a run), and writes
`/var/lib/sloth-sdrsweep/latest.json`: a max-hold level per 100 kHz
display bin per row, each row's noise floor, and a list of peaks found
at the FFT's full resolution (about 1 kHz), each labelled when it sits
on the receiver's own 24 MHz clock harmonics or on a spur a calibration
run found with no antenna. slothweb's Spectrum tab reads that file
(`GET /api/spectrum`) and draws it as an isometric waterfall -
frequency across, time receding diagonally, height and colour the
level - with a US band-allocation strip and labels on the strongest
peaks. Its "Run 1-min sweep" button is `POST /api/spectrum/run`, which
creates an empty request file that `sloth-sdrsweep.path` turns into a
start. sloth and slothweb never touch the radio.

**Sources**: `src/sdrsweep/main.c`, `src/sdrsweep/sdrsweep_dsp.{c,h}`,
`tests/test_sdrsweep.c`, `packaging/systemd/sloth-sdrsweep.{service,path}`,
`packaging/systemd/sloth-sdrsweep.sysusers.conf`,
`packaging/default/sloth-sdrsweep`, `web/src/web_spectrum.{c,h}`,
`web/tests/test_spectrum.c`, `web/ui/spectrum.{js,css}`, `Makefile`
("sloth-sdrsweep").

**Last updated**: 2026-11-13 (first version).

## Why it is consistent with MISSION.md §2

- **Receive only.** The helper opens the device, sets the receive
  chain (antenna port, sample rate, IF bandwidth, a fixed gain) and the
  tuner frequency, and reads a receive stream. It sets up no transmit
  stream and writes nothing to the device; the transmit direction and
  the stream-write call are not named in `src/sdrsweep/main.c`, and
  `tests/test_sdrsweep.c :: test_helper_never_transmits` fails if they
  ever are. Nothing it does puts a frame on any network.
- **It tunes a receiver the operator dedicated.** §2 allows sloth to
  "tune a receiver already in [its mode], and only its own"; here the
  operator names the device in `/etc/default/sloth-sdrsweep`, and on a
  host where another service holds that receiver the operator writes the
  drop-in that hands it over ([[deployment]] §9). sloth itself still
  drives no radio: the helper is a separate binary that neither `sloth`
  nor `slothweb` links (`test_helper_is_not_linked_into_sloth_or_slothweb`),
  as `sloth-ble-scan` and `sloth-monitor-up` are.
- **Opt-in and announced.** `make install-service` installs the units
  and never enables them; until the operator enables
  `sloth-sdrsweep.path`, the button queues a request nothing acts on and
  the tab says so. A run logs on stderr (the journal) what it opens,
  which port, the gain and the span, before it tunes anything.
- **The browser cannot steer it.** The request file is empty and never
  read; the POST's body is ignored; the helper's settings are the
  operator's file and its unit's command line. The POST passes the same
  gate as every slothweb write (Origin equal to Host, Sec-Fetch-Site,
  the per-peer bucket when there is a store, the Content-Type), the peer
  allow list before that, `--web-read-only` removes it, and an agent
  header is refused: the radio is the operator's.
- **It cannot be used to hog the radio.** One run at a time (409), and
  none within the cooldown after the last (429 with `Retry-After`;
  10 minutes by default, `SLOTH_SDRSWEEP_COOLDOWN`). The helper applies
  the cooldown itself too, from its own `status.json`, for a start that
  did not come through slothweb, and fails closed: a `status.json` that
  is there but unreadable or not its own (no `state`) refuses the run
  (exit 3) instead of reading as "no previous run"; only a missing file,
  the first run, passes.

This is the second control slothweb has (the first is the triage
write surface, docs/web-frrs-spec.md); the owner approved it on
2026-11-13 for this purpose and no other.

## The sweep

| Setting | Default | Why |
|---|---|---|
| device | `driver=sdrplay` | SoapySDRPlay3; the args *string* form, because the key/value form returned "no match" for it (measured in the Python bindings) |
| antenna | `Antenna A` (`Antenna B` with `--calibrate`) | slothweb shows it, so a reader knows why bands far from the antenna's design look empty |
| gain | `IFGR=40,RFGR=3`, gain mode off | fixed, so rows and runs compare |
| span | 0.5-2000 MHz | clamped to the device's tuning range; the RSPdx refuses a 2001.5 MHz centre, so the last step's centre is clamped to 2000 MHz and the bins it shares with the step before are counted once |
| sample rate, bandwidth | 8 MS/s, 7 MHz | |
| kept per step | the central 6 MHz, less ±25 kHz around DC | the band edges roll off and the centre carries the LO's DC spike |
| FFT | 8192 points, Hann window: 976.6 Hz bins | |
| frames per step | 16 (one 16 ms capture), after 30 ms of samples discarded since the retune | 16 frames make the frame mean steady enough for the +6 dB test (below); 4 would pass several hundred noise-only bins a sweep |
| duration | 60 s of whole sweeps | each sweep is one row; a new one starts only if it should end inside the duration |

334 steps a sweep. The Python prototype took 43 s a sweep with three
captures of 24 frames a step; one capture should give 15-20 s.

### Levels

dBFS with a full-scale complex tone at 0: the window's coherent gain is
removed (`- 20 log10(sum w)`), so the number does not depend on the FFT
size. Each step keeps, per bin, the mean power over its frames and the
max-hold. The step's floor is the median of its kept bins' mean - a few
carriers in 6 MHz do not move it, and it needs no noise model.
`tests/test_sdrsweep.c` checks both against first principles: a tone of
amplitude A reads 20 log10 A dBFS at its bin; complex white noise of
per-sample power s2 reads 10 log10(s2 · 1.5 / N) (Hann: sum w² = 3N/8).

### Detection

At full resolution across the whole run, a bin is a signal when its
frame-mean level averaged over the rows stands 6 dB above its step's
floor, or its max-hold stands 16 dB above in any row (both thresholds
from the prototype on this receiver). Signal bins within 50 kHz of each
other are one peak (the prototype clustered with gaps of four bins and
merged clusters within 50 kHz; the second test subsumes the first). A
peak's frequency is its strongest bin's; it carries its width, the
largest average and peak SNR among its bins, its strongest level in
dBFS, and the number of rows it met a threshold in. The 400 strongest
by peak SNR are kept.

### Labels

- **`clock harmonic?`**: within 6 kHz of a multiple of 24 MHz above
  20 MHz. The RSPdx-R2's 24 MHz reference shows at 1176, 1224, ...,
  1944 MHz near -60 dBFS with nothing on the port (measured
  2026-11-13). A guess the operator can rule out; nothing is removed.
- **`internal`**: `sloth-sdrsweep --calibrate` sweeps once with the
  unconnected port (`Antenna B`) and writes `spurs.json`; a later run's
  peak within 6 kHz of a calibration peak and no more than 6 dB above
  its **absolute** level is the receiver's own. Not by SNR: a strong
  outside signal leaks into the unconnected port and raises its floor,
  which made the prototype's SNR comparison wrong.

## Output

In `/var/lib/sloth-sdrsweep` (0755, files 0644, written atomically:
a temporary file, fsync, rename):

- `latest.json` - the last run; the one before is `prev.json`.
- `status.json` - one line: `state` (`running`, `done`, `stopped`,
  `failed`), `mode`, `pid`, `started`, `updated` (at least once a second
  while sweeping), `ended` and `next_allowed` once the device was opened,
  `cooldown`, `row`, `step`, `steps`, `antenna`, and `error` when failed.
- `spurs.json` - the calibration, same format as `latest.json`.

`latest.json`:

```
{"version":1,"mode":"sweep","complete":true,"started":1763040000.250,
 "ended":1763040061.900,"device":"driver=sdrplay","driver":"sdrplay",
 "hardware":"RSPdx-R2","serial":"...","antenna":"Antenna A",
 "gain":"IFGR=40,RFGR=3","sample_rate":8000000,"bandwidth":7000000,
 "keep_hz":6000000,"dc_guard_hz":25000,"nfft":8192,"frames":16,
 "duration":60,"calibrated":false,"steps":334,"f_lo":500000,
 "f_hi":2000000000,"bin_hz":100000,"bins":19995,"fft_bin_hz":976.562,
 "quant":{"offset_db":-130.0,"step_db":0.5},
 "rows":[
 {"t":1763040000.300,"floor":-101.5,"data":"<base64 of 19995 bytes>"},
 ...],
 "peaks":[
 {"freq_hz":144390000,"width_hz":11719,"snr_avg":9.5,"snr_peak":31.0,"dbfs":-61.5,"rows":3,"note":""},
 {"freq_hz":1176000000,"width_hz":1953,"snr_avg":30.1,"snr_peak":31.2,"dbfs":-60.0,"rows":4,"note":"clock harmonic?"},
 ...]}
```

A row's `data` is one byte per display bin, `q = round((dBFS + 130) · 2)`
clamped to 0..255 (dBFS = q/2 - 130; 0 also means no data), the
max-hold of every FFT bin in that 100 kHz. `complete` is false when a
signal stopped the run early (the rows completed are kept; a cut row is
kept only when it is the only one). Each peak is on a line of its own,
which is what the calibration reader parses.

## slothweb

- `GET /api/spectrum`: the status (`installed`, `state`, `running`,
  `queued`, `queued_since`, `can_run`, `why_not`, `retry_after`, and the
  `status.json` members), then `"sweep"`: `latest.json`, re-serialised
  by a strict reader (every string through slothweb's escaper, numbers
  checked against RFC 8259's grammar, eight levels deep at most), or
  `null` with `"sweep_error"`: `too_large` (over 4 MiB), `invalid` or
  `unreadable` (not a regular file, a link). `?status=1`: the status
  alone, which the tab polls while a run is queued or running. Under the
  Local scope the sweep is out of scope (`"out_of_scope":true`).
- `POST /api/spectrum/run`: `202 {"queued":true}`, or `409 running` /
  `409 queued`, `429 cooldown` with `Retry-After`, `503 not_installed`
  (no state directory) or `503 request_failed` (the request file could
  not be created). GET there is `405 Allow: POST`.
- `--spectrum-dir DIR` (default `/var/lib/sloth-sdrsweep`) and
  `--spectrum-request PATH` (default `/run/slothweb/sdrsweep.request`,
  inside the unit's `RuntimeDirectory`), both absolute.

The tab: the run button (with a confirmation that the receiver is taken
for about a minute, which pauses APRS for that minute on a sensor where
the two share it) and the run's state; the waterfall with a log/linear
frequency axis (log by default), zoom presets (Full, HF 0.5-30, VHF
30-300, UHF 300-1000, L-band 1000-2000) and drag-to-zoom (double-click
for Full); a band-allocation strip (the US table, 47 CFR 2.106,
simplified, for orientation only: the sensor may be elsewhere); labels
on the N strongest peaks in view (frequency and band; `?` dashed for a
clock harmonic, `int` dim for an internal spur); a tooltip with
frequency, level, SNR over the row's floor, band and the nearest peak;
and the peak list, the canvas's words, for every peak in view. The
configured antenna is named on the tab: a 2 m/70 cm antenna makes HF and
L-band look empty, and the reader should know why.

## What it does not do

- It does not demodulate, decode or record anything; a level per bin is
  all it keeps.
- It does not run on a schedule. A timer unit could start it; none
  ships.
- It does not share the receiver gracefully by itself: a drop-in stops
  the service that holds it and starts it again afterwards
  ([[deployment]] §9).
- The band table is not a regulatory reference and is not localised.

## Related pages

- [[deployment]] - §9, installing the helper and the units, and the
  drop-in for a receiver another service holds.
- [[slothweb]] - the routes, among the others.
- [[aprs]] - the decoder that shares the receiver on the reference host.
- [[ble]] - `sloth-ble-scan`, the other helper built the same way.
