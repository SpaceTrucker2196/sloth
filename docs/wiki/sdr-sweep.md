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
start; `sloth-sdrsweep-auto.timer`, when the operator enables it, starts
the same service every 5 minutes. After each run the helper also keeps a
one-row record of it in `history/`, and the tab's range selector (last 3
scans, 1 h, 5 h, 12 h, 24 h) draws those records, one row per run, by
their time. sloth and slothweb never touch the radio.

**Sources**: `src/sdrsweep/main.c`, `src/sdrsweep/sdrsweep_dsp.{c,h}`,
`tests/test_sdrsweep.c`, `packaging/systemd/sloth-sdrsweep.{service,path}`,
`packaging/systemd/sloth-sdrsweep-auto.timer`,
`packaging/systemd/sloth-sdrsweep.sysusers.conf`,
`packaging/default/sloth-sdrsweep`, `web/src/web_spectrum.{c,h}`,
`web/tests/test_spectrum.c`, `web/ui/spectrum.{js,css}`, `Makefile`
("sloth-sdrsweep").

**Last updated**: 2026-11-15 (scheduled sweeps every 5 minutes, the
history directory and the tab's ranges; default cooldown 600 s to
150 s, slothweb's own 120 s floor); 2026-11-13 (first version).

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
  150 s by default, `SLOTH_SDRSWEEP_COOLDOWN`; slothweb refuses a press
  within 120 s of the last run's end whatever the cooldown says, so an
  operator's `COOLDOWN=0` does not hand the browser the receiver). A
  run is about a minute, so the button can hold the receiver at most
  about a third of the time. The helper applies
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
- `history/<started, whole seconds>.json` - one record per sweep run
  (below, "History").

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

## History

After writing `latest.json`, a sweep run (not a calibration) writes one
compact record of itself into `history/` (atomically, as above) and
prunes the directory (`sdrs_write_hist()`, `sdrs_hist_prune()`):

```
{"version":1,"kind":"history","mode":"sweep","complete":true,
 "started":1763040000.250,"ended":1763040048.900,"t_first":...,"t_last":...,
 "antenna":"Antenna A","rows":3,"floor":-95.2,"f_lo":500000,
 "f_hi":2000000000,"bin_hz":100000,"bins":19995,
 "quant":{"offset_db":-130.0,"step_db":0.5},
 "data":"<base64: the max over the run's rows, per display bin>",
 "peaks":[ ...the 64 strongest by peak SNR, in frequency order... ]}
```

`floor` is the median of the rows' floors. Records older than 25 h
(24 h and a margin) go, then the oldest while more than 400 are left;
only names of digits plus `.json` are ever touched. Size, computed from
a real run's `latest.json` on Beta-Site (2026-11-15, 19,995 bins, 400
peaks found): 33.8 KB a record (26.7 KB of base64, 6.8 KB of peaks),
so 288 runs a day is 9.7 MB and the 400-record cap 13.5 MB. A record
that cannot be written is said on stderr and does not fail the run.

## Scheduled sweeps

`sloth-sdrsweep-auto.timer` (installed, not enabled) starts
`sloth-sdrsweep.service` at :00, :05, :10, ... (`OnCalendar=*:0/5`,
`Persistent=false`). It starts the service itself rather than creating
slothweb's request file, so the run is exactly the Run button's: the
same account, sandbox and settings, and a site's drop-in in
`sloth-sdrsweep.service.d/` (the `Conflicts=` with a decoder sharing the
receiver and the `ExecStopPost=` that restarts it) applies to it too.
It does not pile up: a start while a run is going joins that run (a
oneshot), and a start inside the cooldown is refused by the helper with
exit 3, which the service counts as success (`SuccessExitStatus=3`).

The cooldown is why the default moved from 600 s to 150 s: it counts
from the end of one run to the next start, and a 5-minute period less a
run of 50-90 s leaves 210-250 s. Keep `SLOTH_SDRSWEEP_COOLDOWN` under
about 200 s with the timer enabled, or its runs are refused (each one
still briefly stops and restarts a service the drop-in names).
`tests/test_sdrsweep.c :: test_auto_timer` holds the default under the
period less 90 s.

The cost: a receiver shared with a decoder is taken about a minute in
every five, roughly 20% of the time (the owner accepted this for the
SDRplay shared with APRS, 2026-11-15).

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
- `GET /api/spectrum?range=R`, R one of `last3`, `1h`, `5h`, `12h`,
  `24h` (anything else 400 `unknown_range`): the status, then `"range"`,
  `"runs"`, `"skipped"`, and `"sweep"`: a document shaped like
  `latest.json` with `"mode":"history"`, `"from"` and `"to"` (the
  window), `"pool"`, one row per run oldest first (`t` its start,
  `ended`, `floor`, `rows`, `complete`, `data`) and the newest run's
  peaks; `null` when no record could be read. `last3` is the three
  newest records whatever their age, one max-hold row each (not their
  full sweep rows: a record keeps one row, which is what keeps a day of
  them at ~10 MB; until there are records the tab falls back to
  `latest.json`, whose rows are the latest run's sweeps). The other
  ranges are the records that started in the last R, read newest first,
  at most 600. Every record is read whole by the strict reader: a
  member twice, a bad number, base64 that is not exactly `bins` bytes, a
  link, a non-regular file, over 512 KiB, version not 1: skipped and
  counted in `skipped`, never fatal. The newest good record sets the
  grid; one on another span (the operator changed it) is skipped. A
  record must be in the window by its name and by its own `started`.
  Long windows are max-pooled: k neighbouring bins become one, k =
  ceil(runs x bins / 1.5 M) (`web_spectrum_pool()`), so with 19,995
  bins 1 h and 5 h are unpooled, 12 h is in pairs (200 kHz), 24 h in
  fours (400 kHz) and the body stays under about 2 MB (measured: 24 h,
  273 records, 1.85 MB in 73 ms; 12 h 1.75 MB; 5 h 1.29 MB). Max, not
  mean: a narrow carrier survives pooling and only gets wider. The
  answer without `range` is unchanged.

The tab: the run button (with a confirmation that the receiver is taken
for about a minute, which pauses APRS for that minute on a sensor where
the two share it) and the run's state; the range selector (last 3
scans by default, kept per browser as `slothweb.v1.spectrum.range`); the
waterfall. In 1 h to 24 h the rows sit at their start time along the
depth axis, which is labelled HH:MM at round intervals at least a label
apart, and a stretch with no run (longer than 1.8 times the usual
spacing, the window's edges included) is hatched on the floor and
dashed on the time axis with "no runs". The depth the rows take grows
and the ridge height shrinks with the row count (3 rows are tall
ridges, 288 a terrain); rows are painted back to front, each column
down to its own baseline so nearer ridges hide what is behind them, and
past 24 rows the column bodies darken under a bright cap and only every
few ridges get an outline, so a dense range does not turn into a
hairball. The picture is drawn once into an offscreen canvas and the
hover line and drag box over a copy of it. Hover names the run under
the pointer (the frontmost whose painted column covers it), its time,
sweep count and floor. The waterfall has a log/linear
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
- It does not run on a schedule unless the operator enables
  `sloth-sdrsweep-auto.timer`.
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
