/* sloth-sdrsweep's pure half: the arithmetic and the file formats, with
 * no SoapySDR in sight, so tests/test_sdrsweep.c can hold every number
 * the helper writes to synthetic tones and noise built from first
 * principles (docs/wiki/sdr-sweep.md).
 *
 * The helper (src/sdrsweep/main.c) tunes, reads CF32 samples and hands
 * them here; this file turns them into dBFS spectra, a per-step noise
 * floor, the display rows slothweb draws, and the run's peak list, and
 * writes the JSON slothweb reads. Every symbol is `sdrs_`; nothing that
 * sloth or slothweb links names this file (the Makefile builds it into
 * the helper and sloth_test only).
 *
 * Conventions:
 *   - dBFS: a complex full-scale tone (|x| = 1) at a bin centre reads
 *     0 dBFS. The window's coherent gain is removed by subtracting
 *     20*log10(sum of the window), so the reading does not depend on
 *     the FFT size or the window.
 *   - Spectra are "shifted": index 0 is the most negative frequency,
 *     index n/2 is DC (the tuned centre), index n-1 the most positive.
 *   - A display level is quantised to one byte, q = round((dBFS + 130)
 *     * 2) clamped to 0..255: half-dB steps over -130..-2.5 dBFS, and
 *     0 also means "no data". */
#ifndef SLOTH_SDRSWEEP_DSP_H
#define SLOTH_SDRSWEEP_DSP_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SDRS_NFFT_MIN        256
#define SDRS_NFFT_MAX        65536
#define SDRS_STEPS_MAX       4096
#define SDRS_ROWS_MAX        48       /* time rows kept per run */
#define SDRS_PEAKS_MAX       400      /* the strongest are kept */
#define SDRS_DISP_MAX        200000   /* display bins */

/* Display quantisation (see above). */
#define SDRS_Q_OFFSET_DB     (-130.0)
#define SDRS_Q_STEP_DB       0.5

/* Detection, measured on this receiver class with an antenna and with
 * none (docs/wiki/sdr-sweep.md "Detection"): a bin is a signal when its
 * frame-averaged level stands SDRS_DET_AVG_DB above its step's floor in
 * the run's average, or its max-hold stands SDRS_DET_PEAK_DB above in
 * any row. Flagged bins at most SDRS_GAP_BINS apart are one cluster;
 * clusters within SDRS_MERGE_HZ of each other are one peak. */
#define SDRS_DET_AVG_DB      6.0f
#define SDRS_DET_PEAK_DB     16.0f
#define SDRS_GAP_BINS        4
#define SDRS_MERGE_HZ        50e3

/* The RSPdx-R2's reference is 24 MHz and its harmonics show as fixed
 * spurs at n x 24 MHz (1176..1944 MHz near -60 dBFS with no antenna on
 * the port, measured 2026-11-13). A peak within SDRS_CLOCK_TOL_HZ of
 * one, above SDRS_CLOCK_MIN_HZ, is marked "clock harmonic?": a guess
 * the operator can rule out, never a removal. */
#define SDRS_CLOCK_HZ        24e6
#define SDRS_CLOCK_TOL_HZ    6e3
#define SDRS_CLOCK_MIN_HZ    20e6
/* A calibration run (no antenna on the port) names the receiver's own
 * spurs; a run's peak within SDRS_CAL_TOL_HZ of one, and no more than
 * SDRS_CAL_DB above the spur's absolute level, is "internal". Absolute
 * levels, never SNR: a strong outside signal leaks into the unconnected
 * port, raising its floor and making its SNR wrong. */
#define SDRS_CAL_TOL_HZ      6e3
#define SDRS_CAL_DB          6.0f

enum { SDRS_NOTE_NONE = 0, SDRS_NOTE_CLOCK = 1, SDRS_NOTE_INTERNAL = 2 };

/* ── FFT and spectra ── */

int    sdrs_is_pow2(int n);
/* In place, forward: X[k] = sum_n x[n] exp(-j 2 pi k n / N). n a power
 * of two. */
void   sdrs_fft(float *re, float *im, int n);
/* The periodic Hann window, w[i] = 0.5 - 0.5 cos(2 pi i / n). Returns
 * its sum, the coherent gain the dBFS reference removes. */
double sdrs_hann(float *w, int n);
/* One frame of n interleaved CF32 samples: windowed, transformed,
 * shifted, |X|^2 into pow (linear, unnormalised). re and im are n
 * floats of scratch. */
void   sdrs_frame_power(const float *iq, int n, const float *w,
                        float *re, float *im, float *pow);
/* Linear |X|^2 to dBFS for a window summing to wsum. -200 for zero. */
float  sdrs_pow_dbfs(float pow, double wsum);
/* The median of v[0..n-1]. scratch holds n floats and may be v itself,
 * which is then left sorted; otherwise v is untouched. */
float  sdrs_median(const float *v, int n, float *scratch);

/* ── the plan ── */

typedef struct {
    double f_lo, f_hi;      /* Hz, the span to cover */
    double rate;            /* samples per second (complex) */
    double keep;            /* Hz of each step kept, centred */
    double dc_guard;        /* Hz either side of the centre dropped */
    double dev_min, dev_max;/* the device's tunable centre range */
    int    nfft;
} sdrs_plan_t;

/* Clamp f_lo/f_hi to the device range and check the shape: 0, or -1
 * with a reason in *why. */
int    sdrs_plan_check(sdrs_plan_t *p, const char **why);
/* Step centres tiling [f_lo, f_hi] with the kept width, the last one
 * clamped to dev_max (the RSPdx refuses a centre past 2000 MHz).
 * Returns the count, or -1 when more than max. */
int    sdrs_plan_steps(const sdrs_plan_t *p, double *centres, int max);
/* The shifted FFT indices each step keeps: |offset| <= keep/2 and
 * > dc_guard. Returns the count. */
int    sdrs_plan_kept(const sdrs_plan_t *p, int *k, int max);

/* ── one run ── */

typedef struct {
    sdrs_plan_t plan;
    double   bin_hz;        /* rate / nfft */
    double   disp_hz;       /* display bin width */
    int      nsteps, nkept, ndisp;
    double  *centres;       /* nsteps */
    int     *kept;          /* nkept shifted indices */
    /* Per (step, kept bin), across the run. */
    uint8_t *valid;         /* in [f_lo, f_hi] and past the previous step */
    float   *avg_sum;       /* sum over rows of the frame-mean SNR, dB */
    float   *pk_snr;        /* max over rows of the max-hold SNR, dB */
    float   *pk_db;         /* max over rows of the max-hold, dBFS */
    uint16_t *seen;         /* rows in which the bin met a threshold */
    uint16_t *step_rows;    /* nsteps: rows that measured the step */
    int     *disp_idx;      /* (step, kept) to display bin, or -1 */
    /* The row in progress. */
    float   *row_db;        /* ndisp max-hold dBFS, -200 none */
    float   *row_floor;     /* nsteps, NAN until measured */
    float   *scratch;       /* max(nkept, nsteps) */
    int      rows;          /* rows completed */
} sdrs_run_t;

int    sdrs_run_init(sdrs_run_t *r, const sdrs_plan_t *p, double disp_hz);
void   sdrs_run_free(sdrs_run_t *r);
double sdrs_run_freq(const sdrs_run_t *r, int step, int j);
void   sdrs_run_row_begin(sdrs_run_t *r);
/* One step of the current row: mean_db and max_db are the shifted
 * frame-mean and max-hold spectra in dBFS (nfft each). Returns the
 * step's floor (the median of its kept bins' frame mean). */
float  sdrs_run_step(sdrs_run_t *r, int step, const float *mean_db, const float *max_db);
/* Close the row: q gets ndisp quantised levels; returns the row's floor
 * (the median of the floors its steps measured), or NAN if none. */
float  sdrs_run_row_end(sdrs_run_t *r, uint8_t *q);

typedef struct {
    double freq_hz, width_hz;
    float  snr_avg, snr_peak, dbfs;
    int    rows;
    int    note;
} sdrs_peak_t;

/* Detect, cluster and merge across the run; the SDRS_PEAKS_MAX
 * strongest by peak SNR, in frequency order. Returns the count, -1 on
 * allocation failure. */
int    sdrs_run_peaks(const sdrs_run_t *r, sdrs_peak_t *out, int max);
int    sdrs_is_clock_harmonic(double f);
/* Mark each peak: internal when a calibration spur explains it, else
 * clock harmonic? when it sits on one. cal may be NULL. */
void   sdrs_label(sdrs_peak_t *p, int n, const sdrs_peak_t *cal, int ncal);
const char *sdrs_note_name(int note);

/* ── formats ── */

uint8_t sdrs_quant(float dbfs);
/* RFC 4648 base64 of n bytes into out (4 * ceil(n / 3) + 1 bytes, NUL
 * terminated). Returns the length written. */
size_t sdrs_b64(const uint8_t *in, size_t n, char *out);
/* A JSON string, quoted and escaped (RFC 8259 §7). */
void   sdrs_json_str(FILE *f, const char *s);

typedef struct {
    const char *mode;       /* "sweep" or "calibrate" */
    int    complete;        /* 0: stopped before the duration ran out */
    double started, ended;  /* unix seconds */
    const char *device, *driver, *hardware, *serial, *antenna, *gain;
    double rate, bandwidth, keep, dc_guard;
    int    nfft, frames;
    double duration;
    int    calibrated;      /* a spurs.json was applied */
} sdrs_meta_t;

typedef struct {
    double   t;             /* unix seconds the row began */
    float    floor;         /* dBFS */
    uint8_t *q;             /* ndisp */
} sdrs_row_t;

/* The whole document (docs/wiki/sdr-sweep.md "Output"). Each peak on a
 * line of its own, which is what sdrs_parse_cal() reads back. 0, or -1
 * on a write error. */
int    sdrs_write_json(FILE *f, const sdrs_meta_t *m, const sdrs_run_t *r,
                       const sdrs_row_t *rows, int nrows,
                       const sdrs_peak_t *peaks, int npeaks);
/* The peaks of a document sdrs_write_json() wrote: each line holding
 * "freq_hz": and "dbfs": numbers. Lines without both are skipped.
 * Returns the count. */
int    sdrs_parse_cal(const char *text, sdrs_peak_t *out, int max);
/* The number after "key": in text, or def when absent or not a number. */
double sdrs_json_num(const char *text, const char *key, double def);

#endif
