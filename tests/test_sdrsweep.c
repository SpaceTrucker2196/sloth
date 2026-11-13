#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "runner.h"
#include "sdrsweep/sdrsweep_dsp.h"

/*
 * sloth-sdrsweep's pure half (src/sdrsweep/sdrsweep_dsp.c) and the
 * helper's boundaries (docs/wiki/sdr-sweep.md).
 *
 * Every expected number is derived here from first principles, never
 * produced by the code under test and fed back: the DFT by its
 * definition, the window's sums in closed form (periodic Hann: sum n/2,
 * sum of squares 3n/8), the noise floor of complex white noise of
 * per-sample power s2 through that window (|X|^2 has mean s2 * 3n/8, so
 * 10 log10(s2 * 1.5 / n) dBFS once the coherent gain (n/2)^2 is
 * removed), and base64 from RFC 4648 §10's vectors.
 *
 * Absence assertions, each seen red under the named mutation and then
 * restored (docs/wiki/log.md, the 2026-11-13 sdr-sweep entry):
 *   - test_overlap_counted_once: `&& f > prev_hi` dropped from the
 *     validity test in sdrs_run_init() (the clamped last step's bins
 *     counted twice, frequencies not increasing);
 *   - test_clusters_and_separation: the merge distance set to 500 kHz
 *     (the two tones 200 kHz apart became one peak);
 *   - test_label_cal_absolute_level: `p[i].dbfs <= cal[c].dbfs +
 *     SDRS_CAL_DB` dropped (a signal 40 dB above the spur went
 *     "internal");
 *   - test_helper_never_transmits: a SoapySDRDevice_writeStream call
 *     added to src/sdrsweep/main.c;
 *   - test_helper_is_not_linked_into_sloth_or_slothweb:
 *     src/sdrsweep/sdrsweep_dsp.c appended to CORE_COMMON_SRCS;
 *   - test_units_name_no_site_service: `Conflicts=aprs.service` added to
 *     packaging/systemd/sloth-sdrsweep.service.
 */

static uint32_t g_lcg;
static double urand(void) {
    g_lcg = g_lcg * 1664525u + 1013904223u;
    return ((g_lcg >> 8) + 0.5) / 16777216.0;
}
/* Box-Muller: one standard normal. */
static double nrand(void) {
    double u = urand(), v = urand();
    return sqrt(-2.0 * log(u)) * cos(2 * M_PI * v);
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *b = malloc((size_t)n + 1);
    if (b && fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); b = NULL; }
    if (b) b[n] = '\0';
    fclose(f);
    return b;
}

/* ── the transform ── */

static void test_fft_matches_the_definition(void) {
    enum { N = 64 };
    float re[N], im[N];
    double xr[N], xi[N];
    g_lcg = 7;
    for (int i = 0; i < N; i++) {
        xr[i] = urand() - 0.5; xi[i] = urand() - 0.5;
        re[i] = (float)xr[i]; im[i] = (float)xi[i];
    }
    sdrs_fft(re, im, N);
    double worst = 0;
    for (int k = 0; k < N; k++) {
        double sr = 0, si = 0;
        for (int n = 0; n < N; n++) {
            double a = -2 * M_PI * k * n / N;
            sr += xr[n] * cos(a) - xi[n] * sin(a);
            si += xr[n] * sin(a) + xi[n] * cos(a);
        }
        double e = fabs(sr - re[k]) + fabs(si - im[k]);
        if (e > worst) worst = e;
    }
    ASSERT(worst < 1e-4);
    /* An impulse is flat; a complex exponential at bin 3 is one line. */
    for (int i = 0; i < N; i++) { re[i] = i == 0; im[i] = 0; }
    sdrs_fft(re, im, N);
    int flat = 1;
    for (int k = 0; k < N; k++) flat &= fabsf(re[k] - 1) < 1e-6f && fabsf(im[k]) < 1e-6f;
    ASSERT(flat);
    for (int i = 0; i < N; i++) {
        re[i] = (float)cos(2 * M_PI * 3 * i / N);
        im[i] = (float)sin(2 * M_PI * 3 * i / N);
    }
    sdrs_fft(re, im, N);
    ASSERT_NEAR(re[3], N, 1e-3);
    int quiet = 1;
    for (int k = 0; k < N; k++) if (k != 3) quiet &= hypotf(re[k], im[k]) < 1e-3f;
    ASSERT(quiet);
    ASSERT(sdrs_is_pow2(8192));
    ASSERT(!sdrs_is_pow2(1000));
    ASSERT(!sdrs_is_pow2(0));
}

static void test_hann_sums(void) {
    enum { N = 1024 };
    float w[N];
    double s = sdrs_hann(w, N), s2 = 0;
    for (int i = 0; i < N; i++) s2 += (double)w[i] * w[i];
    ASSERT_NEAR(s, N / 2.0, 1e-3);
    ASSERT_NEAR(s2, 3.0 * N / 8.0, 1e-3);
    ASSERT_NEAR(w[0], 0, 1e-7);
    ASSERT_NEAR(w[N / 2], 1, 1e-7);
}

/* A full-scale complex tone reads 0 dBFS wherever the window and size,
 * and lands at its shifted index: n/2 + k for +k bins, n/2 - k for -k. */
static void test_dbfs_reference(void) {
    static const int sizes[] = { 256, 8192 };
    for (size_t z = 0; z < 2; z++) {
        int n = sizes[z];
        float *iq = malloc(2 * (size_t)n * sizeof(float));
        float *w = malloc((size_t)n * sizeof(float)), *re = malloc((size_t)n * sizeof(float));
        float *im = malloc((size_t)n * sizeof(float)), *pw = malloc((size_t)n * sizeof(float));
        ASSERT(iq && w && re && im && pw);
        if (!iq || !w || !re || !im || !pw) { free(iq); free(w); free(re); free(im); free(pw); return; }
        double ws = sdrs_hann(w, n);
        static const struct { int k; double amp, want; } T[] = {
            { 10, 1.0, 0.0 }, { -40, 0.1, -20.0 }, { 3, 0.001, -60.0 },
        };
        for (size_t t = 0; t < 3; t++) {
            for (int i = 0; i < n; i++) {
                double a = 2 * M_PI * T[t].k * i / n;
                iq[2 * i] = (float)(T[t].amp * cos(a));
                iq[2 * i + 1] = (float)(T[t].amp * sin(a));
            }
            sdrs_frame_power(iq, n, w, re, im, pw);
            int at = n / 2 + T[t].k, best = 0;
            for (int i = 1; i < n; i++) if (pw[i] > pw[best]) best = i;
            ASSERT_EQ(best, at);
            ASSERT_NEAR(sdrs_pow_dbfs(pw[at], ws), T[t].want, 0.01);
        }
        free(iq); free(w); free(re); free(im); free(pw);
    }
    ASSERT_NEAR(sdrs_pow_dbfs(0, 512), -200, 1e-6);
}

static void test_median(void) {
    float v[] = { 5, 1, 4, 2, 3 }, s[5];
    ASSERT_NEAR(sdrs_median(v, 5, s), 3, 1e-9);
    ASSERT_NEAR(v[0], 5, 1e-9);                  /* untouched */
    ASSERT_NEAR(sdrs_median(v, 4, s), 3, 1e-9);  /* 5,1,4,2: (2+4)/2 */
    ASSERT(isnan(sdrs_median(v, 0, s)));
}

/* ── the plan ── */

static void test_plan_full_span(void) {
    sdrs_plan_t p = { 0.5e6, 2000e6, 8e6, 6e6, 25e3, 1e3, 2000e6, 8192 };
    const char *why = NULL;
    ASSERT_EQ(sdrs_plan_check(&p, &why), 0);
    static double c[SDRS_STEPS_MAX];
    int n = sdrs_plan_steps(&p, c, SDRS_STEPS_MAX);
    /* ceil(1999.5 / 6) = 334 steps of 6 MHz; the last centre would be
     * 0.5 + 6 * 333.5 = 2001.5 MHz, which the RSPdx refuses: clamped. */
    ASSERT_EQ(n, 334);
    ASSERT_NEAR(c[0], 3.5e6, 1e-3);
    ASSERT_NEAR(c[332], 0.5e6 + 6e6 * 332.5, 1e-3);
    ASSERT_NEAR(c[333], 2000e6, 1e-3);
    int over = 0;
    for (int i = 0; i < n; i++) over |= c[i] > p.dev_max;
    ASSERT(!over);
    /* Kept per step: |offset| <= 3 MHz is 3072 bins of 976.5625 Hz
     * either side plus DC, 6145; 25 kHz is 25.6 bins, so DC +-25 go. */
    int k[8192];
    ASSERT_EQ(sdrs_plan_kept(&p, k, 8192), 6145 - 51);
    ASSERT_EQ(k[0], 4096 - 3072);
    /* A span outside the device, and shapes that cannot work. */
    sdrs_plan_t q = p;
    q.f_lo = 2100e6; q.f_hi = 2200e6;
    ASSERT_EQ(sdrs_plan_check(&q, &why), -1);
    q = p; q.nfft = 1000;
    ASSERT_EQ(sdrs_plan_check(&q, &why), -1);
    q = p; q.dc_guard = 3e6;
    ASSERT_EQ(sdrs_plan_check(&q, &why), -1);
    q = p; q.f_hi = 3000e6;
    ASSERT_EQ(sdrs_plan_check(&q, &why), 0);
    ASSERT_NEAR(q.f_hi, 2000e6, 1e-3);
}

/* ── a run on synthetic samples ── */

enum { TN = 1024, TFRAMES = 16 };
#define T_RATE 1.024e6     /* 1 kHz bins */

typedef struct { double f, amp; } tone_t;

/* One step at centre c: complex noise of per-sample power s2 plus the
 * tones, TFRAMES frames, through the helper's own frame path. A tone
 * further from the centre than 0.45 of the rate is left out, as the
 * receiver's IF filter leaves it out: sampled, it would alias into the
 * step and show at the wrong frequency. */
static void step_at(sdrs_run_t *r, int s, double s2, const tone_t *t, int nt) {
    static float iq[2 * TN], w[TN], re[TN], im[TN], pw[TN], mean[TN], mx[TN], md[TN], xd[TN];
    double ws = sdrs_hann(w, TN), sd = sqrt(s2 / 2);
    for (int k = 0; k < TN; k++) { mean[k] = 0; mx[k] = 0; }
    for (int fr = 0; fr < TFRAMES; fr++) {
        for (int i = 0; i < TN; i++) {
            double x = sd * nrand(), y = sd * nrand();
            for (int j = 0; j < nt; j++) {
                if (fabs(t[j].f - r->centres[s]) > 0.45 * T_RATE) continue;
                double a = 2 * M_PI * (t[j].f - r->centres[s]) * (fr * TN + i) / T_RATE;
                x += t[j].amp * cos(a); y += t[j].amp * sin(a);
            }
            iq[2 * i] = (float)x; iq[2 * i + 1] = (float)y;
        }
        sdrs_frame_power(iq, TN, w, re, im, pw);
        for (int k = 0; k < TN; k++) {
            mean[k] += pw[k] / TFRAMES;
            if (pw[k] > mx[k]) mx[k] = pw[k];
        }
    }
    for (int k = 0; k < TN; k++) { md[k] = sdrs_pow_dbfs(mean[k], ws); xd[k] = sdrs_pow_dbfs(mx[k], ws); }
    sdrs_run_step(r, s, md, xd);
}

static int run_rows(sdrs_run_t *r, int rows, double s2, const tone_t *t, int nt,
                    uint8_t *q, float *fl) {
    for (int row = 0; row < rows; row++) {
        sdrs_run_row_begin(r);
        for (int s = 0; s < r->nsteps; s++) step_at(r, s, s2, t, nt);
        *fl = sdrs_run_row_end(r, q);
    }
    return 0;
}

static void test_floor_and_one_tone(void) {
    /* 100.0-102.4 MHz in 3 steps of 800 kHz; a -20 dBFS tone at
     * 101.2345 MHz over noise of per-sample power 1e-6 (-60 dB). */
    sdrs_plan_t p = { 100e6, 102.4e6, T_RATE, 0.8e6, 10e3, 1e6, 3e9, TN };
    const char *why;
    ASSERT_EQ(sdrs_plan_check(&p, &why), 0);
    sdrs_run_t r;
    ASSERT_EQ(sdrs_run_init(&r, &p, 100e3), 0);
    ASSERT_EQ(r.nsteps, 3);
    ASSERT_EQ(r.ndisp, 24);
    static uint8_t q[64];
    float fl = 0;
    tone_t t = { 101.2345e6, 0.1 };
    g_lcg = 1;
    run_rows(&r, 2, 1e-6, &t, 1, q, &fl);
    /* The floor: 10 log10(1e-6 * 1.5 / 1024) = -88.3 dBFS for the mean;
     * the median of a mean of 16 exponentials, a gamma(16), sits at
     * about (16 - 1/3) / 16 of it, 0.09 dB under. */
    double want = 10 * log10(1e-6 * 1.5 / TN) - 0.09;
    ASSERT_NEAR(fl, want, 1.0);
    ASSERT_EQ(r.rows, 2);
    sdrs_peak_t pk[8];
    int n = sdrs_run_peaks(&r, pk, 8);
    ASSERT_EQ(n, 1);
    if (n == 1) {
        /* The bin nearest the tone is 1 kHz wide; the tone sits 0.5 kHz
         * off a bin centre, where Hann loses 1.42 dB (scalloping:
         * |sum w e^{j pi i/n}| / sum w = 0.849). */
        ASSERT(fabs(pk[0].freq_hz - t.f) <= 1e3);
        ASSERT_NEAR(pk[0].dbfs, -20 - 1.42, 0.3);
        ASSERT_NEAR(pk[0].snr_peak, pk[0].dbfs - fl, 3.0);
        ASSERT_EQ(pk[0].rows, 2);
        ASSERT_EQ(pk[0].note, SDRS_NOTE_NONE);
        ASSERT(pk[0].width_hz >= 1e3 && pk[0].width_hz < 20e3);
    }
    /* The display row: the tone's 100 kHz bin holds its max-hold. */
    int d = (int)((t.f - p.f_lo) / 100e3);
    ASSERT_NEAR(q[d], sdrs_quant(pk[0].dbfs), 1.5);
    ASSERT_LT(q[d + 3], q[d] - 80);
    sdrs_run_free(&r);
}

static void test_clusters_and_separation(void) {
    sdrs_plan_t p = { 100e6, 100.8e6, T_RATE, 0.8e6, 10e3, 1e6, 3e9, TN };
    const char *why;
    ASSERT_EQ(sdrs_plan_check(&p, &why), 0);
    sdrs_run_t r;
    ASSERT_EQ(sdrs_run_init(&r, &p, 100e3), 0);
    static uint8_t q[16];
    float fl;
    /* 100.10 and 100.13 MHz (30 kHz apart: one peak, the stronger's
     * frequency); 100.55 MHz (420 kHz on: its own); 100.75 MHz (200 kHz
     * on: its own). */
    tone_t t[] = { { 100.10e6, 0.01 }, { 100.13e6, 0.03 }, { 100.55e6, 0.03 }, { 100.75e6, 0.03 } };
    g_lcg = 2;
    run_rows(&r, 1, 1e-6, t, 4, q, &fl);
    sdrs_peak_t pk[8];
    int n = sdrs_run_peaks(&r, pk, 8);
    ASSERT_EQ(n, 3);
    if (n == 3) {
        ASSERT(fabs(pk[0].freq_hz - 100.13e6) <= 1e3);
        ASSERT(pk[0].width_hz >= 30e3);
        ASSERT(fabs(pk[1].freq_hz - 100.55e6) <= 1e3);
        ASSERT(fabs(pk[2].freq_hz - 100.75e6) <= 1e3);
    }
    /* Capped at 2: the strongest two by peak SNR, still in frequency
     * order. */
    n = sdrs_run_peaks(&r, pk, 2);
    ASSERT_EQ(n, 2);
    ASSERT(n == 2 && pk[0].freq_hz < pk[1].freq_hz);
    sdrs_run_free(&r);
    /* Nothing but noise: no peaks. */
    ASSERT_EQ(sdrs_run_init(&r, &p, 100e3), 0);
    g_lcg = 3;
    run_rows(&r, 2, 1e-6, NULL, 0, q, &fl);
    ASSERT_EQ(sdrs_run_peaks(&r, pk, 8), 0);
    sdrs_run_free(&r);
}

/* The last step clamped to the device's top overlaps its neighbour;
 * each frequency is the run's once, so valid bins rise strictly. */
static void test_overlap_counted_once(void) {
    sdrs_plan_t p = { 100e6, 102e6, T_RATE, 0.8e6, 10e3, 1e6, 102e6, TN };
    const char *why;
    ASSERT_EQ(sdrs_plan_check(&p, &why), 0);
    sdrs_run_t r;
    ASSERT_EQ(sdrs_run_init(&r, &p, 100e3), 0);
    ASSERT_EQ(r.nsteps, 3);
    ASSERT_NEAR(r.centres[2], 102e6, 1e-3);     /* 102.0, not 102.0 + 0.0 */
    double last = -1;
    int rising = 1, count = 0;
    for (int s = 0; s < r.nsteps; s++)
        for (int j = 0; j < r.nkept; j++) {
            if (!r.valid[(size_t)s * r.nkept + j]) continue;
            double f = sdrs_run_freq(&r, s, j);
            rising &= f > last;
            last = f;
            count++;
        }
    ASSERT(rising);
    ASSERT(last <= p.f_hi);
    /* 2 MHz at 1 kHz, less the three DC guards' 19 bins each and the
     * dropped overlap: never more bins than the span holds. */
    ASSERT(count <= 2001);
    ASSERT(count > 2001 - 3 * 21);
    sdrs_run_free(&r);
}

/* ── labels ── */

static void test_clock_harmonics(void) {
    ASSERT(sdrs_is_clock_harmonic(1176e6));
    ASSERT(sdrs_is_clock_harmonic(1944e6));
    ASSERT(sdrs_is_clock_harmonic(1176e6 + 6e3));
    ASSERT(sdrs_is_clock_harmonic(1224e6 - 5.9e3));
    ASSERT(!sdrs_is_clock_harmonic(1176e6 + 6.1e3));
    ASSERT(sdrs_is_clock_harmonic(24e6));
    ASSERT(!sdrs_is_clock_harmonic(12e6));
    ASSERT(!sdrs_is_clock_harmonic(19.999e6));
    ASSERT(!sdrs_is_clock_harmonic(144.39e6));
}

static void test_label_cal_absolute_level(void) {
    sdrs_peak_t p[3] = {
        { 1200.002e6, 2e3, 20, 30, -62, 3, 0 },   /* the spur, as calibrated */
        { 1200.001e6, 2e3, 50, 60, -20, 3, 0 },   /* a real signal on it */
        { 144.390e6, 8e3, 25, 35, -55, 3, 0 },
    };
    sdrs_peak_t cal[1] = { { 1200.000e6, 1e3, 0, 0, -60, 0, 0 } };
    sdrs_label(p, 3, cal, 1);
    ASSERT_EQ(p[0].note, SDRS_NOTE_INTERNAL);
    ASSERT_EQ(p[1].note, SDRS_NOTE_CLOCK);       /* 40 dB over the spur */
    ASSERT_EQ(p[2].note, SDRS_NOTE_NONE);
    sdrs_label(p, 3, NULL, 0);
    ASSERT_EQ(p[0].note, SDRS_NOTE_CLOCK);
    ASSERT_STR(sdrs_note_name(SDRS_NOTE_CLOCK), "clock harmonic?");
    ASSERT_STR(sdrs_note_name(SDRS_NOTE_INTERNAL), "internal");
    ASSERT_STR(sdrs_note_name(SDRS_NOTE_NONE), "");
}

/* ── formats ── */

static void test_quant(void) {
    ASSERT_EQ(sdrs_quant(-130), 0);
    ASSERT_EQ(sdrs_quant(-200), 0);
    ASSERT_EQ(sdrs_quant(NAN), 0);
    ASSERT_EQ(sdrs_quant(-129.5f), 1);
    ASSERT_EQ(sdrs_quant(-20), 220);
    ASSERT_EQ(sdrs_quant(-2.5f), 255);
    ASSERT_EQ(sdrs_quant(0), 255);
}

static void test_base64_rfc4648(void) {
    static const char *const in[] = { "", "f", "fo", "foo", "foob", "fooba", "foobar" };
    static const char *const out[] = { "", "Zg==", "Zm8=", "Zm9v", "Zm9vYg==", "Zm9vYmE=", "Zm9vYmFy" };
    char b[16];
    for (int i = 0; i < 7; i++) {
        size_t n = sdrs_b64((const uint8_t *)in[i], strlen(in[i]), b);
        ASSERT_STR(b, out[i]);
        ASSERT_EQ(n, strlen(out[i]));
    }
    const uint8_t bin[3] = { 0xff, 0x00, 0xfe };
    sdrs_b64(bin, 3, b);
    ASSERT_STR(b, "/wD+");
}

static void test_json_document(void) {
    sdrs_plan_t p = { 100e6, 100.8e6, T_RATE, 0.8e6, 10e3, 1e6, 3e9, TN };
    sdrs_run_t r;
    ASSERT_EQ(sdrs_run_init(&r, &p, 100e3), 0);
    uint8_t q[8] = { 0, 1, 2, 255, 0, 0, 0, 220 };
    sdrs_row_t rows[2] = { { 1700000000.25, -88.25f, q }, { 1700000020.5, NAN, q } };
    sdrs_peak_t pk[2] = {
        { 100.1e6, 3e3, 7.5f, 21.25f, -64.5f, 2, SDRS_NOTE_NONE },
        { 120e6, 1e3, 2, 18, -61, 1, SDRS_NOTE_CLOCK },
    };
    sdrs_meta_t m = { "sweep", 1, 1700000000.0, 1700000061.0, "driver=sdrplay,serial=\"x\"",
                      "SDRplay", "RSPdx-R2", "\x01" "23", "Antenna A", "IFGR=40,RFGR=3",
                      8e6, 7e6, 6e6, 25e3, 8192, 4, 60, 0 };
    char *buf = NULL;
    size_t len = 0;
    FILE *f = open_memstream(&buf, &len);
    ASSERT(f != NULL);
    if (!f) { sdrs_run_free(&r); return; }
    ASSERT_EQ(sdrs_write_json(f, &m, &r, rows, 2, pk, 2), 0);
    fclose(f);
    static const char head[] = "{\"version\":1,\"mode\":\"sweep\",\"complete\":true,";
    ASSERT(strncmp(buf, head, sizeof(head) - 1) == 0);
    ASSERT(strstr(buf, "\"device\":\"driver=sdrplay,serial=\\\"x\\\"\"") != NULL);
    ASSERT(strstr(buf, "\"serial\":\"\\u000123\"") != NULL);
    ASSERT(strstr(buf, "\"bins\":8,") != NULL);
    ASSERT(strstr(buf, "\"bin_hz\":100000,") != NULL);
    ASSERT(strstr(buf, "\"quant\":{\"offset_db\":-130.0,\"step_db\":0.5}") != NULL);
    /* 0,1,2,255,0,0,0,220 is AAEC/wAAANw= by RFC 4648's alphabet. */
    ASSERT(strstr(buf, "{\"t\":1700000000.250,\"floor\":-88.2,\"data\":\"AAEC/wAAANw=\"}") != NULL ||
           strstr(buf, "{\"t\":1700000000.250,\"floor\":-88.3,\"data\":\"AAEC/wAAANw=\"}") != NULL);
    ASSERT(strstr(buf, "\"floor\":null") != NULL);
    ASSERT(strstr(buf, "\n{\"freq_hz\":120000000,\"width_hz\":1000,\"snr_avg\":2.0,"
                       "\"snr_peak\":18.0,\"dbfs\":-61.0,\"rows\":1,\"note\":\"clock harmonic?\"}") != NULL);
    ASSERT(buf[len - 1] == '\n' && buf[len - 2] == '}');
    /* What --calibrate writes is what a sweep reads back. */
    sdrs_peak_t back[4];
    ASSERT_EQ(sdrs_parse_cal(buf, back, 4), 2);
    ASSERT_NEAR(back[1].freq_hz, 120e6, 0.5);
    ASSERT_NEAR(back[0].dbfs, -64.5, 0.01);
    ASSERT_NEAR(back[0].width_hz, 3e3, 0.5);
    free(buf);
    sdrs_run_free(&r);
}

static void test_parse_hand_written(void) {
    const char *t =
        "{\"peaks\":[\n"
        "{\"freq_hz\":1176000000,\"dbfs\":-60.5},\n"
        "{\"freq_hz\":\"x\",\"dbfs\":-1},\n"       /* not a number: skipped */
        "{\"dbfs\":-50},\n"                       /* no frequency: skipped */
        "{\"freq_hz\":1224000000,\"width_hz\":2000,\"dbfs\":-58}]}\n";
    sdrs_peak_t c[4];
    ASSERT_EQ(sdrs_parse_cal(t, c, 4), 2);
    ASSERT_NEAR(c[0].freq_hz, 1176e6, 0.5);
    ASSERT_NEAR(c[1].dbfs, -58, 1e-6);
    ASSERT_NEAR(c[1].width_hz, 2000, 1e-6);
    ASSERT_EQ(sdrs_parse_cal(t, c, 1), 1);
    ASSERT_NEAR(sdrs_json_num("{\"ended\":1700000061.5,\"x\":1}", "ended", 0), 1700000061.5, 1e-3);
    ASSERT_NEAR(sdrs_json_num("{\"ended\":null}", "ended", -1), -1, 1e-9);
    ASSERT_NEAR(sdrs_json_num("{}", "ended", 7), 7, 1e-9);
}

/* ── the helper's boundaries ── */

/* Receive only: the helper never sets up a transmit stream nor writes
 * one. A text scan of its one file that talks to SoapySDR. */
static void test_helper_never_transmits(void) {
    char *s = slurp("src/sdrsweep/main.c");
    ASSERT(s != NULL);
    if (!s) return;
    ASSERT(strstr(s, "SOAPY_SDR_TX") == NULL);
    ASSERT(strstr(s, "writeStream") == NULL);
    ASSERT(strstr(s, "SOAPY_SDR_RX") != NULL);
    /* The stop path the SDRplay API needs is there. */
    ASSERT(strstr(s, "SoapySDRDevice_deactivateStream") != NULL);
    ASSERT(strstr(s, "SoapySDRDevice_closeStream") != NULL);
    ASSERT(strstr(s, "SoapySDRDevice_unmake") != NULL);
    ASSERT(strstr(s, "SA_RESTART") != NULL);    /* named, and not set */
    ASSERT(strstr(s, "sa.sa_flags = SA_RESTART") == NULL);
    free(s);
}

/* sloth and slothweb drive no radio: src/sdrsweep/ is named only by the
 * helper's own lists and the test build's, and nothing in web/src
 * includes it. */
static void test_helper_is_not_linked_into_sloth_or_slothweb(void) {
    char *mk = slurp("Makefile");
    ASSERT(mk != NULL);
    if (!mk) return;
    /* SoapySDR is linked by the helper's rule alone. */
    ASSERT(strstr(mk, "WEB_LDLIBS      = -lpthread -lm\n") != NULL);
    int named = 0, ok = 1, prev_test_only = 0;
    for (char *l = mk; l && *l; ) {
        char *nl = strchr(l, '\n');
        if (nl) *nl = '\0';
        if (strstr(l, "src/sdrsweep/") && l[0] != '#') {
            named++;
            int allowed = !strncmp(l, "SDRSWEEP_SRCS", 13) || !strncmp(l, "SDRSWEEP_HDRS", 13) ||
                          (prev_test_only && (l[0] == ' ' || l[0] == '\t'));
            if (!allowed) {
                fprintf(stderr, "    Makefile names src/sdrsweep/ elsewhere: %s\n", l);
                ok = 0;
            }
        }
        prev_test_only = !strncmp(l, "TEST_ONLY_SRCS", 14);
        l = nl ? nl + 1 : NULL;
    }
    ASSERT(ok);
    ASSERT_GE(named, 3);
    free(mk);
    DIR *d = opendir("web/src");
    ASSERT(d != NULL);
    if (!d) return;
    struct dirent *e;
    int clean = 1, seen = 0;
    while ((e = readdir(d))) {
        size_t n = strlen(e->d_name);
        if (n < 3 || (strcmp(e->d_name + n - 2, ".c") && strcmp(e->d_name + n - 2, ".h"))) continue;
        char path[300];
        snprintf(path, sizeof(path), "web/src/%s", e->d_name);
        char *s = slurp(path);
        if (!s) continue;
        seen++;
        if (strstr(s, "sdrsweep_dsp") || strstr(s, "SoapySDR/")) {
            fprintf(stderr, "    %s names the helper or SoapySDR\n", path);
            clean = 0;
        }
        free(s);
    }
    closedir(d);
    ASSERT(clean);
    ASSERT_GT(seen, 10);
}

/* The units: a oneshot under its own account with no capability, the
 * request consumed as root before the run, a stop timeout that lets the
 * SDRplay close finish, the path unit watching the file slothweb makes,
 * and no site's service named in either (the APRS conflict is a
 * drop-in, docs/wiki/deployment.md). */
static void test_units_name_no_site_service(void) {
    char *svc = slurp("packaging/systemd/sloth-sdrsweep.service");
    char *path = slurp("packaging/systemd/sloth-sdrsweep.path");
    char *mk = slurp("Makefile");
    ASSERT(svc && path && mk);
    if (!svc || !path || !mk) { free(svc); free(path); free(mk); return; }
    ASSERT(strstr(svc, "\nType=oneshot\n") != NULL);
    ASSERT(strstr(svc, "\nUser=sloth-sdrsweep\n") != NULL);
    ASSERT(strstr(svc, "\nCapabilityBoundingSet=\n") != NULL);
    ASSERT(strstr(svc, "\nNoNewPrivileges=true\n") != NULL);
    ASSERT(strstr(svc, "\nExecStartPre=+/bin/rm -f /run/slothweb/sdrsweep.request\n") != NULL);
    ASSERT(strstr(svc, "\nExecStart=/usr/local/sbin/sloth-sdrsweep --out /var/lib/sloth-sdrsweep\n") != NULL);
    ASSERT(strstr(svc, "\nTimeoutStopSec=60\n") != NULL);
    ASSERT(strstr(svc, "\nStateDirectory=sloth-sdrsweep\n") != NULL);
    ASSERT(strstr(svc, "\nDynamicUser") == NULL);
    ASSERT(strstr(svc, "[Install]") == NULL);   /* started by the path unit only */
    ASSERT(strstr(path, "\nPathExists=/run/slothweb/sdrsweep.request\n") != NULL);
    ASSERT(strstr(path, "\nUnit=sloth-sdrsweep.service\n") != NULL);
    static const char *const site[] = { "aprs", "direwolf", "dump1090", "readsb" };
    for (size_t i = 0; i < sizeof(site) / sizeof(site[0]); i++) {
        for (const char *l = svc; l && *l; ) {
            const char *nl = strchr(l, '\n');
            if (*l != '#') {
                size_t n = nl ? (size_t)(nl - l) : strlen(l);
                char line[512];
                snprintf(line, sizeof(line), "%.*s", (int)(n < 511 ? n : 511), l);
                if (strstr(line, site[i])) {
                    fprintf(stderr, "    sloth-sdrsweep.service names %s: %s\n", site[i], line);
                    ASSERT(0);
                }
            }
            l = nl ? nl + 1 : NULL;
        }
    }
    /* Installed, never enabled, by make. */
    ASSERT(strstr(mk, "packaging/systemd/sloth-sdrsweep.path $(DESTDIR)$(UNITDIR)/sloth-sdrsweep.path") != NULL);
    ASSERT(strstr(mk, "[ -e $(DESTDIR)$(DEFAULTDIR)/sloth-sdrsweep ] ||") != NULL);
    ASSERT(strstr(mk, "enable --now sloth-sdrsweep") != NULL);   /* only in an @echo */
    ASSERT(strstr(mk, "\tsystemctl enable") == NULL);
    free(svc); free(path); free(mk);
}

void run_sdrsweep_tests(void) {
    TEST_SUITE("sloth-sdrsweep (SDR sweep helper, pure half)");
    RUN_TEST(test_fft_matches_the_definition);
    RUN_TEST(test_hann_sums);
    RUN_TEST(test_dbfs_reference);
    RUN_TEST(test_median);
    RUN_TEST(test_plan_full_span);
    RUN_TEST(test_floor_and_one_tone);
    RUN_TEST(test_clusters_and_separation);
    RUN_TEST(test_overlap_counted_once);
    RUN_TEST(test_clock_harmonics);
    RUN_TEST(test_label_cal_absolute_level);
    RUN_TEST(test_quant);
    RUN_TEST(test_base64_rfc4648);
    RUN_TEST(test_json_document);
    RUN_TEST(test_parse_hand_written);
    RUN_TEST(test_helper_never_transmits);
    RUN_TEST(test_helper_is_not_linked_into_sloth_or_slothweb);
    RUN_TEST(test_units_name_no_site_service);
}
