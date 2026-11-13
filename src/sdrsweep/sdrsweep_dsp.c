/* sloth-sdrsweep's pure half; sdrsweep_dsp.h says what and why. */
#include "sdrsweep/sdrsweep_dsp.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define SDRS_NONE_DB (-200.0f)

/* ── FFT and spectra ── */

int sdrs_is_pow2(int n) { return n > 0 && (n & (n - 1)) == 0; }

/* Iterative radix-2 decimation in time: bit-reversal permutation, then
 * log2(n) stages of butterflies. Twiddles in double, each from its own
 * angle rather than a recurrence, so the error does not grow with n. */
void sdrs_fft(float *re, float *im, int n) {
    for (int i = 1, j = 0; i < n; i++) {
        int bit = n >> 1;
        for (; j & bit; bit >>= 1) j ^= bit;
        j ^= bit;
        if (i < j) {
            float t = re[i]; re[i] = re[j]; re[j] = t;
            t = im[i]; im[i] = im[j]; im[j] = t;
        }
    }
    for (int len = 2; len <= n; len <<= 1) {
        int half = len >> 1;
        double step = -2.0 * M_PI / len;
        for (int k = 0; k < half; k++) {
            double wr = cos(step * k), wi = sin(step * k);
            for (int i = k; i < n; i += len) {
                int j = i + half;
                double xr = re[j] * wr - im[j] * wi;
                double xi = re[j] * wi + im[j] * wr;
                re[j] = (float)(re[i] - xr);
                im[j] = (float)(im[i] - xi);
                re[i] = (float)(re[i] + xr);
                im[i] = (float)(im[i] + xi);
            }
        }
    }
}

double sdrs_hann(float *w, int n) {
    double sum = 0;
    for (int i = 0; i < n; i++) {
        w[i] = (float)(0.5 - 0.5 * cos(2.0 * M_PI * i / n));
        sum += w[i];
    }
    return sum;
}

void sdrs_frame_power(const float *iq, int n, const float *w,
                      float *re, float *im, float *pow) {
    for (int i = 0; i < n; i++) {
        re[i] = iq[2 * i] * w[i];
        im[i] = iq[2 * i + 1] * w[i];
    }
    sdrs_fft(re, im, n);
    int h = n / 2;
    for (int k = 0; k < n; k++) {
        int s = (k + h) & (n - 1);          /* bin k lands at shifted s */
        pow[s] = re[k] * re[k] + im[k] * im[k];
    }
}

float sdrs_pow_dbfs(float pow, double wsum) {
    if (!(pow > 0)) return SDRS_NONE_DB;
    return (float)(10.0 * log10(pow) - 20.0 * log10(wsum));
}

static int cmp_float(const void *a, const void *b) {
    float x = *(const float *)a, y = *(const float *)b;
    return (x > y) - (x < y);
}

float sdrs_median(const float *v, int n, float *scratch) {
    if (n <= 0) return NAN;
    if (scratch != v) memcpy(scratch, v, (size_t)n * sizeof(*v));
    qsort(scratch, (size_t)n, sizeof(*scratch), cmp_float);
    return n & 1 ? scratch[n / 2] : 0.5f * (scratch[n / 2 - 1] + scratch[n / 2]);
}

/* ── the plan ── */

int sdrs_plan_check(sdrs_plan_t *p, const char **why) {
    if (!sdrs_is_pow2(p->nfft) || p->nfft < SDRS_NFFT_MIN || p->nfft > SDRS_NFFT_MAX) {
        *why = "nfft must be a power of two in 256..65536"; return -1;
    }
    if (!(p->rate > 0) || !(p->keep > 0) || p->keep > p->rate) {
        *why = "the kept width must be positive and no wider than the sample rate"; return -1;
    }
    if (!(p->dc_guard >= 0) || p->dc_guard * 2 >= p->keep) {
        *why = "the DC guard must be smaller than half the kept width"; return -1;
    }
    if (!(p->dev_max > p->dev_min)) { *why = "the device reports no frequency range"; return -1; }
    if (p->f_lo < p->dev_min) p->f_lo = p->dev_min;
    if (p->f_hi > p->dev_max) p->f_hi = p->dev_max;
    if (!(p->f_hi > p->f_lo)) { *why = "the span is empty inside the device's range"; return -1; }
    return 0;
}

int sdrs_plan_steps(const sdrs_plan_t *p, double *centres, int max) {
    int n = (int)ceil((p->f_hi - p->f_lo) / p->keep - 1e-9);
    if (n < 1) n = 1;
    if (n > max) return -1;
    for (int i = 0; i < n; i++) {
        double c = p->f_lo + p->keep * (i + 0.5);
        if (c > p->dev_max) c = p->dev_max;
        if (c < p->dev_min) c = p->dev_min;
        centres[i] = c;
    }
    return n;
}

int sdrs_plan_kept(const sdrs_plan_t *p, int *k, int max) {
    double bin = p->rate / p->nfft;
    int n = 0;
    for (int s = 0; s < p->nfft; s++) {
        double off = (s - p->nfft / 2) * bin;
        double a = fabs(off);
        if (a <= p->keep / 2 && a > p->dc_guard && n < max) k[n++] = s;
    }
    return n;
}

/* ── one run ── */

double sdrs_run_freq(const sdrs_run_t *r, int step, int j) {
    return r->centres[step] + (r->kept[j] - r->plan.nfft / 2) * r->bin_hz;
}

void sdrs_run_free(sdrs_run_t *r) {
    free(r->centres); free(r->kept); free(r->valid); free(r->avg_sum);
    free(r->pk_snr); free(r->pk_db); free(r->seen); free(r->step_rows);
    free(r->disp_idx); free(r->row_db); free(r->row_floor); free(r->scratch);
    memset(r, 0, sizeof(*r));
}

int sdrs_run_init(sdrs_run_t *r, const sdrs_plan_t *p, double disp_hz) {
    memset(r, 0, sizeof(*r));
    r->plan = *p;
    r->bin_hz = p->rate / p->nfft;
    r->disp_hz = disp_hz;
    double nd = ceil((p->f_hi - p->f_lo) / disp_hz - 1e-9);
    if (!(disp_hz > 0) || nd < 1 || nd > SDRS_DISP_MAX) return -1;
    r->ndisp = (int)nd;
    r->centres = malloc(SDRS_STEPS_MAX * sizeof(*r->centres));
    r->kept = malloc((size_t)p->nfft * sizeof(*r->kept));
    if (!r->centres || !r->kept) { sdrs_run_free(r); return -1; }
    r->nsteps = sdrs_plan_steps(p, r->centres, SDRS_STEPS_MAX);
    r->nkept = sdrs_plan_kept(p, r->kept, p->nfft);
    if (r->nsteps < 1 || r->nkept < 1) { sdrs_run_free(r); return -1; }
    size_t nb = (size_t)r->nsteps * (size_t)r->nkept;
    r->valid = calloc(nb, 1);
    r->avg_sum = calloc(nb, sizeof(float));
    r->pk_snr = malloc(nb * sizeof(float));
    r->pk_db = malloc(nb * sizeof(float));
    r->seen = calloc(nb, sizeof(uint16_t));
    r->disp_idx = malloc(nb * sizeof(int));
    r->step_rows = calloc((size_t)r->nsteps, sizeof(uint16_t));
    r->row_db = malloc((size_t)r->ndisp * sizeof(float));
    r->row_floor = malloc((size_t)r->nsteps * sizeof(float));
    int sc = r->nkept > r->nsteps ? r->nkept : r->nsteps;
    r->scratch = malloc((size_t)sc * sizeof(float));
    if (!r->valid || !r->avg_sum || !r->pk_snr || !r->pk_db || !r->seen || !r->disp_idx ||
        !r->step_rows || !r->row_db || !r->row_floor || !r->scratch) {
        sdrs_run_free(r);
        return -1;
    }
    /* A bin is the run's when it lies in the span and above everything
     * an earlier step covered: the last step, clamped to the device's
     * top, overlaps its neighbour, and a frequency is counted once. */
    double prev_hi = -1;
    for (int s = 0; s < r->nsteps; s++) {
        double hi = prev_hi;
        for (int j = 0; j < r->nkept; j++) {
            size_t b = (size_t)s * r->nkept + j;
            double f = sdrs_run_freq(r, s, j);
            r->pk_snr[b] = -1e9f;
            r->pk_db[b] = SDRS_NONE_DB;
            r->valid[b] = f >= p->f_lo && f <= p->f_hi && f > prev_hi;
            int d = (int)floor((f - p->f_lo) / disp_hz);
            r->disp_idx[b] = r->valid[b] && d >= 0 && d < r->ndisp ? d : -1;
            if (f > hi) hi = f;
        }
        prev_hi = hi;
    }
    return 0;
}

void sdrs_run_row_begin(sdrs_run_t *r) {
    for (int i = 0; i < r->ndisp; i++) r->row_db[i] = SDRS_NONE_DB;
    for (int s = 0; s < r->nsteps; s++) r->row_floor[s] = NAN;
}

float sdrs_run_step(sdrs_run_t *r, int step, const float *mean_db, const float *max_db) {
    int nk = r->nkept;
    float *tmp = r->scratch;
    for (int j = 0; j < nk; j++) tmp[j] = mean_db[r->kept[j]];
    /* The floor is the median of the kept bins' frame mean: a handful
     * of carriers in 6 MHz move it by nothing, a band full of them by
     * little, and it needs no model of the noise. */
    float fl = sdrs_median(tmp, nk, tmp);
    r->row_floor[step] = fl;
    r->step_rows[step]++;
    for (int j = 0; j < nk; j++) {
        size_t b = (size_t)step * nk + j;
        if (!r->valid[b]) continue;
        float m = mean_db[r->kept[j]], x = max_db[r->kept[j]];
        float sa = m - fl, sp = x - fl;
        r->avg_sum[b] += sa;
        if (sp > r->pk_snr[b]) r->pk_snr[b] = sp;
        if (x > r->pk_db[b]) r->pk_db[b] = x;
        if ((sa >= SDRS_DET_AVG_DB || sp >= SDRS_DET_PEAK_DB) && r->seen[b] < UINT16_MAX)
            r->seen[b]++;
        int d = r->disp_idx[b];
        if (d >= 0 && x > r->row_db[d]) r->row_db[d] = x;
    }
    return fl;
}

float sdrs_run_row_end(sdrs_run_t *r, uint8_t *q) {
    for (int i = 0; i < r->ndisp; i++) q[i] = sdrs_quant(r->row_db[i]);
    int n = 0;
    for (int s = 0; s < r->nsteps; s++)
        if (!isnan(r->row_floor[s])) r->scratch[n++] = r->row_floor[s];
    float f = n ? sdrs_median(r->scratch, n, r->scratch) : NAN;
    r->rows++;
    return f;
}

/* ── peaks ── */

static int flagged(const sdrs_run_t *r, size_t b, int s) {
    if (!r->valid[b] || !r->step_rows[s]) return 0;
    float avg = r->avg_sum[b] / r->step_rows[s];
    return avg >= SDRS_DET_AVG_DB || r->pk_snr[b] >= SDRS_DET_PEAK_DB;
}

static int cmp_snr_desc(const void *a, const void *b) {
    float x = ((const sdrs_peak_t *)a)->snr_peak, y = ((const sdrs_peak_t *)b)->snr_peak;
    return (x < y) - (x > y);
}

static int cmp_freq(const void *a, const void *b) {
    double x = ((const sdrs_peak_t *)a)->freq_hz, y = ((const sdrs_peak_t *)b)->freq_hz;
    return (x > y) - (x < y);
}

typedef struct {
    double lo, hi, best_f;
    float  avg, snr, db;
    int    rows;
} cl_t;

static void cl_fold(cl_t *c, const cl_t *o) {
    if (o->hi > c->hi) c->hi = o->hi;
    if (o->avg > c->avg) c->avg = o->avg;
    if (o->snr > c->snr) c->snr = o->snr;
    if (o->db > c->db) { c->db = o->db; c->best_f = o->best_f; }
    if (o->rows > c->rows) c->rows = o->rows;
}

int sdrs_run_peaks(const sdrs_run_t *r, sdrs_peak_t *out, int max) {
    int cap = 1024, n = 0;
    cl_t *cl = malloc((size_t)cap * sizeof(*cl));
    if (!cl) return -1;
    double gap = (SDRS_GAP_BINS + 1) * r->bin_hz + r->bin_hz * 0.01;
    int open = 0;
    for (int s = 0; s < r->nsteps; s++) {
        for (int j = 0; j < r->nkept; j++) {
            size_t b = (size_t)s * r->nkept + j;
            if (!flagged(r, b, s)) continue;
            double f = sdrs_run_freq(r, s, j);
            cl_t one = { f, f, f, r->avg_sum[b] / r->step_rows[s], r->pk_snr[b],
                         r->pk_db[b], r->seen[b] };
            /* Bins at most SDRS_GAP_BINS apart join; then a cluster
             * within SDRS_MERGE_HZ of the one before it merges, which
             * is the same test with the wider distance. */
            if (open && f - cl[n - 1].hi <= (gap > SDRS_MERGE_HZ ? gap : SDRS_MERGE_HZ)) {
                cl_fold(&cl[n - 1], &one);
                continue;
            }
            if (n == cap) {
                cl_t *g = realloc(cl, (size_t)cap * 2 * sizeof(*cl));
                if (!g) { free(cl); return -1; }
                cl = g;
                cap *= 2;
            }
            cl[n++] = one;
            open = 1;
        }
    }
    sdrs_peak_t *all = malloc((size_t)(n ? n : 1) * sizeof(*all));
    if (!all) { free(cl); return -1; }
    for (int i = 0; i < n; i++) {
        all[i].freq_hz = cl[i].best_f;
        all[i].width_hz = cl[i].hi - cl[i].lo + r->bin_hz;
        all[i].snr_avg = cl[i].avg;
        all[i].snr_peak = cl[i].snr;
        all[i].dbfs = cl[i].db;
        all[i].rows = cl[i].rows;
        all[i].note = SDRS_NOTE_NONE;
    }
    free(cl);
    if (n > max) {
        qsort(all, (size_t)n, sizeof(*all), cmp_snr_desc);
        n = max;
    }
    qsort(all, (size_t)n, sizeof(*all), cmp_freq);
    memcpy(out, all, (size_t)n * sizeof(*out));
    free(all);
    return n;
}

int sdrs_is_clock_harmonic(double f) {
    if (f <= SDRS_CLOCK_MIN_HZ) return 0;
    double k = floor(f / SDRS_CLOCK_HZ + 0.5);
    return fabs(f - k * SDRS_CLOCK_HZ) <= SDRS_CLOCK_TOL_HZ;
}

void sdrs_label(sdrs_peak_t *p, int n, const sdrs_peak_t *cal, int ncal) {
    for (int i = 0; i < n; i++) {
        p[i].note = sdrs_is_clock_harmonic(p[i].freq_hz) ? SDRS_NOTE_CLOCK : SDRS_NOTE_NONE;
        for (int c = 0; cal && c < ncal; c++) {
            double tol = (cal[c].width_hz + p[i].width_hz) / 2;
            if (tol < SDRS_CAL_TOL_HZ) tol = SDRS_CAL_TOL_HZ;
            if (fabs(cal[c].freq_hz - p[i].freq_hz) <= tol &&
                p[i].dbfs <= cal[c].dbfs + SDRS_CAL_DB) {
                p[i].note = SDRS_NOTE_INTERNAL;
                break;
            }
        }
    }
}

const char *sdrs_note_name(int note) {
    switch (note) {
    case SDRS_NOTE_CLOCK:    return "clock harmonic?";
    case SDRS_NOTE_INTERNAL: return "internal";
    default:                 return "";
    }
}

/* ── formats ── */

uint8_t sdrs_quant(float dbfs) {
    if (!(dbfs > SDRS_Q_OFFSET_DB)) return 0;
    double q = floor((dbfs - SDRS_Q_OFFSET_DB) / SDRS_Q_STEP_DB + 0.5);
    return q >= 255 ? 255 : (uint8_t)q;
}

size_t sdrs_b64(const uint8_t *in, size_t n, char *out) {
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = 0, i = 0;
    for (; i + 2 < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = A[v >> 18]; out[o++] = A[(v >> 12) & 63];
        out[o++] = A[(v >> 6) & 63]; out[o++] = A[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16 | (i + 1 < n ? (uint32_t)in[i + 1] << 8 : 0);
        out[o++] = A[v >> 18];
        out[o++] = A[(v >> 12) & 63];
        out[o++] = i + 1 < n ? A[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

void sdrs_json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') { fputc('\\', f); fputc(*p, f); }
        else if (*p < 0x20 || *p == 0x7f) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

/* A float as JSON: NAN and the infinities are not numbers there. */
static void num(FILE *f, double v, int prec) {
    if (isnan(v) || isinf(v)) fputs("null", f);
    else fprintf(f, "%.*f", prec, v);
}

static void kv_str(FILE *f, const char *k, const char *v) {
    fprintf(f, "\"%s\":", k);
    sdrs_json_str(f, v);
    fputc(',', f);
}

int sdrs_write_json(FILE *f, const sdrs_meta_t *m, const sdrs_run_t *r,
                    const sdrs_row_t *rows, int nrows,
                    const sdrs_peak_t *peaks, int npeaks) {
    fputs("{\"version\":1,", f);
    kv_str(f, "mode", m->mode);
    fprintf(f, "\"complete\":%s,\"started\":", m->complete ? "true" : "false");
    num(f, m->started, 3);
    fputs(",\"ended\":", f);
    num(f, m->ended, 3);
    fputc(',', f);
    kv_str(f, "device", m->device);
    kv_str(f, "driver", m->driver);
    kv_str(f, "hardware", m->hardware);
    kv_str(f, "serial", m->serial);
    kv_str(f, "antenna", m->antenna);
    kv_str(f, "gain", m->gain);
    fprintf(f, "\"sample_rate\":%.0f,\"bandwidth\":%.0f,\"keep_hz\":%.0f,"
               "\"dc_guard_hz\":%.0f,\"nfft\":%d,\"frames\":%d,\"duration\":%.0f,",
            m->rate, m->bandwidth, m->keep, m->dc_guard, m->nfft, m->frames, m->duration);
    fprintf(f, "\"calibrated\":%s,\"steps\":%d,", m->calibrated ? "true" : "false",
            r->nsteps);
    fprintf(f, "\"f_lo\":%.0f,\"f_hi\":%.0f,\"bin_hz\":%.0f,\"bins\":%d,",
            r->plan.f_lo, r->plan.f_hi, r->disp_hz, r->ndisp);
    fprintf(f, "\"fft_bin_hz\":%.3f,\"quant\":{\"offset_db\":%.1f,\"step_db\":%.1f},\n",
            r->bin_hz, SDRS_Q_OFFSET_DB, SDRS_Q_STEP_DB);
    fputs("\"rows\":[", f);
    char *b64 = malloc(4 * ((size_t)r->ndisp / 3 + 1) + 1);
    if (!b64) return -1;
    for (int i = 0; i < nrows; i++) {
        sdrs_b64(rows[i].q, (size_t)r->ndisp, b64);
        fprintf(f, "%s\n{\"t\":", i ? "," : "");
        num(f, rows[i].t, 3);
        fputs(",\"floor\":", f);
        num(f, rows[i].floor, 1);
        fprintf(f, ",\"data\":\"%s\"}", b64);
    }
    free(b64);
    fputs("],\n\"peaks\":[", f);
    for (int i = 0; i < npeaks; i++) {
        const sdrs_peak_t *p = &peaks[i];
        fprintf(f, "%s\n{\"freq_hz\":%.0f,\"width_hz\":%.0f,\"snr_avg\":", i ? "," : "",
                p->freq_hz, p->width_hz);
        num(f, p->snr_avg, 1);
        fputs(",\"snr_peak\":", f);
        num(f, p->snr_peak, 1);
        fputs(",\"dbfs\":", f);
        num(f, p->dbfs, 1);
        fprintf(f, ",\"rows\":%d,\"note\":", p->rows);
        sdrs_json_str(f, sdrs_note_name(p->note));
        fputc('}', f);
    }
    fputs("]}\n", f);
    return ferror(f) ? -1 : 0;
}

double sdrs_json_num(const char *text, const char *key, double def) {
    char pat[64];
    int n = snprintf(pat, sizeof(pat), "\"%s\":", key);
    if (n < 0 || (size_t)n >= sizeof(pat)) return def;
    const char *p = strstr(text, pat);
    if (!p) return def;
    p += n;
    char *end;
    double v = strtod(p, &end);
    return end == p || isnan(v) || isinf(v) ? def : v;
}

int sdrs_parse_cal(const char *text, sdrs_peak_t *out, int max) {
    int n = 0;
    for (const char *l = text; l && *l && n < max; ) {
        const char *nl = strchr(l, '\n');
        size_t len = nl ? (size_t)(nl - l) : strlen(l);
        char line[512];
        if (len < sizeof(line)) {
            memcpy(line, l, len);
            line[len] = '\0';
            if (strstr(line, "\"freq_hz\":") && strstr(line, "\"dbfs\":")) {
                double f = sdrs_json_num(line, "freq_hz", NAN);
                double d = sdrs_json_num(line, "dbfs", NAN);
                if (!isnan(f) && !isnan(d)) {
                    memset(&out[n], 0, sizeof(out[n]));
                    out[n].freq_hz = f;
                    out[n].dbfs = (float)d;
                    out[n].width_hz = sdrs_json_num(line, "width_hz", 0);
                    n++;
                }
            }
        }
        l = nl ? nl + 1 : NULL;
    }
    return n;
}
