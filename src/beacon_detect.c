#include <stdio.h>
#include <string.h>
#include <math.h>
#include "beacon_detect.h"

static bd_track_t tracks[BD_MAX_TRACKS];
static int        track_count;

static bd_track_t *find(const char *ip, uint16_t port) {
    for (int i = 0; i < track_count; i++) {
        if (tracks[i].remote_port == port &&
            strcmp(tracks[i].remote_ip, ip) == 0)
            return &tracks[i];
    }
    return NULL;
}

static bd_track_t *upsert(const char *ip, uint16_t port) {
    bd_track_t *t = find(ip, port);
    if (t) return t;
    if (track_count >= BD_MAX_TRACKS) {
        int oldest = 0;
        for (int i = 1; i < track_count; i++) {
            if (tracks[i].last_active < tracks[oldest].last_active)
                oldest = i;
        }
        memset(&tracks[oldest], 0, sizeof(tracks[oldest]));
        snprintf(tracks[oldest].remote_ip,
                 sizeof(tracks[oldest].remote_ip), "%s", ip);
        tracks[oldest].remote_port = port;
        return &tracks[oldest];
    }
    t = &tracks[track_count++];
    memset(t, 0, sizeof(*t));
    snprintf(t->remote_ip, sizeof(t->remote_ip), "%s", ip);
    t->remote_port = port;
    return t;
}

void bd_observe(const char *remote_ip, uint16_t port, time_t now) {
    if (!remote_ip || !remote_ip[0]) return;
    bd_track_t *t = upsert(remote_ip, port);
    if (!t) return;
    t->samples[t->head] = now;
    t->head = (t->head + 1) % BD_MAX_SAMPLES;
    if (t->sample_count < BD_MAX_SAMPLES) t->sample_count++;
    t->last_active = now;
}

void bd_update(const sloth_state_t *s, time_t now) {
    if (!s) return;
    for (int i = 0; i < s->conn_count; i++) {
        const conn_t *c = &s->conns[i];
        if (!c->remote_addr[0] || c->remote_port == 0) continue;
        bd_track_t *t = find(c->remote_addr, c->remote_port);
        if (!t || (now - t->last_active) >= BD_GAP_S) {
            bd_observe(c->remote_addr, c->remote_port, now);
        } else {
            t->last_active = now;
        }
    }
}

static int collect_sorted(const bd_track_t *t, time_t out[BD_MAX_SAMPLES]) {
    int n = t->sample_count;
    if (n <= 0) return 0;
    int start = (n < BD_MAX_SAMPLES) ? 0 : t->head;
    for (int i = 0; i < n; i++)
        out[i] = t->samples[(start + i) % BD_MAX_SAMPLES];
    return n;
}

int bd_stats(const char *remote_ip, uint16_t port,
             double *mean_s, double *jitter_s) {
    if (mean_s)   *mean_s = 0.0;
    if (jitter_s) *jitter_s = 0.0;
    bd_track_t *t = find(remote_ip, port);
    if (!t) return 0;

    time_t pts[BD_MAX_SAMPLES];
    int n = collect_sorted(t, pts);
    if (n < 2) return n;

    double sum = 0.0;
    int    gaps = n - 1;
    for (int i = 1; i < n; i++) sum += (double)(pts[i] - pts[i - 1]);
    double mean = sum / gaps;

    double sq = 0.0;
    for (int i = 1; i < n; i++) {
        double d = (double)(pts[i] - pts[i - 1]) - mean;
        sq += d * d;
    }
    double var = (gaps > 0) ? (sq / gaps) : 0.0;
    double stddev = sqrt(var);

    if (mean_s)   *mean_s   = mean;
    if (jitter_s) *jitter_s = stddev;
    return n;
}

/* ── v2: gap-concentration test ─────────────────────────────
 *
 * v1's stddev/mean ratio is sensitive to outliers and rules out the
 * jittered beacons we actually want to catch. v2 instead uses a
 * robust *concentration* statistic: the fraction of inter-arrival
 * gaps that fall within ±30% of the median gap.
 *
 * Math intuition (with truths derived from the additive-jitter model
 * t_i = i·T + U[-j·T, j·T]):
 *   - At  0% jitter, all gaps == median → concentration = 1.00
 *   - At 25% jitter, ~87% of gaps inside ±30% of median  → 0.87
 *   - At 30% jitter, ~75%                                 → 0.75
 *   - At 40% jitter, ~60%                                 → 0.60  ← threshold
 *   - At 50% jitter, ~50%
 *   - Pure uniform-random gaps on [0, 2·median] → ~30%
 *
 * Periodic structure is robust against jitter under this measure in
 * a way it isn't under stddev/mean. The trade-off is we no longer
 * "search" for a period — we just report the median. For the
 * detection question that's enough; the *exact* period can drift
 * within the recovery range without affecting the fire decision. */
static int bd_concentration_compute(const time_t *samples, int n,
                                    double *out_median,
                                    double *out_concentration) {
    if (n < BD_MIN_SAMPLES_V2) return 0;

    long gaps[BD_MAX_SAMPLES];
    int gn = 0;
    for (int i = 1; i < n; i++) {
        long g = (long)(samples[i] - samples[i - 1]);
        if (g < 0) g = -g;
        gaps[gn++] = g;
    }
    /* Sort by insertion — gn ≤ 15 so quadratic is fine. */
    long sorted[BD_MAX_SAMPLES];
    memcpy(sorted, gaps, (size_t)gn * sizeof(long));
    for (int i = 1; i < gn; i++) {
        long key = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > key) {
            sorted[j + 1] = sorted[j];
            j--;
        }
        sorted[j + 1] = key;
    }
    double median = (double)sorted[gn / 2];
    if (median < (double)BD_MIN_INTERVAL_S) return 0;

    double lo = median * 0.70;
    double hi = median * 1.30;
    int in_window = 0;
    for (int i = 0; i < gn; i++) {
        double g = (double)gaps[i];
        if (g >= lo && g <= hi) in_window++;
    }
    *out_median        = median;
    *out_concentration = (double)in_window / (double)gn;
    return n;
}

int bd_autocorr_stats(const char *remote_ip, uint16_t port,
                      double *period_s, double *concentration) {
    if (period_s)      *period_s      = 0.0;
    if (concentration) *concentration = 0.0;
    bd_track_t *t = find(remote_ip, port);
    if (!t) return 0;

    time_t pts[BD_MAX_SAMPLES];
    int n = collect_sorted(t, pts);
    double p = 0.0, c = 0.0;
    int ok = bd_concentration_compute(pts, n, &p, &c);
    if (!ok) return 0;
    if (period_s)      *period_s      = p;
    if (concentration) *concentration = c;
    return ok;
}

int bd_is_strong(const char *remote_ip, uint16_t port) {
    bd_track_t *t = find(remote_ip, port);
    if (!t) return 0;

    /* v1 — classic low-jitter test. Cheapest path; covers Cobalt
     * default and any C2 framework that hasn't dialed up jitter. */
    double mean = 0.0, jitter = 0.0;
    int n = bd_stats(remote_ip, port, &mean, &jitter);
    if (n >= BD_MIN_SAMPLES &&
        mean >= (double)BD_MIN_INTERVAL_S &&
        mean > 0.0 &&
        jitter / mean <= BD_MAX_JITTER_RATIO) {
        return 1;
    }

    /* v2 — gap concentration. Catches up to ~40% additive jitter.
     * Requires more samples than v1 to keep the false-positive rate
     * down. */
    time_t pts[BD_MAX_SAMPLES];
    int npts = collect_sorted(t, pts);
    double period = 0.0, concentration = 0.0;
    if (bd_concentration_compute(pts, npts, &period, &concentration)) {
        if (concentration >= BD_MIN_CONCENTRATION) return 2;
    }
    return 0;
}

void bd_each(bd_each_fn cb, void *ud) {
    if (!cb) return;
    for (int i = 0; i < track_count; i++) {
        if (cb(&tracks[i], ud)) return;
    }
}

void bd_clear(void) {
    track_count = 0;
    memset(tracks, 0, sizeof(tracks));
}
