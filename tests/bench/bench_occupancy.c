/* Max-occupancy bench (#91): the two synthesis passes the external
 * review called out as superlinear, timed with every table they read
 * filled to capacity.
 *
 *   seqnum correlation   MAX_SEQNUM_CLIENTS (256) rotating, randomised
 *                        MACs with full SEQNUM_HISTORY_LEN (8) histories,
 *                        after 256 more were churned through and evicted.
 *   PNL union            MAX_PNL_CLIENTS (128) x MAX_PNL_SSIDS_PER_CLI
 *                        (16) distinct SSIDs, read by karma_update() and
 *                        rule_karma_ap() against MAX_BEACON_APS (256)
 *                        SSID-cycling beacons.
 *
 * Each input is shaped to defeat the early-outs, so the figure is a
 * ceiling, not a typical tick:
 *
 *   - seqnum: every pair passes freshness, ordering, the dt window and
 *     the forward-gap test, then fails trail continuity on the LAST step
 *     - so no pair is accepted, the MAX_SEQNUM_CORRELATIONS cap never
 *     trips, and all 32,640 pairs pay the full per-pair cost in both
 *     directions. A second shape, 32 radios each rotating through 8
 *     addresses, is the realistic case and is reported beside it.
 *   - PNL: all 2,048 SSIDs are distinct, so the union's duplicate search
 *     never finds a match and stops early, and no beacon SSID is in any
 *     PNL, so every per-AP scan runs to the end.
 *
 * Built against the shipped configuration's -O2 core archive, not the
 * -O0 test build - a bench of unoptimised code would overstate the cost
 * by several times. Not part of `make test`: it times, it does not
 * assert behaviour, and a timing threshold in the suite would fail on a
 * slow CI runner for no defect. It does assert occupancy, and exits
 * non-zero if any table is short of capacity, because a bench that
 * silently ran half-full would report a reassuring number for the wrong
 * reason.
 *
 * Run: make bench [BENCH_ITERS=n]. Record the result in
 * docs/wiki/ring-buffers.md with the host and command. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sloth.h"
#include "seqnum_track.h"
#include "probe_pnl.h"
#include "karma_detect.h"
#include "alerts.h"
#include "alerts/rules.h"
#include "sensor_health.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

typedef struct { double min, med, max; } stat_t;

static stat_t summarise(double *v, int n) {
    qsort(v, (size_t)n, sizeof(*v), cmp_d);
    stat_t s = { v[0], v[n / 2], v[n - 1] };
    return s;
}

static void report(const char *name, stat_t s) {
    printf("  %-34s min %8.3f  median %8.3f  max %8.3f ms\n",
           name, s.min, s.med, s.max);
}

/* Randomised (locally administered, unicast) MAC from an index. */
static void mk_mac(uint8_t m[6], uint8_t tag, int i) {
    m[0] = 0x02 | (uint8_t)(tag << 2);
    m[1] = 0xbe; m[2] = 0x7c;
    m[3] = (uint8_t)(i >> 8); m[4] = (uint8_t)i; m[5] = 0x5a;
}

static int fail;

static void need(int ok, const char *what) {
    if (!ok) { fprintf(stderr, "bench: not at capacity: %s\n", what); fail = 1; }
}

/* Every pair reaches hist_runs_forward() and fails there on the last
 * step: oldest..newest is 110,111,...,116 then 100. The newest (100)
 * is 10 behind every other trail's oldest (110), so the forward-gap
 * test passes for every ordered pair; timestamps are all equal, which
 * the ordering test allows. */
static void fill_seqnum_adversarial(time_t t) {
    seqnum_clear();
    uint8_t m[6];
    for (int i = 0; i < MAX_SEQNUM_CLIENTS; i++) {    /* churn, evicted below */
        mk_mac(m, 1, i);
        seqnum_track_observe_at(m, 50, t - 200);
    }
    for (int i = 0; i < MAX_SEQNUM_CLIENTS; i++) {
        mk_mac(m, 2, i);
        for (int k = 0; k < SEQNUM_HISTORY_LEN - 1; k++)
            seqnum_track_observe_at(m, (uint16_t)(110 + k), t);
        seqnum_track_observe_at(m, 100, t);
    }
}

/* 32 radios x 8 addresses: each address carries a forward-running
 * trail and the next address picks the counter up a few frames later,
 * a second on. The shape correlation exists to find. */
static void fill_seqnum_rotation(time_t t) {
    seqnum_clear();
    uint8_t m[6];
    for (int i = 0; i < MAX_SEQNUM_CLIENTS; i++) {
        mk_mac(m, 1, i);
        seqnum_track_observe_at(m, 50, t - 200);
    }
    for (int r = 0; r < 32; r++) {
        uint16_t seq = (uint16_t)(r * 128);
        for (int a = 0; a < 8; a++) {
            mk_mac(m, 3, r * 8 + a);
            time_t ts = t - 16 + 2 * a;
            for (int k = 0; k < SEQNUM_HISTORY_LEN; k++)
                seqnum_track_observe_at(m, (uint16_t)(seq++ & 0x0FFF), ts);
            seq = (uint16_t)(seq + 3);
        }
    }
}

static stat_t time_seqnum(sloth_state_t *s, time_t t, int iters, double *buf) {
    for (int i = 0; i < iters; i++) {
        double a = now_ms();
        seqnum_snapshot_at(s, t);
        buf[i] = now_ms() - a;
    }
    return summarise(buf, iters);
}

static void fill_pnl_and_beacons(sloth_state_t *s, time_t t) {
    uint8_t m[6];
    char ssid[33];
    for (int c = 0; c < MAX_PNL_CLIENTS; c++) {
        mk_mac(m, 0, c);
        for (int k = 0; k < MAX_PNL_SSIDS_PER_CLI; k++) {
            snprintf(ssid, sizeof(ssid), "pnl-%03d-%02d", c, k);
            probe_pnl_observe(m, ssid, NULL, NULL);
        }
    }
    probe_pnl_snapshot(s);
    s->beacon_count = MAX_BEACON_APS;
    for (int b = 0; b < MAX_BEACON_APS; b++) {
        beacon_ap_t *a = &s->beacon_aps[b];
        memset(a, 0, sizeof(*a));
        mk_mac(a->bssid, 3, b);
        a->bssid[0] = 0x00;                         /* a real-looking OUI */
        for (int h = 0; h < MAX_AP_SSID_HISTORY; h++)
            snprintf(a->ssid_history[h], sizeof(a->ssid_history[h]),
                     "lure-%03d-%d", b, h);
        a->ssid_history_n = MAX_AP_SSID_HISTORY;
        snprintf(a->ssid, sizeof(a->ssid), "%s", a->ssid_history[0]);
        a->first_seen = t - 60;
        a->last_seen  = t;
    }
}

int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 50;
    if (iters < 1) iters = 1;
    double *buf = calloc((size_t)iters, sizeof(double));
    sloth_state_t *s = calloc(1, sizeof(*s));
    if (!buf || !s) { fprintf(stderr, "bench: out of memory\n"); return 2; }
    time_t t = time(NULL);

    printf("sloth max-occupancy bench (#91), %d iterations\n", iters);

    sh_evict_reset();
    fill_seqnum_adversarial(t);
    need(seqnum_client_count() == MAX_SEQNUM_CLIENTS, "seqnum clients");
    int acc = -1, maxc = -1;
    int pairs = seqnum_corr_candidate_pairs(t, &acc, &maxc);
    stat_t sq = time_seqnum(s, t, iters, buf);
    need(s->seqnum_count == MAX_SEQNUM_CLIENTS, "seqnum snapshot");
    for (int i = 0; i < s->seqnum_count; i++)
        need(s->seqnum_clients[i].hist_n == SEQNUM_HISTORY_LEN, "seqnum history");
    printf("seqnum: %d clients x %d history, %d pairs compared, %d accepted, "
           "%llu evicted while filling\n",
           seqnum_client_count(), SEQNUM_HISTORY_LEN, pairs, acc,
           (unsigned long long)sh_evict_count(SH_EVICT_SEQNUM_CLIENT));
    report("seqnum_snapshot (no early-out)", sq);

    fill_seqnum_rotation(t);
    need(seqnum_client_count() == MAX_SEQNUM_CLIENTS, "seqnum rotation clients");
    stat_t sr = time_seqnum(s, t, iters, buf);
    printf("seqnum rotation shape: %d correlations reported (cap %d)\n",
           s->seqnum_correlation_count, MAX_SEQNUM_CORRELATIONS);
    report("seqnum_snapshot (32 radios x 8)", sr);

    probe_pnl_clear();
    fill_pnl_and_beacons(s, t);
    need(s->pnl_count == MAX_PNL_CLIENTS, "pnl clients");
    for (int c = 0; c < s->pnl_count; c++)
        need(s->pnl_clients[c].ssid_count == MAX_PNL_SSIDS_PER_CLI, "pnl ssids");

    for (int i = 0; i < iters; i++) {
        double a = now_ms();
        karma_update(s);
        buf[i] = now_ms() - a;
    }
    stat_t ku = summarise(buf, iters);
    need(s->karma_count == MAX_KARMA_APS, "karma candidates");

    for (int i = 0; i < iters; i++) {
        alerts_clear();
        double a = now_ms();
        rule_karma_ap(s, t);
        buf[i] = now_ms() - a;
    }
    stat_t rk = summarise(buf, iters);

    printf("pnl: %d clients x %d SSIDs (all distinct), %d beacons x %d SSIDs, "
           "%d karma candidates\n",
           s->pnl_count, MAX_PNL_SSIDS_PER_CLI, s->beacon_count,
           MAX_AP_SSID_HISTORY, s->karma_count);
    report("karma_update (union + per-AP)", ku);
    report("rule_karma_ap", rk);

    printf("worst-case sum per tick (medians): %.3f ms\n",
           sq.med + ku.med + rk.med);

    free(buf);
    free(s);
    if (fail) return 1;
    return 0;
}
