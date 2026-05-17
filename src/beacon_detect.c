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

int bd_is_strong(const char *remote_ip, uint16_t port) {
    double mean = 0, jitter = 0;
    int n = bd_stats(remote_ip, port, &mean, &jitter);
    if (n < BD_MIN_SAMPLES)        return 0;
    if (mean < BD_MIN_INTERVAL_S)  return 0;
    if (mean <= 0)                 return 0;
    if (jitter / mean > BD_MAX_JITTER_RATIO) return 0;
    return 1;
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
