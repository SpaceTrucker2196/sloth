/* Per-channel RF quality accounting. Contract in rf_quality.h (B3). */

#include <pthread.h>
#include <string.h>

#include "rf_quality.h"

typedef struct {
    int      channel;
    uint32_t frames;
    uint32_t retries;
    uint32_t bad_fcs;
    time_t   window_start;   /* when the current counting window opened */
    time_t   last_seen;
} rf_chan_t;

/* The probe thread observes (probe.c, per monitor-mode frame) while the
 * poll loop snapshots into the channel view (main.c). Unlocked, a read
 * could land on a slot mid-eviction and report one channel's counters
 * under another's number. g_mu is a leaf: only arithmetic and memset
 * run while it is held, so taking it under another module's lock
 * cannot close a cycle. The static helpers below expect it held. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static rf_chan_t       g_ch[MAX_RF_CHANNELS];
static int             g_n;

static rf_chan_t *find(int channel) {
    for (int i = 0; i < g_n; i++)
        if (g_ch[i].channel == channel) return &g_ch[i];
    return NULL;
}

/* Roll the window when it has aged out. Counters are reset rather than
 * decayed: a channel that was jammed an hour ago and is clean now
 * should read clean, and a sliding decay would keep it amber for no
 * reason the operator could act on. */
static void roll_if_stale(rf_chan_t *c, time_t now) {
    if (c->window_start == 0) { c->window_start = now; return; }
    long age = (long)(now - c->window_start);
    if (age < 0) age = 0;                 /* clock stepped back */
    if (age > RF_WINDOW_SECS) {
        c->frames = c->retries = c->bad_fcs = 0;
        c->window_start = now;
    }
}

void rf_quality_observe(int channel, int retry, int bad_fcs, time_t now) {
    if (channel <= 0) return;             /* unmapped frequency */

    pthread_mutex_lock(&g_mu);
    rf_chan_t *c = find(channel);
    if (!c) {
        if (g_n < MAX_RF_CHANNELS) {
            c = &g_ch[g_n++];
            memset(c, 0, sizeof(*c));
            c->channel      = channel;
            c->window_start = now;
        } else {
            /* Table full: evict the stalest channel. A hop list longer
             * than the table would otherwise lock out whichever channel
             * the radio moved to most recently — the one being measured
             * right now. */
            int oldest = 0;
            for (int i = 1; i < g_n; i++)
                if (g_ch[i].last_seen < g_ch[oldest].last_seen) oldest = i;
            c = &g_ch[oldest];
            memset(c, 0, sizeof(*c));
            c->channel      = channel;
            c->window_start = now;
        }
    }
    roll_if_stale(c, now);

    c->frames++;
    if (retry)   c->retries++;
    if (bad_fcs) c->bad_fcs++;
    if (now > c->last_seen) c->last_seen = now;
    pthread_mutex_unlock(&g_mu);
}

/* Shared ratio helper. -1 means "not enough traffic to say", which is
 * a different answer from 0% and callers must not conflate them. */
static int pct_locked(rf_chan_t *c, time_t now, int want_fcs) {
    if (!c) return -1;
    roll_if_stale(c, now);
    if (c->frames < RF_MIN_FRAMES) return -1;
    uint32_t hits = want_fcs ? c->bad_fcs : c->retries;
    return (int)((hits * 100u) / c->frames);
}

static int pct_of(int channel, time_t now, int want_fcs) {
    pthread_mutex_lock(&g_mu);
    int pct = pct_locked(find(channel), now, want_fcs);
    pthread_mutex_unlock(&g_mu);
    return pct;
}

int rf_quality_retry_pct(int channel, time_t now)  { return pct_of(channel, now, 0); }
int rf_quality_badfcs_pct(int channel, time_t now) { return pct_of(channel, now, 1); }

int rf_quality_is_degraded(int channel, time_t now) {
    int pct = rf_quality_retry_pct(channel, now);
    return pct >= RF_RETRY_DEGRADED_PCT;   /* -1 (unknown) is not degraded */
}

/* One lock hold for the whole pass, so a row's frame count and both
 * ratios describe the same instant instead of three reads the probe
 * thread can interleave with. */
void rf_quality_snapshot(sloth_state_t *s, time_t now) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < s->channel_count; i++) {
        channel_summary_t *row = &s->channels[i];
        rf_chan_t *c = find(row->channel);
        if (!c) {
            row->frames     = 0;
            row->retry_pct  = -1;
            row->badfcs_pct = -1;
            continue;
        }
        roll_if_stale(c, now);
        row->frames     = c->frames;
        row->retry_pct  = pct_locked(c, now, 0);
        row->badfcs_pct = pct_locked(c, now, 1);
    }
    pthread_mutex_unlock(&g_mu);
}

void rf_quality_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_ch, 0, sizeof(g_ch));
    pthread_mutex_unlock(&g_mu);
}
