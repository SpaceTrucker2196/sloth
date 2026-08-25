#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "ctrl_frames.h"

/* Per-source counters, for the subtypes that name a transmitter. */
typedef struct {
    uint8_t  ta[6];
    uint32_t sub[16];        /* indexed by control subtype */
    int      max_nav;        /* highest Duration seen from this source */
    time_t   first_seen;
    time_t   last_seen;
} ctrl_src_t;

/* Per-channel totals, for everything — including CTS and ACK, which
 * carry no transmitter and can be attributed to nothing else. */
typedef struct {
    int      channel;
    uint32_t sub[16];
    uint32_t total;
    time_t   last_seen;
} ctrl_chan_t;

/* Defined below, beside the rest of the Bl0ck state. */
static void bar_observe(const uint8_t *dot11, int len, time_t now);

static ctrl_src_t      g_src[CTRL_MAX_SOURCES];
static int             g_src_n;
static ctrl_chan_t     g_chan[CTRL_MAX_CHANNELS];
static int             g_chan_n;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* Caller holds g_mu. */
static ctrl_src_t *src_slot(const uint8_t ta[6], time_t now) {
    for (int i = 0; i < g_src_n; i++)
        if (memcmp(g_src[i].ta, ta, 6) == 0) return &g_src[i];
    int slot;
    if (g_src_n < CTRL_MAX_SOURCES) {
        slot = g_src_n++;
    } else {
        slot = 0;
        for (int i = 1; i < CTRL_MAX_SOURCES; i++)
            if (g_src[i].last_seen < g_src[slot].last_seen) slot = i;
    }
    memset(&g_src[slot], 0, sizeof(g_src[slot]));
    memcpy(g_src[slot].ta, ta, 6);
    g_src[slot].first_seen = now;
    return &g_src[slot];
}

static ctrl_chan_t *chan_slot(int channel) {
    for (int i = 0; i < g_chan_n; i++)
        if (g_chan[i].channel == channel) return &g_chan[i];
    int slot;
    if (g_chan_n < CTRL_MAX_CHANNELS) {
        slot = g_chan_n++;
    } else {
        slot = 0;
        for (int i = 1; i < CTRL_MAX_CHANNELS; i++)
            if (g_chan[i].last_seen < g_chan[slot].last_seen) slot = i;
    }
    memset(&g_chan[slot], 0, sizeof(g_chan[slot]));
    g_chan[slot].channel = channel;
    return &g_chan[slot];
}

/* Which control subtypes carry a transmitter address, and where.
 *
 * RTS and the Block-Ack pair put TA at offset 10, after RA. PS-Poll's
 * layout differs: the BSSID sits where RA would be and TA follows at
 * 10 anyway. CTS and ACK have neither — they end after RA.
 *
 * Returns the TA offset, or -1 when the frame carries no transmitter. */
static int ta_offset(int subtype, int len) {
    switch (subtype) {
    case CTRL_SUB_RTS:
    case CTRL_SUB_BLOCKACK_REQ:
    case CTRL_SUB_BLOCKACK:
    case CTRL_SUB_PS_POLL:
        return len >= 16 ? 10 : -1;
    default:
        return -1;          /* CTS, ACK, CF-End: RA only */
    }
}

void ctrl_observe(const uint8_t *dot11, int len, int channel, time_t now) {
    if (!dot11 || len < 10) return;
    /* FC byte 0: bits 2-3 type, bits 4-7 subtype. Type 1 is control. */
    int type = (dot11[0] >> 2) & 0x03;
    if (type != 1) return;
    int sub = (dot11[0] >> 4) & 0x0f;

    /* Duration/ID at bytes 2-3, little-endian: the NAV reservation this
     * frame is asking every other radio to honour. */
    int nav = dot11[2] | (dot11[3] << 8);

    pthread_mutex_lock(&g_mu);

    if (channel > 0) {
        ctrl_chan_t *c = chan_slot(channel);
        c->sub[sub]++;
        c->total++;
        c->last_seen = now;
    }

    if (sub == CTRL_SUB_BLOCKACK_REQ) bar_observe(dot11, len, now);

    int off = ta_offset(sub, len);
    if (off >= 0) {
        const uint8_t *ta = dot11 + off;
        /* A group-addressed transmitter is not a transmitter. */
        if (!(ta[0] & 0x01)) {
            ctrl_src_t *s = src_slot(ta, now);
            s->sub[sub]++;
            if (nav > s->max_nav) s->max_nav = nav;
            s->last_seen = now;
        }
    }

    pthread_mutex_unlock(&g_mu);
}

/* ── Block-Ack paralysis (Bl0ck) — #70 ───────────────────── */

static sloth_bar_state_t g_bar[BAR_MAX_PAIRS];
static int               g_bar_n;

int bar_ssn_forward_distance(uint16_t from, uint16_t to) {
    /* Modulo the 12-bit sequence space. A plain (to - from) is negative
     * or enormous on every wrap, and a station transmitting steadily
     * wraps roughly every 4096 frames — which is often. This is the
     * arithmetic the whole detector rests on. */
    return (int)(((unsigned)to - (unsigned)from) & (BAR_SSN_MODULUS - 1));
}

/* Caller holds g_mu. */
static sloth_bar_state_t *bar_slot(const uint8_t bssid[6],
                                   const uint8_t sta[6], int tid,
                                   time_t now) {
    for (int i = 0; i < g_bar_n; i++)
        if (g_bar[i].tid == tid &&
            memcmp(g_bar[i].bssid, bssid, 6) == 0 &&
            memcmp(g_bar[i].sta,   sta,   6) == 0) return &g_bar[i];
    int slot;
    if (g_bar_n < BAR_MAX_PAIRS) {
        slot = g_bar_n++;
    } else {
        slot = 0;
        for (int i = 1; i < BAR_MAX_PAIRS; i++)
            if (g_bar[i].last_bar_ts < g_bar[slot].last_bar_ts) slot = i;
    }
    memset(&g_bar[slot], 0, sizeof(g_bar[slot]));
    memcpy(g_bar[slot].bssid, bssid, 6);
    memcpy(g_bar[slot].sta,   sta,   6);
    g_bar[slot].tid        = (uint8_t)tid;
    g_bar[slot].first_seen = now;
    return &g_bar[slot];
}

/* Fold a Block-Ack Request into the per-TID state. Caller holds g_mu.
 *
 * BAR layout after the header: BAR Control(2), then the Block Ack
 * Starting Sequence Control(2) — fragment number in bits 0-3, the
 * starting sequence number in bits 4-15. */
static void bar_observe(const uint8_t *dot11, int len, time_t now) {
    if (len < 20) return;
    uint16_t ctl = (uint16_t)(dot11[16] | (dot11[17] << 8));
    /* Multi-TID BARs carry a list rather than one TID and are rare
     * enough that guessing at their layout would risk inventing jumps.
     * Skipped rather than misread. */
    if (ctl & 0x0002) return;
    int tid = (ctl >> 12) & 0x0f;

    uint16_t ssc = (uint16_t)(dot11[18] | (dot11[19] << 8));
    uint16_t ssn = (uint16_t)(ssc >> 4);

    const uint8_t *ra = dot11 + 4;    /* the peer being asked to advance */
    const uint8_t *ta = dot11 + 10;   /* who the BAR claims to be from   */
    if ((ta[0] & 0x01) || (ra[0] & 0x01)) return;

    sloth_bar_state_t *b = bar_slot(ra, ta, tid, now);
    b->total_bars++;

    /* The first BAR for a triple establishes the baseline. Treating it
     * as a jump would flag every connection sloth joins mid-flight,
     * which is every connection when the sensor starts. */
    if (b->last_bar_ts) {
        int jump = bar_ssn_forward_distance(b->last_ssn, ssn);
        if (jump > BAR_SUSPICIOUS_JUMP) {
            b->suspicious_bars++;
            b->last_jump = (uint16_t)jump;
        }
    }
    b->last_ssn     = ssn;
    b->last_bar_ts  = now;
}

int bar_worst_offender(time_t now, int window_s, sloth_bar_state_t *out) {
    int best = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_bar_n; i++) {
        if (!g_bar[i].last_bar_ts) continue;
        if (now - g_bar[i].last_bar_ts > window_s) continue;
        if ((int)g_bar[i].suspicious_bars <= best) continue;
        best = (int)g_bar[i].suspicious_bars;
        if (out) *out = g_bar[i];
    }
    pthread_mutex_unlock(&g_mu);
    return best;
}

int bar_find(const uint8_t bssid[6], const uint8_t sta[6], int tid,
             sloth_bar_state_t *out) {
    int hit = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_bar_n; i++)
        if (g_bar[i].tid == tid &&
            memcmp(g_bar[i].bssid, bssid, 6) == 0 &&
            memcmp(g_bar[i].sta,   sta,   6) == 0) {
            if (out) *out = g_bar[i];
            hit = 1; break;
        }
    pthread_mutex_unlock(&g_mu);
    return hit;
}

int bar_pair_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_bar_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ctrl_channel_total(int channel) {
    int n = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_chan_n; i++)
        if (g_chan[i].channel == channel) { n = (int)g_chan[i].total; break; }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ctrl_channel_subtype(int channel, int subtype) {
    int n = 0;
    if (subtype < 0 || subtype > 15) return 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_chan_n; i++)
        if (g_chan[i].channel == channel) {
            n = (int)g_chan[i].sub[subtype]; break;
        }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ctrl_source_count(const uint8_t ta[6], int subtype) {
    int n = 0;
    if (subtype < 0 || subtype > 15) return 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_src_n; i++)
        if (memcmp(g_src[i].ta, ta, 6) == 0) { n = (int)g_src[i].sub[subtype]; break; }
    pthread_mutex_unlock(&g_mu);
    return n;
}

int ctrl_rts_flood(time_t now, int window_s, int rate_per_s, int sustain_s,
                   uint8_t out_ta[6], int *max_nav, int *duration_s) {
    int best = 0, best_nav = 0, best_dur = 0;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_src_n; i++) {
        const ctrl_src_t *s = &g_src[i];
        if (!s->last_seen || now - s->last_seen > window_s) continue;
        int n = (int)s->sub[CTRL_SUB_RTS];
        if (n <= 0) continue;

        /* Duration the source has actually been transmitting, floored at
         * one second so a burst inside a single second is not divided by
         * zero — and required to reach the sustain window, which is what
         * separates a flood from a retry burst. */
        int dur = (int)(s->last_seen - s->first_seen);
        if (dur < 1) dur = 1;
        if (dur < sustain_s) continue;
        if (n / dur < rate_per_s) continue;

        if (n <= best) continue;
        best     = n;
        best_nav = s->max_nav;
        best_dur = dur;
        if (out_ta) memcpy(out_ta, s->ta, 6);
    }
    pthread_mutex_unlock(&g_mu);
    if (max_nav)    *max_nav    = best_nav;
    if (duration_s) *duration_s = best_dur;
    return best;
}

void ctrl_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_mu);
    /* Fold the per-channel control totals into the channel summary the
     * [m] view already renders. The summary is rebuilt each poll from
     * the frame ring, so this annotates rather than creates rows —
     * inventing a channel row from control frames alone would show a
     * channel with no APs and no clients on it. */
    for (int i = 0; i < s->channel_count; i++) {
        channel_summary_t *cs = &s->channels[i];
        for (int j = 0; j < g_chan_n; j++) {
            if (g_chan[j].channel != cs->channel) continue;
            cs->ctrl_total     = g_chan[j].total;
            cs->ctrl_rts       = g_chan[j].sub[CTRL_SUB_RTS];
            cs->ctrl_cts       = g_chan[j].sub[CTRL_SUB_CTS];
            cs->ctrl_ack       = g_chan[j].sub[CTRL_SUB_ACK];
            cs->ctrl_blockack  = g_chan[j].sub[CTRL_SUB_BLOCKACK];
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

int ctrl_source_table_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_src_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void ctrl_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_src, 0, sizeof(g_src));
    memset(g_chan, 0, sizeof(g_chan));
    memset(g_bar, 0, sizeof(g_bar));
    g_src_n = 0;
    g_chan_n = 0;
    g_bar_n = 0;
    pthread_mutex_unlock(&g_mu);
}
