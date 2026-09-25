#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "seqnum_track.h"

static seqnum_client_t g_tbl[MAX_SEQNUM_CLIENTS];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

static int mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static int g_corr_enabled = 1;
static int g_corr_retain  = SEQNUM_CORR_RETAIN_S;

void seqnum_corr_set_enabled(int on) { g_corr_enabled = on ? 1 : 0; }
int  seqnum_corr_enabled(void)       { return g_corr_enabled; }

void seqnum_corr_set_retain_secs(int secs) {
    if (secs >= 1) g_corr_retain = secs;
}
int  seqnum_corr_retain_secs(void) { return g_corr_retain; }

void seqnum_track_observe(const uint8_t mac[6], uint16_t seqnum)
{
    seqnum_track_observe_at(mac, seqnum, time(NULL));
}

void seqnum_track_observe_at(const uint8_t mac[6], uint16_t seqnum, time_t now)
{
    /* Skip clearly invalid sources: NULL OUI, multicast, broadcast. */
    if (!mac) return;
    if ((mac[0] & 0x01) != 0) return;   /* multicast/broadcast — not a STA */

    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (mac_eq(g_tbl[i].mac, mac)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_SEQNUM_CLIENTS) {
            /* Evict least-recently-seen. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].mac, mac, 6);
        g_tbl[idx].mac_random = (mac[0] & 0x02) ? 1 : 0;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].frame_count++;

    /* Push to history ring (newest at index 0). */
    int n = g_tbl[idx].hist_n;
    if (n < SEQNUM_HISTORY_LEN) n++;
    for (int i = n - 1; i > 0; i--) {
        g_tbl[idx].hist[i]    = g_tbl[idx].hist[i - 1];
        g_tbl[idx].hist_ts[i] = g_tbl[idx].hist_ts[i - 1];
    }
    g_tbl[idx].hist[0]    = seqnum & 0x0FFF;
    g_tbl[idx].hist_ts[0] = now;
    g_tbl[idx].hist_n     = n;

    pthread_mutex_unlock(&g_mu);
}

/* 12-bit modular distance. The seqnum field is 12 bits — distance
 * 4095 -> 0 is 1, not 4095. */
static int seq_gap(uint16_t a, uint16_t b) {
    int diff = (int)a - (int)b;
    if (diff < 0) diff = -diff;
    if (diff > 2048) diff = 4096 - diff;
    return diff;
}

/* Forward modular advance from `from` to `to`. Direction matters:
 * absolute distance cannot tell a counter that advanced 5 from one that
 * went back 5, and only the first is consistent with one radio's
 * monotonic counter continuing under a new address. */
static int seq_fwd(uint16_t from, uint16_t to) {
    return ((int)to - (int)from + 4096) & 0x0FFF;
}

/* hist[0] is the newest entry, hist[hist_n-1] the oldest. */
#define HIST_NEWEST(c)    ((c)->hist[0])
#define HIST_OLDEST(c)    ((c)->hist[(c)->hist_n - 1])
#define HIST_NEWEST_TS(c) ((c)->hist_ts[0])
#define HIST_OLDEST_TS(c) ((c)->hist_ts[(c)->hist_n - 1])

/* A trail whose own steps do not run forward is not a counter we can
 * extrapolate across an address change — it is a table entry that has
 * wrapped, been reordered, or belongs to more than one radio. */
static int hist_runs_forward(const seqnum_client_t *c) {
    for (int i = c->hist_n - 1; i > 0; i--) {
        if (seq_fwd(c->hist[i], c->hist[i - 1]) > SEQNUM_CORR_SEQ_WINDOW)
            return 0;
    }
    return 1;
}

/* What a reported pair rests on. Kept together because the score is only
 * meaningful beside the window it was computed over. */
typedef struct {
    int    fwd_gap;
    int    abs_gap;
    long   dt_ms;
    int    confidence;
    time_t window_start;
    time_t window_end;
} corr_evidence_t;

/* Confidence, in percent, for one accepted transition. Every term is a
 * property of the evidence, and the weights are calibrated against the
 * dense fixture in tests/test_seqnum_track.c — a pair scoring at the
 * floor is at the coincidence rate that fixture measures, which is
 * exactly what the floor is for.
 *
 * The ceiling is below 100 on purpose: a shared counter position is
 * circumstantial, and no passive observation closes the gap to
 * certainty. */
static int corr_confidence(int fwd_gap, long dt_ms, int depth,
                           int rnd_a, int rnd_b) {
    int score = 0;

    /* Counter proximity. A rotation happens between two frames, so the
     * closest seams are the strongest evidence. */
    if      (fwd_gap <=  4) score += 40;
    else if (fwd_gap <= 16) score += 28;
    else if (fwd_gap <= 32) score += 16;
    else                    score += 8;

    /* Immediacy. An address rotation is a seam in one stream; the longer
     * the silence, the more room for a second radio to be the answer. */
    if      (dt_ms <=  2000) score += 20;
    else if (dt_ms <=  8000) score += 12;
    else if (dt_ms <= 16000) score += 6;

    /* Evidence depth — entries on the thinner side. One frame each shows
     * a position, not a direction, and scores nothing for depth. */
    if      (depth >= 6) score += 20;
    else if (depth >= 4) score += 12;
    else if (depth >= 2) score += 6;

    /* The hypothesis under test is *address randomisation*, and the
     * shape it actually produces is one randomised address beside one
     * burned-in one — a device rotating away from, or back to, an
     * anchor identity. That shape is the only one that can reach the
     * upper band.
     *
     * Two randomised addresses is a real case (one phone across two
     * rotations) but a weaker inferential one: there is no anchor, so
     * nothing distinguishes it from two phones that both randomise,
     * which in a dense room is the majority of the population. It is
     * scored flat, not suppressed. Two burned-in addresses sharing a
     * counter position is likelier to be two radios and is scored down. */
    if      (rnd_a != rnd_b) score += 14;
    else if (rnd_a)          score += 0;
    else                     score -= 10;

    if (score > SEQNUM_CORR_CONF_MAX) score = SEQNUM_CORR_CONF_MAX;
    if (score < 0)                    score = 0;
    return score;
}

/* One direction of the hypothesis: `x` held the address first, then the
 * radio rotated to `y`. Returns 1 and fills `ev` when every requirement
 * holds.
 *
 * The pre-#94 rule minimised absolute modular distance over the cross
 * product of two histories and accepted any pair inside a flat window.
 * That accepted 23.4 % of the pairs in the dense fixture. Each check
 * below removes a class of those:
 *
 *   freshness   — a claim about now must rest on evidence from now.
 *   ordering    — a rotation has a before and an after.
 *   exclusivity — one radio holds one address at a time, so two MACs
 *                 transmitting through the same seconds are two radios
 *                 however close their counters sit.
 *   direction   — the counter must have advanced, not merely landed
 *                 nearby.
 *   continuity  — each trail must run forward on its own before it can
 *                 be extrapolated across the seam. */
static int try_direction(const seqnum_client_t *x, const seqnum_client_t *y,
                         time_t now, int retain, corr_evidence_t *ev)
{
    if (x->hist_n == 0 || y->hist_n == 0) return 0;

    /* Freshness: both sides inside the retention window, counted from
     * now. Two long-stale histories no longer describe anything
     * current, whatever they once looked like. */
    if (now - HIST_NEWEST_TS(x) > retain) return 0;
    if (now - HIST_NEWEST_TS(y) > retain) return 0;

    /* Ordering + exclusivity in one test: x must be finished before y
     * starts. Equality is allowed because observation timestamps have
     * one-second resolution and a rotation inside a burst is the normal
     * case; anything interleaved is rejected. */
    if (HIST_NEWEST_TS(x) > HIST_OLDEST_TS(y)) return 0;

    long dt_ms = (long)(HIST_OLDEST_TS(y) - HIST_NEWEST_TS(x)) * 1000;
    if (dt_ms > (long)SEQNUM_CORR_DT_MAX_S * 1000) return 0;

    /* Direction: the counter continued forward across the seam. Zero is
     * excluded — the later address repeating the earlier one's last
     * sequence number is a duplicate value, not a continuation, and in a
     * dense room duplicates are the commonest coincidence there is. */
    int fwd = seq_fwd(HIST_NEWEST(x), HIST_OLDEST(y));
    if (fwd < 1 || fwd > SEQNUM_CORR_SEQ_WINDOW) return 0;

    if (!hist_runs_forward(x) || !hist_runs_forward(y)) return 0;

    int depth = x->hist_n < y->hist_n ? x->hist_n : y->hist_n;
    int conf  = corr_confidence(fwd, dt_ms, depth,
                                x->mac_random, y->mac_random);
    if (conf < SEQNUM_CORR_CONF_MIN) return 0;

    ev->fwd_gap      = fwd;
    ev->abs_gap      = seq_gap(HIST_NEWEST(x), HIST_OLDEST(y));
    ev->dt_ms        = dt_ms;
    ev->confidence   = conf;
    ev->window_start = HIST_OLDEST_TS(x);
    ev->window_end   = HIST_NEWEST_TS(y);
    return 1;
}

/* The pair is unordered — either address may have been seen first — so
 * both directions are tried and the better-supported one is reported.
 * `*out_a_earlier` says which way round the transition ran. */
static int try_correlate(const seqnum_client_t *a, const seqnum_client_t *b,
                         time_t now, int retain,
                         corr_evidence_t *out, int *out_a_earlier)
{
    if (mac_eq(a->mac, b->mac)) return 0;

    corr_evidence_t ab, ba;
    int ok_ab = try_direction(a, b, now, retain, &ab);
    int ok_ba = try_direction(b, a, now, retain, &ba);

    if (!ok_ab && !ok_ba) return 0;
    if (ok_ab && (!ok_ba || ab.confidence >= ba.confidence)) {
        *out = ab; *out_a_earlier = 1;
    } else {
        *out = ba; *out_a_earlier = 0;
    }
    return 1;
}

/* How long a per-MAC record is kept. Raising the correlation window
 * past this raises the table horizon with it, so a longer window is
 * never starved of the candidates it is supposed to consider. */
static int client_retain_secs(void) {
    return g_corr_retain > SEQNUM_CLIENT_RETAIN_S
         ? g_corr_retain : SEQNUM_CLIENT_RETAIN_S;
}

/* Drop records nobody has heard from inside the horizon. Caller holds
 * the mutex.
 *
 * Before #94 the only way out of this table was eviction on fill, so a
 * quiet sensor kept every address it had ever heard for the life of the
 * process — unbounded retention of data that can be personal, and the
 * supply of stale halves for stale pairs. */
static void expire_clients(time_t now) {
    int retain = client_retain_secs();
    int w = 0;
    for (int i = 0; i < g_n; i++) {
        if (now - g_tbl[i].last_seen > retain) continue;
        if (w != i) g_tbl[w] = g_tbl[i];
        w++;
    }
    if (w < g_n) memset(&g_tbl[w], 0, sizeof(g_tbl[0]) * (size_t)(g_n - w));
    g_n = w;
}

int seqnum_corr_is_strong(const seqnum_correlation_t *c)
{
    if (!c) return 0;
    if (c->confidence < SEQNUM_CORR_CONF_STRONG) return 0;
    return (c->mac_a_random != c->mac_b_random) ? 1 : 0;
}

int seqnum_corr_candidate_pairs(time_t now, int *out_accepted,
                                int *out_max_conf)
{
    int compared = 0, accepted = 0, max_conf = 0;
    pthread_mutex_lock(&g_mu);
    /* Deliberately not gated on g_corr_enabled: this measures the
     * acceptance test itself, which is the thing being calibrated. */
    for (int i = 0; i < g_n; i++) {
        for (int j = i + 1; j < g_n; j++) {
            corr_evidence_t ev; int a_earlier;
            compared++;
            if (!try_correlate(&g_tbl[i], &g_tbl[j], now, g_corr_retain,
                               &ev, &a_earlier)) continue;
            accepted++;
            if (ev.confidence > max_conf) max_conf = ev.confidence;
        }
    }
    pthread_mutex_unlock(&g_mu);
    if (out_accepted) *out_accepted = accepted;
    if (out_max_conf) *out_max_conf = max_conf;
    return compared;
}

void seqnum_snapshot(sloth_state_t *s)
{
    seqnum_snapshot_at(s, time(NULL));
}

void seqnum_snapshot_at(sloth_state_t *s, time_t now)
{
    pthread_mutex_lock(&g_mu);

    expire_clients(now);

    /* Copy the per-MAC table, newest-activity first. */
    int n = g_n < MAX_SEQNUM_CLIENTS ? g_n : MAX_SEQNUM_CLIENTS;
    int order[MAX_SEQNUM_CLIENTS];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) s->seqnum_clients[i] = g_tbl[order[i]];
    s->seqnum_count = n;

    /* Pairwise correlation scan. O(n^2) with a bounded per-pair cost —
     * n is capped at MAX_SEQNUM_CLIENTS and the transition test reads
     * each history's two endpoints plus one forward pass.
     *
     * Skipped entirely when longitudinal correlation is switched off:
     * the histories above are observation, linking them across addresses
     * is a separate purpose (#94) and the operator controls it. */
    int corr_n = 0;
    if (g_corr_enabled) {
        for (int i = 0; i < n && corr_n < MAX_SEQNUM_CORRELATIONS; i++) {
            for (int j = i + 1; j < n && corr_n < MAX_SEQNUM_CORRELATIONS; j++) {
                corr_evidence_t ev; int a_earlier = 1;
                if (!try_correlate(&g_tbl[i], &g_tbl[j], now, g_corr_retain,
                                   &ev, &a_earlier)) continue;
                seqnum_correlation_t *c = &s->seqnum_correlations[corr_n++];
                memset(c, 0, sizeof(*c));
                memcpy(c->mac_a, g_tbl[i].mac, 6);
                memcpy(c->mac_b, g_tbl[j].mac, 6);
                c->mac_a_random = g_tbl[i].mac_random;
                c->mac_b_random = g_tbl[j].mac_random;
                c->gap          = ev.abs_gap;
                c->dt_ms        = ev.dt_ms;
                c->a_count      = g_tbl[i].frame_count;
                c->b_count      = g_tbl[j].frame_count;
                c->fwd_gap      = ev.fwd_gap;
                c->confidence   = ev.confidence;
                c->window_start = ev.window_start;
                c->window_end   = ev.window_end;
                c->a_hist_n     = g_tbl[i].hist_n;
                c->b_hist_n     = g_tbl[j].hist_n;
                c->a_is_earlier = a_earlier;
            }
        }
    }
    /* Sort by descending confidence — best-supported first. Gap alone
     * used to order this, which put a one-frame-each coincidence above a
     * full trail whenever its gap happened to be smaller. */
    for (int i = 0; i < corr_n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < corr_n; j++) {
            const seqnum_correlation_t *cj = &s->seqnum_correlations[j];
            const seqnum_correlation_t *cb = &s->seqnum_correlations[best];
            if (cj->confidence > cb->confidence ||
                (cj->confidence == cb->confidence && cj->fwd_gap < cb->fwd_gap))
                best = j;
        }
        if (best != i) {
            seqnum_correlation_t tmp = s->seqnum_correlations[i];
            s->seqnum_correlations[i]    = s->seqnum_correlations[best];
            s->seqnum_correlations[best] = tmp;
        }
    }
    s->seqnum_correlation_count = corr_n;
    if (s->seqnum_corr_sel >= corr_n)
        s->seqnum_corr_sel = corr_n > 0 ? corr_n - 1 : 0;

    pthread_mutex_unlock(&g_mu);
}

void seqnum_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    g_corr_enabled = 1;
    g_corr_retain  = SEQNUM_CORR_RETAIN_S;
    pthread_mutex_unlock(&g_mu);
}

int seqnum_client_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}
