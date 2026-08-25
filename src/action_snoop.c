#include <string.h>
#include <pthread.h>

#include "action_snoop.h"

/* 802.11 management header is 24 bytes; the Action body starts there.
 * Category and Action occupy the first two body bytes. */
#define DOT11_HDR_LEN     24
#define ACTION_MIN_LEN    (DOT11_HDR_LEN + 2)

/* Neighbor Report element (tag 52) — IEEE 802.11-2020 §9.4.2.36.
 * BSSID(6) + BSSID Info(4) + Operating Class(1) + Channel(1) + PHY(1).
 * Subelements may follow; we only need the BSSID. */
#define IE_NEIGHBOR_REPORT  52
#define NEIGHBOR_MIN_LEN    13

/* BSS Termination Duration field: subelement ID(1) + length(1) +
 * TSF(8) + Duration(2) = 12 bytes, present when B3 is set. */
#define BSS_TERM_DURATION_LEN 12

/* Per-category frame counters. Indexed directly by the category byte,
 * so the whole 0..255 space is covered without a lookup table — the
 * array is 1 KiB and removes any chance of an unmapped category being
 * silently dropped rather than counted. */
static int             g_cat_count[256];
static int             g_total;
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;

/* ── BTM steering state (slice 2) ─────────────────────────
 *
 * The table is LRU-evicted on overflow rather than refusing new pairs:
 * under a forcing attack the interesting pair is the newest one, and a
 * full table that rejects it would make the detector fail exactly when
 * it matters. */
static btm_steer_t     g_btm[MAX_BTM_PAIRS];
static int             g_btm_n;
static pthread_mutex_t g_btm_mu = PTHREAD_MUTEX_INITIALIZER;

/* Event ring for the rate window. Sized so a full window of the
 * threshold rate across every tracked pair still fits — otherwise a
 * broad flood could roll the ring and hide the targeted steering that
 * is the actual signal. */
#define BTM_EVT_RING  256

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    int     imminent;
    time_t  ts;
} btm_evt_t;

static btm_evt_t       g_ring[BTM_EVT_RING];
static int             g_ring_i;
static pthread_mutex_t g_ring_mu = PTHREAD_MUTEX_INITIALIZER;

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

int action_parse_category(const uint8_t *dot11, int len, uint8_t *action_out) {
    if (!dot11 || len < ACTION_MIN_LEN) return -1;
    /* Subtype 13, type 0, protocol version 0 → FC byte 0 == 0xD0.
     * Compared whole rather than masked so a protocol-version-nonzero
     * frame (which we cannot interpret) is rejected rather than parsed. */
    if (dot11[0] != 0xD0) return -1;
    if (action_out) *action_out = dot11[DOT11_HDR_LEN + 1];
    return dot11[DOT11_HDR_LEN];
}

int action_parse_btm_req(const uint8_t *dot11, int len, sloth_btm_req_t *out) {
    if (!out) return 0;
    memset(out, 0, sizeof(*out));

    uint8_t action = 0;
    int cat = action_parse_category(dot11, len, &action);
    if (cat != ACTION_CAT_WNM || action != WNM_ACT_BTM_REQUEST) return 0;

    /* Fixed fields: category, action, dialog token, request mode,
     * disassoc timer (2), validity interval. */
    int off = DOT11_HDR_LEN + 2;
    if (off + 5 > len) return 0;

    out->dialog_token      = dot11[off++];
    out->request_mode      = dot11[off++];
    out->disassoc_timer    = le16(dot11 + off); off += 2;
    out->validity_interval = dot11[off++];

    memcpy(out->target_sta, dot11 + 4,  6);   /* addr1 = DA  */
    memcpy(out->bssid,      dot11 + 16, 6);   /* addr3 = BSSID */

    /* Optional fields, in the order the standard fixes them. Both are
     * skipped rather than stored: neither carries a signal this
     * detector uses, but misreading their length shifts every candidate
     * BSSID that follows. */
    if (out->request_mode & BTM_REQ_BSS_TERM_INCL) {
        if (off + BSS_TERM_DURATION_LEN > len) return 0;
        off += BSS_TERM_DURATION_LEN;
    }
    if (out->request_mode & BTM_REQ_ESS_DISASSOC) {
        if (off + 1 > len) return 0;
        int url_len = dot11[off++];
        if (off + url_len > len) return 0;
        off += url_len;
    }

    /* Remaining bytes are the candidate list: zero or more Neighbor
     * Report elements. A Request with no candidates is legal (and is
     * what a pure "leave now" steer looks like), so running out here is
     * success, not failure. */
    while (off + 2 <= len) {
        uint8_t tag = dot11[off];
        uint8_t tln = dot11[off + 1];
        if (off + 2 + (int)tln > len) break;   /* truncated element */
        if (tag == IE_NEIGHBOR_REPORT && tln >= NEIGHBOR_MIN_LEN) {
            if (out->candidate_count < SLOTH_BTM_MAX_CANDIDATES)
                memcpy(out->candidate_bssids[out->candidate_count++],
                       dot11 + off + 2, 6);
            else
                out->candidates_truncated = 1;
        }
        off += 2 + tln;
    }
    return 1;
}

void action_observe(const uint8_t *dot11, int len, time_t now) {
    uint8_t action = 0;
    int cat = action_parse_category(dot11, len, &action);
    if (cat < 0) return;
    pthread_mutex_lock(&g_mu);
    g_cat_count[cat]++;
    g_total++;
    pthread_mutex_unlock(&g_mu);

    /* Category 10 / Action 7 is the one this module deep-parses. The
     * others stay counted-only until their own issues land (#61 RRM,
     * #63 CSA), and the count is what those issues start from. */
    if (cat != ACTION_CAT_WNM || action != WNM_ACT_BTM_REQUEST) return;
    sloth_btm_req_t req;
    if (action_parse_btm_req(dot11, len, &req)) btm_observe(&req, now);
}

int action_category_count(uint8_t category) {
    pthread_mutex_lock(&g_mu);
    int n = g_cat_count[category];
    pthread_mutex_unlock(&g_mu);
    return n;
}

int action_total_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_total;
    pthread_mutex_unlock(&g_mu);
    return n;
}

void action_clear(void) {
    pthread_mutex_lock(&g_mu);
    memset(g_cat_count, 0, sizeof(g_cat_count));
    g_total = 0;
    pthread_mutex_unlock(&g_mu);
}

/* ── BTM steering table ───────────────────────────────────── */

static int mac_is_usable(const uint8_t m[6]) {
    /* Group-addressed is not a steering target: BTM is addressed
     * management, and a broadcast destination means we have misread the
     * frame rather than found a broadcast steer. An all-zero address is
     * the same kind of evidence. Mirrors the guard assoc_request_observe
     * applies for the same reason. */
    if (m[0] & 0x01) return 0;
    for (int i = 0; i < 6; i++) if (m[i]) return 1;
    return 0;
}

static void ring_record(const uint8_t bssid[6], const uint8_t sta[6],
                        int imminent, time_t now) {
    pthread_mutex_lock(&g_ring_mu);
    btm_evt_t *e = &g_ring[g_ring_i];
    memcpy(e->bssid, bssid, 6);
    memcpy(e->sta,   sta,   6);
    e->imminent = imminent;
    e->ts       = now;
    g_ring_i = (g_ring_i + 1) % BTM_EVT_RING;
    pthread_mutex_unlock(&g_ring_mu);
}

void btm_observe(const sloth_btm_req_t *req, time_t now) {
    if (!req) return;
    if (!mac_is_usable(req->bssid) || !mac_is_usable(req->target_sta)) return;

    int imminent = (req->request_mode & BTM_REQ_DISASSOC_IMM) ? 1 : 0;
    ring_record(req->bssid, req->target_sta, imminent, now);

    pthread_mutex_lock(&g_btm_mu);

    int idx = -1;
    for (int i = 0; i < g_btm_n; i++) {
        if (memcmp(g_btm[i].bssid, req->bssid,      6) == 0 &&
            memcmp(g_btm[i].sta,   req->target_sta, 6) == 0) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_btm_n < MAX_BTM_PAIRS) {
            idx = g_btm_n++;
        } else {
            /* Evict the stalest pair. */
            idx = 0;
            for (int i = 1; i < MAX_BTM_PAIRS; i++)
                if (g_btm[i].last_seen < g_btm[idx].last_seen) idx = i;
        }
        memset(&g_btm[idx], 0, sizeof(g_btm[idx]));
        memcpy(g_btm[idx].bssid, req->bssid,      6);
        memcpy(g_btm[idx].sta,   req->target_sta, 6);
        g_btm[idx].first_seen = now;
    }

    btm_steer_t *t = &g_btm[idx];
    t->req_count++;
    if (imminent) t->imminent_count++;
    t->last_request_mode      = req->request_mode;
    t->last_disassoc_timer    = req->disassoc_timer;
    t->last_validity_interval = req->validity_interval;
    t->last_seen              = now;
    /* The candidate list is replaced, not merged: it is where the AP is
     * pointing the client *now*, and an older destination it has since
     * stopped offering would read as a second live option. */
    t->candidate_count       = req->candidate_count;
    t->candidates_truncated  = req->candidates_truncated;
    memset(t->candidates, 0, sizeof(t->candidates));
    for (int i = 0; i < req->candidate_count && i < MAX_AP_NEIGHBORS; i++)
        memcpy(t->candidates[i], req->candidate_bssids[i], 6);

    pthread_mutex_unlock(&g_btm_mu);
}

int btm_forcing_pair(time_t now, int window_s, int thresh,
                     uint8_t out_bssid[6], uint8_t out_sta[6],
                     int *total_out) {
    int best = 0, best_total = 0;
    pthread_mutex_lock(&g_ring_mu);
    for (int i = 0; i < BTM_EVT_RING; i++) {
        if (!g_ring[i].ts || now - g_ring[i].ts > window_s) continue;
        /* Score each pair from its first in-window slot only, so one
         * pair is not scored once per event it contributed. */
        int seen_earlier = 0;
        for (int j = 0; j < i; j++)
            if (g_ring[j].ts && now - g_ring[j].ts <= window_s &&
                memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) == 0 &&
                memcmp(g_ring[j].sta,   g_ring[i].sta,   6) == 0) {
                seen_earlier = 1; break;
            }
        if (seen_earlier) continue;

        int imminent = 0, total = 0;
        for (int j = 0; j < BTM_EVT_RING; j++) {
            if (!g_ring[j].ts || now - g_ring[j].ts > window_s) continue;
            if (memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) != 0) continue;
            if (memcmp(g_ring[j].sta,   g_ring[i].sta,   6) != 0) continue;
            total++;
            if (g_ring[j].imminent) imminent++;
        }
        if (imminent >= thresh && imminent > best) {
            best       = imminent;
            best_total = total;
            if (out_bssid) memcpy(out_bssid, g_ring[i].bssid, 6);
            if (out_sta)   memcpy(out_sta,   g_ring[i].sta,   6);
        }
    }
    pthread_mutex_unlock(&g_ring_mu);
    if (total_out) *total_out = best_total;
    return best;
}

int btm_find(const uint8_t bssid[6], const uint8_t sta[6], btm_steer_t *out) {
    int hit = 0;
    pthread_mutex_lock(&g_btm_mu);
    for (int i = 0; i < g_btm_n; i++) {
        if (memcmp(g_btm[i].bssid, bssid, 6) == 0 &&
            memcmp(g_btm[i].sta,   sta,   6) == 0) {
            if (out) *out = g_btm[i];
            hit = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_btm_mu);
    return hit;
}

void btm_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_btm_mu);
    int n = g_btm_n;
    if (n > MAX_BTM_PAIRS) n = MAX_BTM_PAIRS;
    memcpy(s->btm_steers, g_btm, (size_t)n * sizeof(g_btm[0]));
    s->btm_steer_count = n;
    pthread_mutex_unlock(&g_btm_mu);

    /* Most recently steered first. Insertion sort: n is bounded at 128
     * and near-sorted in practice, so this beats qsort's call overhead
     * and matches how the other snapshots order small tables. */
    for (int i = 1; i < s->btm_steer_count; i++) {
        btm_steer_t tmp = s->btm_steers[i];
        int j = i - 1;
        while (j >= 0 && s->btm_steers[j].last_seen < tmp.last_seen) {
            s->btm_steers[j + 1] = s->btm_steers[j];
            j--;
        }
        s->btm_steers[j + 1] = tmp;
    }
}

int btm_pair_count(void) {
    pthread_mutex_lock(&g_btm_mu);
    int n = g_btm_n;
    pthread_mutex_unlock(&g_btm_mu);
    return n;
}

void btm_clear(void) {
    pthread_mutex_lock(&g_btm_mu);
    memset(g_btm, 0, sizeof(g_btm));
    g_btm_n = 0;
    pthread_mutex_unlock(&g_btm_mu);
    pthread_mutex_lock(&g_ring_mu);
    memset(g_ring, 0, sizeof(g_ring));
    g_ring_i = 0;
    pthread_mutex_unlock(&g_ring_mu);
}
