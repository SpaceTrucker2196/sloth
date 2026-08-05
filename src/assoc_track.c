#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "assoc_track.h"
#include "beacon_snoop.h"

static assoc_t         g_tbl[MAX_ASSOC_ENTRIES];
static int             g_n   = 0;
static pthread_mutex_t g_mu  = PTHREAD_MUTEX_INITIALIZER;

/* ── Association / reassociation REQUEST parse (#60) ──────── */

/* Fixed body length before the IE list, per IEEE 802.11-2020.
 *   AssocReq   §9.3.3.6: capability(2) + listen interval(2)
 *   ReassocReq §9.3.3.8: the same, plus current AP address(6) */
#define ASSOC_REQ_FIXED    4
#define REASSOC_REQ_FIXED  10
#define DOT11_HDR_LEN      24

/* Supported Rates (tag 1) and Extended Supported Rates (tag 50) carry
 * rates in 500 kbit/s units. The top bit flags "basic rate"; mask it
 * off — the question here is what the client supports, not what the
 * BSS requires. */
static uint32_t rate_bit(uint8_t raw) {
    switch (raw & 0x7f) {
    case 2:   return ASSOC_RATE_1M;
    case 4:   return ASSOC_RATE_2M;
    case 11:  return ASSOC_RATE_5M5;
    case 12:  return ASSOC_RATE_6M;
    case 18:  return ASSOC_RATE_9M;
    case 22:  return ASSOC_RATE_11M;
    case 24:  return ASSOC_RATE_12M;
    case 36:  return ASSOC_RATE_18M;
    case 48:  return ASSOC_RATE_24M;
    case 72:  return ASSOC_RATE_36M;
    case 96:  return ASSOC_RATE_48M;
    case 108: return ASSOC_RATE_54M;
    default:  return 0;   /* HT/VHT MCS rates live in their own IEs */
    }
}

/* Walk the rate IEs only. The rest of the IE list goes through
 * beacon_parse_ies(), which already knows RSN, PHY tier and the vendor
 * fingerprint — but does not extract rates, since a beacon's rate list
 * answers a different question than a client's. */
static uint32_t parse_rates(const uint8_t *ies, int len) {
    uint32_t bits = 0;
    int off = 0;
    while (off + 2 <= len) {
        uint8_t tag = ies[off];
        uint8_t tln = ies[off + 1];
        if (off + 2 + (int)tln > len) break;      /* truncated — stop */
        if (tag == 1 || tag == 50) {
            for (int i = 0; i < (int)tln; i++)
                bits |= rate_bit(ies[off + 2 + i]);
        }
        off += 2 + tln;
    }
    return bits;
}

int assoc_request_parse(const uint8_t *dot11, int len, assoc_req_t *out) {
    if (!dot11 || !out) return 0;
    memset(out, 0, sizeof(*out));
    if (len < DOT11_HDR_LEN) return 0;

    /* Subtype 0 = AssocReq, subtype 2 = ReassocReq; type 0, proto 0.
     * FC0 = (subtype<<4) → 0x00 and 0x20 respectively. Compared whole
     * so a nonzero protocol version is rejected rather than parsed. */
    uint8_t fc0 = dot11[0];
    int is_reassoc;
    if      (fc0 == 0x00) is_reassoc = 0;
    else if (fc0 == 0x20) is_reassoc = 1;
    else return 0;

    int fixed = is_reassoc ? REASSOC_REQ_FIXED : ASSOC_REQ_FIXED;
    if (len < DOT11_HDR_LEN + fixed) return 0;

    out->is_reassoc = is_reassoc;
    /* A request travels STA → AP: addr2 is the client, addr3 the BSSID.
     * The mirror of the response case, where addr1 is the client. */
    memcpy(out->sta,   dot11 + 10, 6);
    memcpy(out->bssid, dot11 + 16, 6);
    out->capability_info = (uint16_t)(dot11[24] | ((uint16_t)dot11[25] << 8));
    out->listen_interval = (uint16_t)(dot11[26] | ((uint16_t)dot11[27] << 8));

    const uint8_t *ies    = dot11 + DOT11_HDR_LEN + fixed;
    int            ie_len = len   - DOT11_HDR_LEN - fixed;
    if (ie_len < 0) return 0;

    out->supported_rates = parse_rates(ies, ie_len);

    /* Reuse the one IE parser (roadmap B3b) rather than adding a fourth
     * copy of the walk. Its seam is the IE blob, so an assoc request
     * feeds it as readily as a beacon: the tags that matter here —
     * SSID(0), RSN(48), HT/VHT/HE/EHT, vendor(221) — are identical.
     *
     * Its channel and enc outputs are discarded: both are AP-side
     * notions (a client sends no DS Parameter Set, and the capability
     * Privacy bit means something different coming from a STA), so
     * reading them here would invent posture the frame doesn't carry. */
    beacon_rsn_t rsn;
    char         enc[10];
    int          channel = 0;
    beacon_parse_ies(ies, ie_len, 0, 0,
                     out->requested_ssid, &channel, enc, &rsn);

    out->akm_bits       = rsn.akm_bits;
    out->pairwise_bits  = rsn.pairwise_bits;
    out->requested_mfp  = rsn.mfp;
    out->vendor_ie_hash = rsn.fp.vendor_ies_hash;
    snprintf(out->phy, sizeof(out->phy), "%s", rsn.phy);
    return 1;
}

/* Requests table, keyed by the same (BSSID, STA) pair as the grants
 * above and bounded the same way. Deliberately not the 256 the issue
 * proposes: a request only earns its slot once there is a grant to
 * compare it against, and grants cap at MAX_ASSOC_ENTRIES — so a
 * larger request table would hold rows that can never pair. Under an
 * assoc flood the LRU eviction is what protects us, not the size. */
static assoc_req_t     g_req[MAX_ASSOC_ENTRIES];
static int             g_req_n = 0;
static pthread_mutex_t g_req_mu = PTHREAD_MUTEX_INITIALIZER;

/* Defined with the flood window below; every observed request feeds it. */
static void flood_record(const uint8_t bssid[6], const uint8_t sta[6],
                         time_t now);

void assoc_request_observe(const assoc_req_t *req, int8_t signal, int channel) {
    (void)signal; (void)channel;   /* recorded with the grant, not the ask */
    if (!req) return;
    /* Same unicast-only guard the grant path applies. */
    if ((req->sta[0] & 0x01) || (req->bssid[0] & 0x01)) return;
    int all0_s = 1, all0_b = 1;
    for (int i = 0; i < 6; i++) {
        if (req->sta[i])   all0_s = 0;
        if (req->bssid[i]) all0_b = 0;
    }
    if (all0_s || all0_b) return;

    time_t now = time(NULL);
    /* Every request feeds the flood window, including repeats from one
     * STA — the rate is the signal there, independent of whether the
     * ask changed. */
    flood_record(req->bssid, req->sta, now);

    pthread_mutex_lock(&g_req_mu);

    int idx = -1, found_existing = 0;
    for (int i = 0; i < g_req_n; i++) {
        if (memcmp(g_req[i].bssid, req->bssid, 6) == 0 &&
            memcmp(g_req[i].sta,   req->sta,   6) == 0) {
            idx = i; found_existing = 1; break;
        }
    }
    if (idx < 0) {
        if (g_req_n < MAX_ASSOC_ENTRIES) {
            idx = g_req_n++;
        } else {
            /* Evict least-recently-seen, as the grant table does. */
            idx = 0;
            for (int i = 1; i < g_req_n; i++)
                if (g_req[i].ts < g_req[idx].ts) idx = i;
        }
    }
    /* Compare against the ask this one replaces, before overwriting.
     * A retry that asks for less is the downgrade actually happening —
     * see the ASSOC_DG_* note in sloth.h for why this, and not the
     * response, is where the signature is visible. */
    int      flags    = 0;
    uint32_t prev_akm = 0;
    int      prev_mfp = 0;
    if (found_existing) {
        const assoc_req_t *old = &g_req[idx];
        prev_akm = old->akm_bits;
        prev_mfp = old->requested_mfp;
        /* SAE was on the table and is now gone, with PSK in its place.
         * Requires the PSK arm: a client that simply stopped sending
         * RSN (roaming to an open BSS) is a different event. */
        if ((old->akm_bits & RSN_AKM_SAE_FAMILY) &&
            !(req->akm_bits & RSN_AKM_SAE_FAMILY) &&
             (req->akm_bits & RSN_AKM_PSK_FAMILY))
            flags |= ASSOC_DG_AKM;
        /* Protection strictly reduced: required -> capable, or either
         * -> none. */
        if (req->requested_mfp < old->requested_mfp)
            flags |= ASSOC_DG_MFP;
        /* TKIP newly on offer where it was not before. */
        if (!(old->pairwise_bits & RSN_CIPHER_TKIP) &&
             (req->pairwise_bits & RSN_CIPHER_TKIP))
            flags |= ASSOC_DG_PAIRWISE;
    }

    /* Latest ask wins outright: a client that re-requests with
     * different parameters has changed its mind, and any later
     * comparison must measure against what it asked for most recently. */
    g_req[idx]                 = *req;
    g_req[idx].ts              = now;
    g_req[idx].downgrade_flags = flags;
    g_req[idx].prev_akm_bits   = prev_akm;
    g_req[idx].prev_mfp        = prev_mfp;
    pthread_mutex_unlock(&g_req_mu);
}

int assoc_request_find(const uint8_t bssid[6], const uint8_t sta[6],
                       assoc_req_t *out) {
    if (!bssid || !sta) return 0;
    pthread_mutex_lock(&g_req_mu);
    int found = 0;
    for (int i = 0; i < g_req_n; i++) {
        if (memcmp(g_req[i].bssid, bssid, 6) == 0 &&
            memcmp(g_req[i].sta,   sta,   6) == 0) {
            if (out) *out = g_req[i];
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_req_mu);
    return found;
}

int assoc_request_count(void) {
    pthread_mutex_lock(&g_req_mu);
    int n = g_req_n;
    pthread_mutex_unlock(&g_req_mu);
    return n;
}

/* ── Assoc-request flood window (#60) ─────────────────────── */

/* Sized to hold well over the fire threshold across the window, so a
 * flood cannot push its own early evidence out before the rule reads
 * it. Same shape as the auth-flood ring. */
#define ASSOC_REQ_RING 256

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    time_t  ts;
} assoc_req_evt_t;

static assoc_req_evt_t g_ring[ASSOC_REQ_RING];
static int             g_ring_i;
static pthread_mutex_t g_ring_mu = PTHREAD_MUTEX_INITIALIZER;

static void flood_record(const uint8_t bssid[6], const uint8_t sta[6],
                         time_t now) {
    pthread_mutex_lock(&g_ring_mu);
    assoc_req_evt_t *e = &g_ring[g_ring_i];
    memcpy(e->bssid, bssid, 6);
    memcpy(e->sta,   sta,   6);
    e->ts = now;
    g_ring_i = (g_ring_i + 1) % ASSOC_REQ_RING;
    pthread_mutex_unlock(&g_ring_mu);
}

int assoc_flood_bssid(time_t now, int window_s, int thresh,
                      uint8_t out_bssid[6], int *distinct_stas) {
    int best = 0, best_distinct = 0;
    pthread_mutex_lock(&g_ring_mu);
    for (int i = 0; i < ASSOC_REQ_RING; i++) {
        if (!g_ring[i].ts || now - g_ring[i].ts > window_s) continue;
        /* Tally each BSSID from its first in-window slot only, so one
         * BSSID isn't scored repeatedly. */
        int seen_earlier = 0;
        for (int j = 0; j < i; j++)
            if (g_ring[j].ts && now - g_ring[j].ts <= window_s &&
                memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) == 0) {
                seen_earlier = 1; break;
            }
        if (seen_earlier) continue;

        int c = 0, distinct = 0;
        for (int j = 0; j < ASSOC_REQ_RING; j++) {
            if (!g_ring[j].ts || now - g_ring[j].ts > window_s) continue;
            if (memcmp(g_ring[j].bssid, g_ring[i].bssid, 6) != 0) continue;
            c++;
            /* First appearance of this STA within the BSSID's events. */
            int sta_seen = 0;
            for (int k = 0; k < j; k++)
                if (g_ring[k].ts && now - g_ring[k].ts <= window_s &&
                    memcmp(g_ring[k].bssid, g_ring[i].bssid, 6) == 0 &&
                    memcmp(g_ring[k].sta,   g_ring[j].sta,   6) == 0) {
                    sta_seen = 1; break;
                }
            if (!sta_seen) distinct++;
        }
        if (c >= thresh && c > best) {
            best = c;
            best_distinct = distinct;
            if (out_bssid) memcpy(out_bssid, g_ring[i].bssid, 6);
        }
    }
    pthread_mutex_unlock(&g_ring_mu);
    if (distinct_stas) *distinct_stas = best_distinct;
    return best;
}

void assoc_flood_clear(void) {
    pthread_mutex_lock(&g_ring_mu);
    memset(g_ring, 0, sizeof(g_ring));
    g_ring_i = 0;
    pthread_mutex_unlock(&g_ring_mu);
}

int assoc_request_downgrade_count(void) {
    pthread_mutex_lock(&g_req_mu);
    int n = 0;
    for (int i = 0; i < g_req_n; i++)
        if (g_req[i].downgrade_flags) n++;
    pthread_mutex_unlock(&g_req_mu);
    return n;
}

void assoc_request_clear(void) {
    pthread_mutex_lock(&g_req_mu);
    g_req_n = 0;
    memset(g_req, 0, sizeof(g_req));
    pthread_mutex_unlock(&g_req_mu);
}

static int pair_eq(const assoc_t *a, const uint8_t bssid[6],
                                       const uint8_t sta[6]) {
    return memcmp(a->bssid, bssid, 6) == 0 &&
           memcmp(a->sta_mac, sta, 6) == 0;
}

/* Promote source: ASSOC_SRC_EAPOL beats _ASSOC / _REASSOC, etc.
 * Same evidence or weaker doesn't downgrade an existing entry. */
static int source_rank(int s) {
    if (s == ASSOC_SRC_EAPOL)   return 3;
    if (s == ASSOC_SRC_ASSOC)   return 2;
    if (s == ASSOC_SRC_REASSOC) return 2;
    return 0;
}

void assoc_observe(const uint8_t bssid[6], const uint8_t sta[6],
                    const char *ssid, int source,
                    int8_t signal, int channel)
{
    if (!bssid || !sta) return;
    /* Reject broadcast / null / multicast addresses on either side
     * — we only track unicast STA <-> AP relationships. */
    if ((sta[0]   & 0x01) || (bssid[0] & 0x01)) return;
    int all0_bssid = 1, all0_sta = 1;
    for (int i = 0; i < 6; i++) {
        if (bssid[i]) all0_bssid = 0;
        if (sta[i])   all0_sta   = 0;
    }
    if (all0_bssid || all0_sta) return;

    time_t now = time(NULL);
    pthread_mutex_lock(&g_mu);

    int idx = -1;
    for (int i = 0; i < g_n; i++) {
        if (pair_eq(&g_tbl[i], bssid, sta)) { idx = i; break; }
    }
    if (idx < 0) {
        if (g_n >= MAX_ASSOC_ENTRIES) {
            /* Evict least-recently-seen. */
            idx = 0;
            for (int i = 1; i < g_n; i++)
                if (g_tbl[i].last_seen < g_tbl[idx].last_seen) idx = i;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        } else {
            idx = g_n++;
            memset(&g_tbl[idx], 0, sizeof(g_tbl[idx]));
        }
        memcpy(g_tbl[idx].bssid,   bssid, 6);
        memcpy(g_tbl[idx].sta_mac, sta,   6);
        g_tbl[idx].first_seen = now;
        g_tbl[idx].sta_random = (sta[0] & 0x02) ? 1 : 0;
    }
    g_tbl[idx].last_seen = now;
    g_tbl[idx].frame_count++;
    g_tbl[idx].signal_dbm = signal;
    if (channel > 0) g_tbl[idx].channel = channel;
    if (source_rank(source) > source_rank(g_tbl[idx].source))
        g_tbl[idx].source = source;
    /* Fill SSID if we don't have it yet — prefer the caller-supplied
     * one, fall back to a beacon-table lookup. */
    if (!g_tbl[idx].ssid[0]) {
        if (ssid && ssid[0])
            snprintf(g_tbl[idx].ssid, sizeof(g_tbl[idx].ssid), "%s", ssid);
        else
            beacon_find_ssid(bssid, g_tbl[idx].ssid);
    }

    pthread_mutex_unlock(&g_mu);
}

void assoc_forget(const uint8_t bssid[6], const uint8_t sta[6])
{
    if (!bssid || !sta) return;
    pthread_mutex_lock(&g_mu);
    for (int i = 0; i < g_n; i++) {
        if (pair_eq(&g_tbl[i], bssid, sta)) {
            /* Swap with last and shrink. */
            if (i != g_n - 1) g_tbl[i] = g_tbl[g_n - 1];
            g_n--;
            memset(&g_tbl[g_n], 0, sizeof(g_tbl[g_n]));
            break;
        }
    }
    pthread_mutex_unlock(&g_mu);
}

void assoc_snapshot(sloth_state_t *s)
{
    pthread_mutex_lock(&g_mu);
    int n = g_n < MAX_ASSOC_ENTRIES ? g_n : MAX_ASSOC_ENTRIES;
    /* Sort by last_seen DESC for the view. */
    int order[MAX_ASSOC_ENTRIES];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++)
            if (g_tbl[order[j]].last_seen > g_tbl[order[best]].last_seen)
                best = j;
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) {
        s->assocs[i] = g_tbl[order[i]];
        /* Backfill SSID lazily — beacon may have been observed after
         * the assoc itself. */
        if (!s->assocs[i].ssid[0])
            beacon_find_ssid(s->assocs[i].bssid, s->assocs[i].ssid);
    }
    s->assoc_count = n;
    if (s->assoc_sel >= n && n > 0) s->assoc_sel = n - 1;
    pthread_mutex_unlock(&g_mu);
}

void assoc_request_snapshot(sloth_state_t *s) {
    if (!s) return;
    pthread_mutex_lock(&g_req_mu);
    int n = g_req_n < MAX_ASSOC_ENTRIES ? g_req_n : MAX_ASSOC_ENTRIES;
    /* Downgrades first, then most recent — an operator scanning this
     * list wants the clients that gave something up at the top, not
     * buried among ordinary associations. */
    int order[MAX_ASSOC_ENTRIES];
    for (int i = 0; i < n; i++) order[i] = i;
    for (int i = 0; i < n - 1; i++) {
        int best = i;
        for (int j = i + 1; j < n; j++) {
            const assoc_req_t *a = &g_req[order[j]];
            const assoc_req_t *b = &g_req[order[best]];
            int a_dg = a->downgrade_flags != 0;
            int b_dg = b->downgrade_flags != 0;
            if (a_dg != b_dg ? a_dg : a->ts > b->ts) best = j;
        }
        if (best != i) { int t = order[i]; order[i] = order[best]; order[best] = t; }
    }
    for (int i = 0; i < n; i++) s->assoc_reqs[i] = g_req[order[i]];
    s->assoc_req_count = n;
    pthread_mutex_unlock(&g_req_mu);
}

void assoc_clear(void) {
    pthread_mutex_lock(&g_mu);
    g_n = 0;
    memset(g_tbl, 0, sizeof(g_tbl));
    pthread_mutex_unlock(&g_mu);
}

int assoc_count(void) {
    pthread_mutex_lock(&g_mu);
    int n = g_n;
    pthread_mutex_unlock(&g_mu);
    return n;
}
