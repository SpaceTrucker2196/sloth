/* #193 field data: counts, read by nothing that decides. Contract and
 * units: twin_field.h. */
#include <string.h>
#include "twin_field.h"

/* One flood episode, keyed by the flooded BSSID. Lives while some
 * victim row of that BSSID has `flood` set; a BSSID that drops out and
 * floods again is a new episode. MAX_DEAUTH_VICTIMS bounds the rows, so
 * it bounds the distinct BSSIDs too and nothing here evicts. */
typedef struct {
    uint8_t bssid[6];
    uint8_t examined, named, coincided;
} tf_flood_t;

/* A beacon entry already counted as a late LAA copy, by the entry's
 * identity: an address the table dropped and rebuilt has a new
 * first_seen and is a new entry. MAX_BEACON_APS bounds it. */
typedef struct {
    uint8_t bssid[6];
    time_t  first_seen;
} tf_entry_t;

static tf_flood_t          g_fl[MAX_DEAUTH_VICTIMS], g_fl_next[MAX_DEAUTH_VICTIMS];
static int                 g_fl_n;
static tf_entry_t          g_laa[MAX_BEACON_APS], g_laa_next[MAX_BEACON_APS];
static int                 g_laa_n;
static twin_field_counts_t g_c;
static int                 g_off;

int  twin_field_enabled(void)       { return !g_off; }
void twin_field_set_enabled(int on) { g_off = !on; }

void twin_field_counts(twin_field_counts_t *out) {
    if (out) *out = g_c;
}

void twin_field_reset(void) {
    memset(&g_c, 0, sizeof(g_c));
    g_fl_n = g_laa_n = 0;
    g_off = 0;
}

static int laa(const uint8_t b[6]) { return (b[0] & 0x02) != 0; }

static void floods_step(const sloth_state_t *s) {
    int n = 0;
    for (int i = 0; i < s->deauth_victim_count && i < MAX_DEAUTH_VICTIMS; i++) {
        const deauth_victim_t *v = &s->deauth_victims[i];
        if (!v->flood) continue;
        int dup = 0;
        for (int k = 0; k < n && !dup; k++)
            dup = memcmp(g_fl_next[k].bssid, v->bssid, 6) == 0;
        if (dup) continue;
        tf_flood_t *e = &g_fl_next[n++];
        int k = 0;
        while (k < g_fl_n && memcmp(g_fl[k].bssid, v->bssid, 6) != 0) k++;
        if (k < g_fl_n) {
            *e = g_fl[k];
        } else {
            memset(e, 0, sizeof(*e));
            memcpy(e->bssid, v->bssid, 6);
            g_c.floods++;
        }
    }
    memcpy(g_fl, g_fl_next, (size_t)n * sizeof(g_fl[0]));
    g_fl_n = n;
}

static void arrivals_step(const sloth_state_t *s) {
    int n = 0;
    for (int j = 0; j < s->beacon_count && j < MAX_BEACON_APS; j++) {
        const beacon_ap_t *b = &s->beacon_aps[j];
        if (!laa(b->bssid) || !b->ssid[0] || !b->first_seen) continue;
        int k = 0;
        while (k < g_laa_n && (memcmp(g_laa[k].bssid, b->bssid, 6) != 0 ||
                               g_laa[k].first_seen != b->first_seen))
            k++;
        int counted = k < g_laa_n;
        if (!counted) {
            for (int i = 0; i < s->beacon_count && !counted; i++)
                if (i != j && twin_late_laa_copy(&s->beacon_aps[i], b, NULL))
                    counted = 1;
            if (!counted) continue;
            g_c.late_laa++;
        }
        memcpy(g_laa_next[n].bssid, b->bssid, 6);
        g_laa_next[n].first_seen = b->first_seen;
        n++;
    }
    memcpy(g_laa, g_laa_next, (size_t)n * sizeof(g_laa[0]));
    g_laa_n = n;
}

void twin_field_begin(const sloth_state_t *s, time_t now) {
    if (g_off || !s) return;
    if (!g_c.since) g_c.since = now;
    floods_step(s);
    arrivals_step(s);
}

void twin_field_flood(const uint8_t bssid[6], int fired, int shape,
                      unsigned excl) {
    if (g_off || !bssid) return;
    int k = 0;
    while (k < g_fl_n && memcmp(g_fl[k].bssid, bssid, 6) != 0) k++;
    /* The chain's flood is a row with `flood` set, so begin() has it;
     * a miss is a caller that skipped begin(), and is not counted. */
    if (k == g_fl_n) return;
    tf_flood_t *e = &g_fl[k];
    if (!e->examined) { e->examined = 1; g_c.floods_chain++; }
    if (fired) {
        if (!e->named) { e->named = 1; g_c.named++; }
        return;
    }
    if (!shape || e->named || e->coincided) return;
    e->coincided = 1;
    g_c.coincide++;
    if (excl & TWIN_FIELD_EXCL_CARRIER) g_c.excl_carrier++;
    if (excl & TWIN_FIELD_EXCL_FAINT)   g_c.excl_faint++;
    if (excl & TWIN_FIELD_EXCL_SIBLING) g_c.excl_sibling++;
    if (excl) g_c.excl_any++;
}
