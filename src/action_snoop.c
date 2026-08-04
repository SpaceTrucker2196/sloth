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
    (void)now;   /* slice 1 counts only; the rate window lands with the rule */
    int cat = action_parse_category(dot11, len, NULL);
    if (cat < 0) return;
    pthread_mutex_lock(&g_mu);
    g_cat_count[cat]++;
    g_total++;
    pthread_mutex_unlock(&g_mu);
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
