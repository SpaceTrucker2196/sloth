#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "ble_flood.h"
#include "stab.h"
#include "tune.h"

/* Contract in ble_flood.h.
 *
 * ── The spam list (gate 3) ──
 *
 * A key is on it only where a primary source documents that a public
 * BLE-spam tool emits it. The source is the tool itself: the "BLE Spam"
 * application the Flipper Zero coverage describes (BleepingComputer,
 * 2023-10-25; Bitdefender, 2023-10-27), read in the Momentum apps
 * repository, ble_spam/protocols/. Quoted and dated in
 * research/bluetooth/ble-spam-flood.md. Every one of these keys is ALSO
 * what a genuine device of that kind advertises - AirPods send Proximity
 * Pair, a Fast Pair headset sends 0xFE2C - which is why gate 3 alone
 * never fires and gates 1 and 2 exist. */
typedef struct {
    uint8_t     family;
    uint16_t    id;
    int16_t     subtype;
    const char *source;
} spam_row_t;

static const spam_row_t k_spam[] = {
    { BLE_FAM_MFR, 0x004C, 0x07,
      "ble_spam continuity.h: ContinuityTypeProximityPair = 0x07, company 0x4C" },
    { BLE_FAM_MFR, 0x004C, 0x0F,
      "ble_spam continuity.h: ContinuityTypeNearbyAction = 0x0F (Action Modal, iOS 17 crash)" },
    { BLE_FAM_MFR, 0x0006, 0x03,
      "ble_spam swiftpair.c: company 0x06 (Microsoft), Microsoft Beacon ID 0x03" },
    { BLE_FAM_MFR, 0x0075, 0x42,
      "ble_spam easysetup.c: company 0x75 (Samsung), buds packet 0x42" },
    { BLE_FAM_MFR, 0x0075, 0x01,
      "ble_spam easysetup.c: company 0x75 (Samsung), watch packet 0x01" },
    { BLE_FAM_SVC_DATA, 0xFE2C, -1,
      "ble_spam fastpair.c: Service Data 0x16, UUID 0xFE2C (Google Fast Pair)" },
};

int ble_spam_family_known(int family, uint16_t id, int subtype,
                          const char **source) {
    for (size_t i = 0; i < sizeof(k_spam) / sizeof(k_spam[0]); i++) {
        const spam_row_t *r = &k_spam[i];
        if (r->family == family && r->id == id && r->subtype == subtype) {
            if (source) *source = r->source;
            return 1;
        }
    }
    if (source) *source = NULL;
    return 0;
}

const char *ble_family_name(int family) {
    switch (family) {
    case BLE_FAM_MFR:      return "mfr";
    case BLE_FAM_SVC_DATA: return "svc_data";
    default:               return "none";
    }
}

/* ── The table ─────────────────────────────────────────────────────── */

/* Address sets per window, for the fresh-address count (gate 1). Two
 * bits per address in 4096: 512 bytes a set, three sets a row. With
 * BLE_FLOOD_ADDR_CAP-sized floods the false-positive rate is a few per
 * cent; past a few thousand addresses a window it climbs, and every
 * false positive is an address wrongly called "heard before" - fresh
 * under-counts, which can hide a flood but never make one. */
#define FLOOD_BLOOM_BITS  4096u
#define FLOOD_BLOOM_BYTES (FLOOD_BLOOM_BITS / 8u)

typedef struct {
    ble_flood_row_t pub;
    uint64_t win_start_ms;
    uint8_t  bloom_cur[FLOOD_BLOOM_BYTES];    /* this window */
    uint8_t  bloom_prev[FLOOD_BLOOM_BYTES];   /* the window before */
    uint8_t  bloom_prev2[FLOOD_BLOOM_BYTES];  /* the one before that */
    uint8_t  addrs[BLE_FLOOD_ADDR_CAP][7];   /* display order + type */
    int8_t   rssi[BLE_FLOOD_RSSI_CAP];
    uint8_t  rssi_n;
} flood_row_t;

typedef struct {
    uint8_t     kind, adv_type, family;
    uint16_t    id;
    int16_t     subtype;
    char        iface[sizeof(((ble_flood_row_t *)0)->sensor_iface)];
} flood_key_t;

static int flood_key_eq(const void *row, const void *key) {
    const flood_row_t *r = row;
    const flood_key_t *k = key;
    return r->pub.sensor_kind == k->kind && r->pub.adv_type == k->adv_type &&
           r->pub.family == k->family && r->pub.id == k->id &&
           r->pub.subtype == k->subtype &&
           strcmp(r->pub.sensor_iface, k->iface) == 0;
}

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
STAB_DECL(g_flood, flood_row_t, MAX_BLE_FLOOD, pub.last_seen, STAB_OLDEST,
          SH_EVICT_BLE_FLOOD, NULL, flood_key_eq);

static uint32_t window_ms(void) {
    return (uint32_t)tune_val(TUNE_BLE_FLOOD_WINDOW_S) * 1000u;
}

static int8_t median(const int8_t *v, int n) {
    int8_t t[BLE_FLOOD_RSSI_CAP];
    memcpy(t, v, (size_t)n);
    for (int i = 1; i < n; i++) {             /* n <= 64: insertion sort */
        int8_t x = t[i];
        int j = i - 1;
        while (j >= 0 && t[j] > x) { t[j + 1] = t[j]; j--; }
        t[j + 1] = x;
    }
    return t[n / 2];
}

/* The window in progress, with its median filled in. */
static ble_flood_win_t cur_win(const flood_row_t *r) {
    ble_flood_win_t w = r->pub.cur;
    w.has_rssi = r->rssi_n > 0;
    w.rssi_median = r->rssi_n ? median(r->rssi, r->rssi_n) : 0;
    return w;
}

/* The window in progress starts empty; it has a baseline when the
 * window just closed held something on this key. */
static void cur_reset(flood_row_t *r) {
    memset(&r->pub.cur, 0, sizeof(r->pub.cur));
    memset(r->bloom_cur, 0, sizeof(r->bloom_cur));
    r->pub.cur.baseline = r->pub.prev.total > 0;
    r->rssi_n = 0;
}

static void bloom_bits(const uint8_t a[7], unsigned *b1, unsigned *b2) {
    uint64_t h = 0xcbf29ce484222325ULL;           /* FNV-1a 64 */
    for (int i = 0; i < 7; i++) { h ^= a[i]; h *= 0x100000001b3ULL; }
    *b1 = (unsigned)(h % FLOOD_BLOOM_BITS);
    *b2 = (unsigned)((h >> 32) % FLOOD_BLOOM_BITS);
}

static int bloom_has(const uint8_t *set, unsigned b1, unsigned b2) {
    return ((set[b1 >> 3] >> (b1 & 7)) & 1) && ((set[b2 >> 3] >> (b2 & 7)) & 1);
}

static void bloom_add(uint8_t *set, unsigned b1, unsigned b2) {
    set[b1 >> 3] |= (uint8_t)(1u << (b1 & 7));
    set[b2 >> 3] |= (uint8_t)(1u << (b2 & 7));
}

/* Close every window `now_ms` is past. Exactly one closed: it becomes
 * `prev`. More than one: the window before now held nothing. A changed
 * window length (--tune) restarts the row, so counts taken over one
 * length are never judged against another. */
static void roll(flood_row_t *r, uint64_t now_ms, uint32_t win) {
    if (r->pub.window_ms != win) {
        r->pub.window_ms = win;
        memset(&r->pub.prev, 0, sizeof(r->pub.prev));
        memset(r->bloom_prev, 0, sizeof(r->bloom_prev));
        memset(r->bloom_prev2, 0, sizeof(r->bloom_prev2));
        cur_reset(r);
        r->win_start_ms = now_ms;
        return;
    }
    if (now_ms < r->win_start_ms + win) return;
    uint64_t n = (now_ms - r->win_start_ms) / win;
    if (n == 1) {
        r->pub.prev = cur_win(r);
        memcpy(r->bloom_prev2, r->bloom_prev, sizeof(r->bloom_prev2));
        memcpy(r->bloom_prev, r->bloom_cur, sizeof(r->bloom_prev));
    } else {
        memset(&r->pub.prev, 0, sizeof(r->pub.prev));
        if (n == 2) memcpy(r->bloom_prev2, r->bloom_cur, sizeof(r->bloom_prev2));
        else        memset(r->bloom_prev2, 0, sizeof(r->bloom_prev2));
        memset(r->bloom_prev, 0, sizeof(r->bloom_prev));
    }
    cur_reset(r);
    r->win_start_ms += n * win;
}

void ble_flood_note(const ble_obs_t *o, const uint8_t addr[6],
                    uint64_t now_ms) {
    if (!o || !o->r || !addr) return;
    const ble_adv_report_t *rep = o->r;
    flood_key_t k;
    memset(&k, 0, sizeof(k));
    if (rep->has_mfr_data) {
        k.family  = BLE_FAM_MFR;
        k.id      = rep->mfr_id;
        k.subtype = rep->mfr_data_len >= 1 ? rep->mfr_data[0] : -1;
    } else if (rep->has_svc_data16) {
        k.family  = BLE_FAM_SVC_DATA;
        k.id      = rep->svc_data_uuid16;
        k.subtype = -1;
    } else {
        return;
    }
    k.kind     = o->sensor_kind;
    k.adv_type = rep->event_type;
    snprintf(k.iface, sizeof(k.iface), "%s", o->iface ? o->iface : "");

    const uint32_t win = window_ms();
    pthread_mutex_lock(&g_mu);
    int created = 0;
    flood_row_t *r = stab_get(&g_flood, &k, o->ts, &created);
    if (r) {
        if (created) {
            r->pub.sensor_kind = k.kind;
            memcpy(r->pub.sensor_iface, k.iface, sizeof(k.iface));
            r->pub.adv_type   = k.adv_type;
            r->pub.family     = k.family;
            r->pub.id         = k.id;
            r->pub.subtype    = k.subtype;
            r->pub.spam_known = (uint8_t)ble_spam_family_known(
                k.family, k.id, k.subtype, NULL);
            r->pub.window_ms  = win;
            r->pub.first_seen = o->ts;
            r->win_start_ms   = now_ms;
        }
        roll(r, now_ms, win);
        r->pub.last_seen = o->ts;
        r->pub.sampled   = o->sampled ? 1 : 0;
        r->pub.total_all++;
        r->pub.cur.total++;

        uint8_t a[7];
        memcpy(a, addr, 6);
        a[6] = rep->addr_type;
        int n = r->pub.cur.distinct, seen = 0;
        for (int i = 0; i < n; i++)
            if (memcmp(r->addrs[i], a, 7) == 0) { seen = 1; break; }
        if (!seen) {
            if (n < BLE_FLOOD_ADDR_CAP) {
                memcpy(r->addrs[n], a, 7);
                r->pub.cur.distinct++;
            } else {
                r->pub.cur.distinct_capped = 1;
            }
        }
        /* Fresh: first time in this window, and in neither of the two
         * before it. A crowd of genuine advertisers keeps its addresses
         * across windows; the spam tool takes a new one per payload
         * (ble_spam.c start_extra_beacon(), research/bluetooth/
         * ble-spam-flood.md). */
        unsigned b1, b2;
        bloom_bits(a, &b1, &b2);
        if (!bloom_has(r->bloom_cur, b1, b2)) {
            bloom_add(r->bloom_cur, b1, b2);
            if (!bloom_has(r->bloom_prev, b1, b2) &&
                !bloom_has(r->bloom_prev2, b1, b2))
                r->pub.cur.fresh++;
        }
        if (rep->has_rssi && r->rssi_n < BLE_FLOOD_RSSI_CAP)
            r->rssi[r->rssi_n++] = rep->rssi;
    }
    pthread_mutex_unlock(&g_mu);
}

void ble_flood_snapshot(sloth_state_t *s, uint64_t now_ms) {
    if (!s) return;
    const uint32_t win = window_ms();
    pthread_mutex_lock(&g_mu);
    int n = 0;
    for (int i = 0; i < stab_count(&g_flood) && n < MAX_BLE_FLOOD; i++) {
        flood_row_t *r = stab_at(&g_flood, i);
        if (!r) continue;
        roll(r, now_ms, win);
        ble_flood_row_t *o = &s->ble_flood[n++];
        *o = r->pub;
        o->cur = cur_win(r);
        o->cur_elapsed_ms = now_ms > r->win_start_ms
            ? (uint32_t)(now_ms - r->win_start_ms) : 0;
    }
    s->ble_flood_count = n;
    pthread_mutex_unlock(&g_mu);
}

void ble_flood_clear(void) {
    pthread_mutex_lock(&g_mu);
    stab_clear(&g_flood);
    pthread_mutex_unlock(&g_mu);
}
