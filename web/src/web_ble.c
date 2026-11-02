#include "web_ble.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_btsig.h"
#include "web_query.h"
#include "web_series.h"
#include "web_ssid.h"

/* ── the vocabularies (sloth's own words; test_parity.c holds them to
 *    src/ble_detect.c, src/rf_distance.c and src/ble_flood.c) ────── */

static const char *const IFACE[WEB_BLE_IF_COUNT] = { "bluetooth-monitor", "ubertooth", "other" };
static const char *const PDU[WEB_BLE_PDU_COUNT] = {
    "ADV_IND", "ADV_DIRECT_IND", "ADV_SCAN_IND", "ADV_NONCONN_IND", "SCAN_RSP",
    "EXT_ADV", "EXT_SCAN_RSP", "adv",
};
static const char *const BAND[WEB_BLE_BAND_COUNT] = {
    "", "immediate", "near", "room", "building", "far",
};
static const char *const BAND_SHORT[WEB_BLE_BAND_COUNT] = { "", "imm", "near", "room", "bldg", "far" };
static const char *const TREND[WEB_BLE_TREND_COUNT] = { "unknown", "approaching", "steady", "leaving" };
static const char *const TREND_GLYPH[WEB_BLE_TREND_COUNT] = {
    "", "\xe2\x86\x98", "\xe2\x86\x92", "\xe2\x86\x97",
};
static const char *const PTX[WEB_BLE_PTX_COUNT] = { "ble_ext_tx_power", "ble_ad_tx_power", "assumed" };
static const char *const PTX_SHORT[WEB_BLE_PTX_COUNT] = { "ext-hdr", "ad", "assumed" };
static const char *const KIND[WEB_BLE_FIND_COUNT] = {
    "adv_flood", "hid_oui", "hid_rotate", "watchlist", "other",
};
static const char *const ALERT[WEB_BLE_ALERT_COUNT] = {
    "BLE_ADV_FLOOD", "BLE_HID_UNEXPECTED", "BLE_WATCHLIST", "other",
};
static const char *const FAMILY[3] = { "mfr", "svc_data", "other" };
static const char *const OUI_TABLE[3] = { "Hak5", "Espressif", "other" };

#define IN(i, n) ((i) >= 0 && (i) < (int)(n))
const char *web_ble_iface_name(int i)  { return IN(i, WEB_BLE_IF_COUNT) ? IFACE[i] : "other"; }
const char *web_ble_pdu_name(int i)    { return IN(i, WEB_BLE_PDU_COUNT) ? PDU[i] : "adv"; }
const char *web_ble_band_name(int b)   { return IN(b, WEB_BLE_BAND_COUNT) ? BAND[b] : ""; }
const char *web_ble_band_short(int b)  { return IN(b, WEB_BLE_BAND_COUNT) ? BAND_SHORT[b] : ""; }
const char *web_ble_trend_name(int t)  { return IN(t, WEB_BLE_TREND_COUNT) ? TREND[t] : "unknown"; }
const char *web_ble_trend_glyph(int t) { return IN(t, WEB_BLE_TREND_COUNT) ? TREND_GLYPH[t] : ""; }
const char *web_ble_ptx_name(int p)    { return IN(p, WEB_BLE_PTX_COUNT) ? PTX[p] : "assumed"; }
const char *web_ble_ptx_short(int p)   { return IN(p, WEB_BLE_PTX_COUNT) ? PTX_SHORT[p] : "assumed"; }
const char *web_ble_kind_name(int k)   { return IN(k, WEB_BLE_FIND_COUNT) ? KIND[k] : "other"; }
const char *web_ble_alert_name(int a)  { return IN(a, WEB_BLE_ALERT_COUNT) ? ALERT[a] : "other"; }
const char *web_ble_family_name(int f) { return IN(f, 3) ? FAMILY[f] : "other"; }
const char *web_ble_oui_table_name(int o) { return IN(o, 3) ? OUI_TABLE[o] : "other"; }

char web_ble_type_ch(int t) {
    switch (t) {
    case 0:  return 'P';
    case 1:  return 'R';
    case 2:  return 'p';
    case 3:  return 'r';
    default: return '?';
    }
}

const char *web_ble_addr_kind(const uint8_t addr[6], int t) {
    static const char *const RANDOM[4] = { "random NRPA", "random RPA", "random reserved",
                                           "random static" };
    switch (t) {
    case 0:   return "public";
    case 1:   return RANDOM[(addr[0] >> 6) & 3];
    case 2:   return "resolved public";
    case 3:   return "resolved random";
    case 255: return "anonymous";
    default:  return "unknown";
    }
}

/* A word's index in a table, or -1. */
static int find_word(const char *const *tab, int n, const char *s) {
    for (int i = 0; s && i < n; i++)
        if (!strcmp(tab[i], s)) return i;
    return -1;
}

/* A word's index in a closed vocabulary whose last slot is "other":
 * anything else lands there, counted. */
static int word_of(const char *const *tab, int n, const char *s, unsigned long *other) {
    int i = find_word(tab, n - 1, s);
    if (i >= 0) return i;
    if (other) (*other)++;
    return n - 1;
}

void web_ble_key_hash(const char *s, char out[17]) {
    uint64_t h = 0xcbf29ce484222325ULL;
    for (const unsigned char *p = (const unsigned char *)s; s && *p; p++) {
        h ^= *p;
        h *= 0x100000001b3ULL;
    }
    snprintf(out, 17, "%016llx", (unsigned long long)h);
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* "xx:xx:xx:xx:xx:xx" (either case) to bytes. 0, or -1. */
static int addr_bytes(const char *s, uint8_t out[6]) {
    if (!s || strlen(s) != 17) return -1;
    for (int i = 0; i < 6; i++) {
        int a = hexv((unsigned char)s[i * 3]), b = hexv((unsigned char)s[i * 3 + 1]);
        if (a < 0 || b < 0 || (i < 5 && s[i * 3 + 2] != ':')) return -1;
        out[i] = (uint8_t)(a << 4 | b);
    }
    return 0;
}

static void addr_text(const uint8_t a[6], char *out) {
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
}

/* A watch category is sloth's own slug (src/ble_watchlist.c): 1..15
 * bytes of [a-z0-9_-]. Anything else is not kept. */
static int cat_ok(const char *s) {
    if (!s || !s[0] || strlen(s) > WEB_BLE_CAT_MAX) return 0;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') || *s == '_' || *s == '-'))
            return 0;
    return 1;
}

/* A bounded integer member: def when absent or out of range. */
static long long ibound(const web_jrec_t *r, const char *k, long long lo, long long hi,
                        long long def) {
    long long v = web_jl_int(r, k, def);
    return v < lo || v > hi ? def : v;
}

static void sstr(char *out, size_t max, const web_jrec_t *r, const char *k) {
    const char *s = web_jl_str(r, k);
    web_utf8_copy(out, max, s ? s : "");
}

/* ── init ───────────────────────────────────────────────────────────── */

int web_ble_init(web_ble_t *b, int store_on) {
    memset(b, 0, sizeof(*b));
    b->store_on = store_on;
    b->dev = calloc(WEB_BLE_DEVICES, sizeof(*b->dev));
    b->al = calloc(WEB_BLE_ALERTS, sizeof(*b->al));
    if (!b->dev || !b->al) {
        free(b->dev);
        free(b->al);
        b->dev = NULL;
        b->al = NULL;
        return -1;
    }
    pthread_mutex_init(&b->mu, NULL);
    return 0;
}

void web_ble_destroy(web_ble_t *b) {
    if (!b->dev) return;
    pthread_mutex_destroy(&b->mu);
    free(b->dev);
    free(b->al);
    b->dev = NULL;
    b->al = NULL;
}

/* ── the advertiser table ───────────────────────────────────────────── */

static web_ble_dev_t *dev_find(web_ble_t *b, const uint8_t addr[6], int type, int iface) {
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        web_ble_dev_t *d = &b->dev[i];
        if (d->used && d->addr_type == type && d->iface == iface && !memcmp(d->addr, addr, 6))
            return d;
    }
    return NULL;
}

static int dev_older(const web_ble_dev_t *d, const web_ble_dev_t *than) {
    return !than || d->last_seen < than->last_seen ||
           (d->last_seen == than->last_seen && d->touched < than->touched);
}

/* A free row, else the least recently heard (by its own last_seen, then
 * by arrival) of the rows with neither a HID flag nor a watch category,
 * evicted and counted. An address flood is many plain rows, each heard
 * once and newer than the resident keyboard or tracker, so age alone
 * would evict the rows that matter first, and one not yet flushed would
 * never reach slothweb.db; the store's row cap orders the same way. The
 * plain oldest of all only when every row is flagged. */
static web_ble_dev_t *dev_slot(web_ble_t *b) {
    web_ble_dev_t *lru = NULL, *plain = NULL;
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        web_ble_dev_t *d = &b->dev[i];
        if (!d->used) return d;
        if (dev_older(d, lru)) lru = d;
        if (!d->hid && !d->watch_category[0] && dev_older(d, plain)) plain = d;
    }
    if (plain) lru = plain;
    b->st.evictions++;
    if (lru->dirty) b->st.evicted_dirty++;
    b->st.rows--;
    memset(lru, 0, sizeof(*lru));
    return lru;
}

/* Set the presence bit of the bucket ts falls in: a newer bucket shifts
 * the strip up to it (the buckets between are quiet), an older one
 * within the day sets its bit, one older than the day is dropped. */
static void pres_mark(web_ble_dev_t *d, long long ts) {
    if (ts <= 0) return;
    long long bk = ts / WEB_BLE_PRES_S;
    if (d->pres_bucket == 0 || bk > d->pres_bucket) {
        long long sh = d->pres_bucket == 0 ? WEB_BLE_PRES_N : bk - d->pres_bucket;
        if (sh >= WEB_BLE_PRES_N) {
            d->pres[0] = d->pres[1] = 0;
        } else if (sh >= 64) {
            d->pres[1] = d->pres[0] << (sh - 64);
            d->pres[0] = 0;
        } else if (sh > 0) {
            d->pres[1] = (d->pres[1] << sh) | (d->pres[0] >> (64 - sh));
            d->pres[0] <<= sh;
        }
        d->pres[1] &= ((uint64_t)1 << (WEB_BLE_PRES_N - 64)) - 1;
        d->pres_bucket = bk;
    }
    long long i = d->pres_bucket - bk;
    if (i < 0 || i >= WEB_BLE_PRES_N) return;
    if (i < 64) d->pres[0] |= (uint64_t)1 << i;
    else d->pres[1] |= (uint64_t)1 << (i - 64);
}

static void dev_fill(web_ble_t *b, web_ble_dev_t *d, const web_jrec_t *r, long long ts) {
    d->adapter = (int)ibound(r, "adapter", 0, 65535, 0);
    d->sampled = web_jl_int(r, "sampled", 0) == 1;
    d->channel = (int)ibound(r, "channel", -1, 39, -1);
    int pdu = find_word(PDU, WEB_BLE_PDU_COUNT, web_jl_str(r, "last_pdu"));
    d->last_pdu = pdu < 0 ? WEB_BLE_PDU_ADV : pdu;
    d->pdu_mask |= (int)ibound(r, "pdu_mask", 0, 127, 0);
    const char *name = web_jl_str(r, "name");
    if (name && name[0]) {
        int np = 0;
        /* Read to 96 bytes (32 octets, three each at most), cut back to
         * a code-point boundary: a byte cut through a sequence would
         * leave its lead byte as a \xNN and flag a name that was valid
         * UTF-8 on the stream. */
        size_t nl = strnlen(name, 32 * 3);
        if (name[nl])
            while (nl > 0 && ((unsigned char)name[nl] & 0xc0) == 0x80) nl--;
        web_ssid_escape(name, nl, d->name, sizeof(d->name), &np);
        d->name_np = np;
        if (np) b->st.name_escaped++;
    } else {
        d->name[0] = '\0';
        d->name_np = 0;
    }
    d->name_complete = web_jl_int(r, "name_complete", 0) == 1;
    d->uuid16 = (int)ibound(r, "uuid16", -1, 65535, -1);
    d->mfr_id = (int)ibound(r, "mfr_id", -1, 65535, -1);
    d->mfr_subtype = (int)ibound(r, "mfr_subtype", -1, 255, -1);
    d->svc_data_uuid16 = (int)ibound(r, "svc_data_uuid16", -1, 65535, -1);
    d->appearance = (int)ibound(r, "appearance", -1, 65535, -1);
    d->hid |= (int)ibound(r, "hid", 0, 3, 0);
    d->tx_power = (int)ibound(r, "tx_power", -128, 127, -128);
    d->flags = (int)ibound(r, "flags", -1, 255, -1);
    d->has_rssi = web_jl_int(r, "has_rssi", 0) == 1;
    d->rssi = d->has_rssi ? (int)ibound(r, "rssi", -127, 20, 0) : 0;
    d->rssi_best = d->has_rssi ? (int)ibound(r, "rssi_best", -127, 20, 0) : 0;
    /* adv_count and last_seen only move up, as the store's upsert keeps
     * them (MAX): an older or repeated record (a second sensor's replay,
     * a reconnect's catch-up) never takes the row back. */
    long long ac = web_jl_int(r, "adv_count", 0);
    if (ac > 0 && (unsigned long long)ac > d->adv_count) d->adv_count = (unsigned long long)ac;
    const char *cat = web_jl_str(r, "watch_category");
    if (cat_ok(cat)) snprintf(d->watch_category, sizeof(d->watch_category), "%s", cat);
    else {
        if (cat && cat[0]) b->st.other_word++;
        d->watch_category[0] = '\0';
    }
    d->ext_adv = web_jl_int(r, "ext_adv", 0) == 1;
    d->primary_phy = (int)ibound(r, "primary_phy", 0, 4, 0);
    d->secondary_phy = (int)ibound(r, "secondary_phy", 0, 4, 0);
    d->adv_sid = (int)ibound(r, "adv_sid", -1, 15, -1);
    long long fs = web_jl_int(r, "first_seen", 0), ls = web_jl_int(r, "last_seen", 0);
    if (fs > 0 && (d->first_seen == 0 || fs < d->first_seen)) d->first_seen = fs;
    if (ls > d->last_seen) d->last_seen = ls;
    else if (ls <= 0 && ts > 0 && d->last_seen == 0) d->last_seen = ts;
    /* The estimate: present with all four members or absent. */
    double m;
    int band = find_word(BAND, WEB_BLE_BAND_COUNT, web_jl_str(r, "est_dist_band"));
    if (web_jl_num(r, "est_dist_m", &m) && m >= 0 && m < 100000 && band > WEB_BLE_BAND_NONE) {
        d->est_valid = 1;
        d->est_dist_dm = (int)floor(m * 10 + 0.5);
        d->est_band = band;
        int tr = find_word(TREND, WEB_BLE_TREND_COUNT, web_jl_str(r, "est_dist_trend"));
        d->est_trend = tr < 0 ? WEB_BLE_TREND_UNKNOWN : tr;
        int px = find_word(PTX, WEB_BLE_PTX_COUNT, web_jl_str(r, "est_ptx_source"));
        d->est_ptx = px < 0 ? WEB_BLE_PTX_ASSUMED : px;
    } else {
        d->est_valid = 0;
        d->est_dist_dm = -1;
        d->est_band = d->est_trend = 0;
        d->est_ptx = WEB_BLE_PTX_ASSUMED;
    }
    /* The rate points: one per record with a later frame time. */
    long long pt = d->last_seen > 0 ? d->last_seen : ts;
    if (d->records == 0) pres_mark(d, d->first_seen);
    if (ls > 0 && ls < pt) pres_mark(d, ls);   /* an older record's own bucket */
    pres_mark(d, pt);
    if (d->npts == 0 || pt > d->pts[(d->pt_head + d->npts - 1) % WEB_BLE_PTS].ts) {
        int at = (d->pt_head + d->npts) % WEB_BLE_PTS;
        if (d->npts == WEB_BLE_PTS) d->pt_head = (d->pt_head + 1) % WEB_BLE_PTS;
        else d->npts++;
        d->pts[at].ts = pt;
        d->pts[at].count = d->adv_count;
    }
    d->records++;
    d->dirty = 1;
    d->touched = ++b->touch;
}

static void dev_apply(web_ble_t *b, const web_jrec_t *r, long long ts) {
    uint8_t addr[6];
    const char *a = web_jl_str(r, "addr");
    long long type = web_jl_int(r, "addr_type", -1);
    const char *iface = web_jl_str(r, "iface");
    if (addr_bytes(a, addr) != 0 || !(type == 255 || (type >= 0 && type <= 3)) || !iface) {
        b->st.bad_records++;
        return;
    }
    int ifi = word_of(IFACE, WEB_BLE_IF_COUNT, iface, &b->st.other_iface);
    web_ble_dev_t *d = dev_find(b, addr, (int)type, ifi);
    if (!d) {
        d = dev_slot(b);
        d->used = 1;
        memcpy(d->addr, addr, 6);
        d->addr_type = (int)type;
        d->iface = ifi;
        d->tx_power = -128;
        d->uuid16 = d->mfr_id = d->mfr_subtype = d->svc_data_uuid16 = d->appearance = -1;
        d->flags = -1;
        d->adv_sid = -1;
        d->est_dist_dm = -1;
        b->st.rows++;
    }
    dev_fill(b, d, r, ts);
    b->st.device_records++;
}

/* ── the findings ───────────────────────────────────────────────────── */

static web_ble_alert_t *al_find(web_ble_t *b, const char *key) {
    for (int i = 0; i < WEB_BLE_ALERTS; i++)
        if (b->al[i].used && !strcmp(b->al[i].key, key)) return &b->al[i];
    return NULL;
}

/* The finding a live key names: the row of that key, else the row the
 * store seeded under its hash (the key itself was never stored). */
static web_ble_alert_t *al_find_live(web_ble_t *b, const char *key) {
    web_ble_alert_t *a = al_find(b, key);
    if (a) return a;
    char hk[WEB_BLE_KEY_MAX + 1];
    char h[17];
    web_ble_key_hash(key, h);
    snprintf(hk, sizeof(hk), "#%s", h);
    return al_find(b, hk);
}

/* A free slot, else the oldest resolved finding, else the oldest
 * standing one; evicted and counted. */
static web_ble_alert_t *al_slot(web_ble_t *b) {
    web_ble_alert_t *res = NULL, *old = NULL;
    for (int i = 0; i < WEB_BLE_ALERTS; i++) {
        web_ble_alert_t *a = &b->al[i];
        if (!a->used) return a;
        if (!a->standing && (!res || a->last_ts < res->last_ts)) res = a;
        if (!old || a->last_ts < old->last_ts) old = a;
    }
    web_ble_alert_t *v = res ? res : old;
    b->st.alert_evictions++;
    b->st.alert_rows--;
    memset(v, 0, sizeof(*v));
    return v;
}

static void al_apply(web_ble_t *b, const web_jrec_t *r, long long ts) {
    const char *key = web_jl_str(r, "key");
    const char *kind = web_jl_str(r, "kind");
    if (!key || !key[0] || strlen(key) > WEB_BLE_KEY_MAX || !kind) {
        b->st.bad_records++;
        return;
    }
    web_ble_alert_t *a = al_find_live(b, key);
    if (a && a->key[0] == '#')       /* a seeded row: the live key again */
        snprintf(a->key, sizeof(a->key), "%s", key);
    if (!a) {
        a = al_slot(b);
        a->used = 1;
        snprintf(a->key, sizeof(a->key), "%s", key);
        a->first_ts = ts;
        a->resolved_ts = -1;
        b->st.alert_rows++;
    }
    a->kind = word_of(KIND, WEB_BLE_FIND_COUNT, kind, &b->st.other_word);
    a->alert = word_of(ALERT, WEB_BLE_ALERT_COUNT, web_jl_str(r, "alert"), &b->st.other_word);
    a->ty = (int)ibound(r, "ty", -1, 65535, -1);
    a->iface = word_of(IFACE, WEB_BLE_IF_COUNT, web_jl_str(r, "iface"), &b->st.other_iface);
    a->sampled = web_jl_int(r, "sampled", 0) == 1;
    a->standing = 1;
    a->resolved_ts = -1;
    if (ts > 0) a->last_ts = ts;
    if (a->first_ts <= 0 || (ts > 0 && ts < a->first_ts)) a->first_ts = ts;
    switch (a->kind) {
    case WEB_BLE_FIND_FLOOD:
        a->adv_type = find_word(PDU, WEB_BLE_PDU_COUNT, web_jl_str(r, "adv_type"));
        if (a->adv_type < 0) a->adv_type = WEB_BLE_PDU_ADV;
        a->family = word_of(FAMILY, 3, web_jl_str(r, "family"), &b->st.other_word);
        a->id = (int)ibound(r, "id", 0, 65535, 0);
        a->subtype = (int)ibound(r, "subtype", -1, 255, -1);
        a->window = web_jl_str(r, "window") && !strcmp(web_jl_str(r, "window"), "previous");
        a->window_s = (int)ibound(r, "window_s", 0, 86400, 0);
        a->distinct = ibound(r, "distinct_addrs", 0, 1 << 30, 0);
        a->distinct_capped = web_jl_int(r, "distinct_capped", 0) == 1;
        a->fresh = ibound(r, "fresh_addrs", 0, 1 << 30, 0);
        a->total = ibound(r, "total_adv", 0, 1LL << 40, 0);
        if (!web_jl_num(r, "rate", &a->rate) || a->rate < 0) a->rate = 0;
        a->has_rssi = web_jl_int(r, "has_rssi", 0) == 1;
        a->median_rssi = a->has_rssi ? (int)ibound(r, "median_rssi", -127, 20, 0) : 0;
        {
            /* sloth's own citation line, not a peer's text; cut, and in
             * the display form all the same. */
            const char *src = web_jl_str(r, "spam_source");
            web_ssid_escape(src ? src : "", src ? strnlen(src, WEB_BLE_DETAIL_MAX) : 0, a->spam_source,
                            sizeof(a->spam_source), NULL);
        }
        break;
    case WEB_BLE_FIND_HID_OUI:
        if (addr_bytes(web_jl_str(r, "addr"), a->addr) != 0) memset(a->addr, 0, 6);
        a->addr_type = (int)ibound(r, "addr_type", 0, 255, 0);
        a->hid = (int)ibound(r, "hid", 0, 3, 0);
        a->appearance = (int)ibound(r, "appearance", -1, 65535, -1);
        a->oui_table = word_of(OUI_TABLE, 3, web_jl_str(r, "oui_table"), &b->st.other_word);
        break;
    case WEB_BLE_FIND_HID_ROTATE:
        a->addrs = ibound(r, "addrs", 0, 1 << 30, 0);
        a->window_s = (int)ibound(r, "window_s", 0, 86400, 0);
        a->appearance = (int)ibound(r, "appearance", -1, 65535, -1);
        break;
    case WEB_BLE_FIND_WATCH: {
        const char *cat = web_jl_str(r, "category");
        if (cat_ok(cat)) snprintf(a->category, sizeof(a->category), "%s", cat);
        else { a->category[0] = '\0'; if (cat && cat[0]) b->st.other_word++; }
        a->addrs = ibound(r, "addrs", 0, 1 << 30, 0);
        a->window_s = (int)ibound(r, "window_s", 0, 86400, 0);
        break;
    }
    default:
        break;
    }
    a->dirty = 1;
    a->seq = ++b->seq;
    b->st.alert_records++;
}

/* An alert.resolve of a key this table holds ends that finding. Any
 * other key (every non-BLE alert) is passed over. */
static void resolve_apply(web_ble_t *b, const web_jrec_t *r, long long ts) {
    const char *key = web_jl_str(r, "key");
    if (!key || !key[0] || strlen(key) > WEB_BLE_KEY_MAX) return;
    web_ble_alert_t *a = al_find_live(b, key);
    if (!a || !a->standing) return;
    a->standing = 0;
    a->resolved_ts = ts > 0 ? ts : a->last_ts;
    a->dirty = 1;
    a->seq = ++b->seq;
    b->st.resolves++;
}

/* ── sensor_health ──────────────────────────────────────────────────── */

static void sh_apply(web_ble_t *b, const web_jrec_t *r, long long ts) {
    /* An older sloth, or one built without the Bluetooth source, has no
     * btmon_iface: nothing to say, and what was said before stands. */
    if (!web_jl_get(r, "btmon_iface")) return;
    web_ble_sh_t *s = &b->sh;
    s->seen = 1;
    s->ts = ts;
    sstr(s->btmon_iface, WEB_BLE_SH_STR, r, "btmon_iface");
    sstr(s->btmon_err, WEB_BLE_SH_STR, r, "btmon_err");
    sstr(s->btmon_exit, WEB_BLE_SH_STR, r, "btmon_exit");
    sstr(s->btmon_exit_detail, WEB_BLE_SH_STR, r, "btmon_exit_detail");
    s->btmon_open = web_jl_int(r, "btmon_open", 0) == 1;
    s->btmon_running = web_jl_int(r, "btmon_running", 0) == 1;
    s->btmon_stats_valid = web_jl_int(r, "btmon_stats_valid", 0) == 1;
    s->btmon_recv = web_jl_int(r, "btmon_recv", 0);
    s->btmon_drop = web_jl_int(r, "btmon_drop", 0);
    s->btmon_ifdrop = web_jl_int(r, "btmon_ifdrop", 0);
    s->btmon_last_frame_ts = web_jl_int(r, "btmon_last_frame_ts", 0);
    s->btmon_stale_secs = web_jl_int(r, "btmon_stale_secs", -1);
    s->ble_controllers = web_jl_int(r, "ble_controllers", 0);
    s->ble_devices = web_jl_int(r, "ble_devices", 0);
    s->ble_records = web_jl_int(r, "ble_records", 0);
    s->ble_adv_reports = web_jl_int(r, "ble_adv_reports", 0);
    s->ble_ext_adv_undecoded = web_jl_int(r, "ble_ext_adv_undecoded", 0);
    s->ble_ext_adv_reports = web_jl_int(r, "ble_ext_adv_reports", 0);
    s->ble_ext_adv_fragments = web_jl_int(r, "ble_ext_adv_fragments", 0);
    s->ble_ext_adv_partial = web_jl_int(r, "ble_ext_adv_partial", 0);
    s->ble_ext_trains_evicted = web_jl_int(r, "ble_ext_trains_evicted", 0);
    s->ble_records_ignored = web_jl_int(r, "ble_records_ignored", 0);
    s->ble_records_malformed = web_jl_int(r, "ble_records_malformed", 0);
    s->ble_host_commands = web_jl_int(r, "ble_host_commands", 0);
    s->ble_index_records = web_jl_int(r, "ble_index_records", 0);
    sstr(s->ble_scan_mode, WEB_BLE_SH_STR, r, "ble_scan_mode");
    sstr(s->ble_scan_filter, WEB_BLE_SH_STR, r, "ble_scan_filter");
    s->ble_scan_accept_list = (int)ibound(r, "ble_scan_accept_list", -1, 1, -1);
    s->ble_scan_enabled = (int)ibound(r, "ble_scan_enabled", -1, 1, -1);
    sstr(s->ble_own_tx, WEB_BLE_SH_STR, r, "ble_own_tx");
    sstr(s->ble_own_tx_kind, WEB_BLE_SH_STR, r, "ble_own_tx_kind");
    sstr(s->ble_own_tx_on, WEB_BLE_SH_LIST, r, "ble_own_tx_on");
    sstr(s->ble_own_tx_asserted, WEB_BLE_SH_LIST, r, "ble_own_tx_asserted");
    s->ble_own_tx_count = web_jl_int(r, "ble_own_tx_count", 0);
    s->ble_own_tx_secs = web_jl_int(r, "ble_own_tx_secs", -1);
    s->ble_own_tx_baseline = web_jl_int(r, "ble_own_tx_baseline", 0) == 1;
    sstr(s->btcap_iface, WEB_BLE_SH_STR, r, "btcap_iface");
    sstr(s->btcap_state, WEB_BLE_SH_STR, r, "btcap_state");
    sstr(s->btcap_err, WEB_BLE_SH_STR, r, "btcap_err");
    sstr(s->btcap_sampling, WEB_BLE_SH_STR, r, "btcap_sampling");
    s->btcap_dlt = web_jl_int(r, "btcap_dlt", -1);
    s->btcap_refused_dlt = web_jl_int(r, "btcap_refused_dlt", -1);
    s->btcap_stale_secs = web_jl_int(r, "btcap_stale_secs", -1);
    s->btcap_recv = web_jl_int(r, "btcap_recv", 0);
    s->btcap_drop = web_jl_int(r, "btcap_drop", 0);
    s->btcap_truncated = web_jl_int(r, "btcap_truncated", 0);
    s->btcap_adv = web_jl_int(r, "btcap_adv", 0);
    s->btcap_scan_req = web_jl_int(r, "btcap_scan_req", 0);
    s->btcap_connect_ind = web_jl_int(r, "btcap_connect_ind", 0);
    s->btcap_ext_adv_undecoded = web_jl_int(r, "btcap_ext_adv_undecoded", 0);
    s->btcap_data_pdus = web_jl_int(r, "btcap_data_pdus", 0);
    s->btcap_other_pdus = web_jl_int(r, "btcap_other_pdus", 0);
    s->btcap_bredr = web_jl_int(r, "btcap_bredr", 0);
    s->btcap_bredr_iac = web_jl_int(r, "btcap_bredr_iac", 0);
    s->btcap_bredr_laps = web_jl_int(r, "btcap_bredr_laps", 0);
    s->rot_present = web_jl_get(r, "ble_rot_hints") != NULL;
    sstr(s->ble_rot_hints, WEB_BLE_SH_STR, r, "ble_rot_hints");
    sstr(s->ble_rot_poisoned, WEB_BLE_SH_STR, r, "ble_rot_poisoned");
    sstr(s->ble_rot_seam_evictions, WEB_BLE_SH_STR, r, "ble_rot_seam_evictions");
    s->evict_ble_device = web_jl_int(r, "evict_ble_device", 0);
    s->evict_bredr_lap = web_jl_int(r, "evict_bredr_lap", 0);
    s->evict_ble_flood = web_jl_int(r, "evict_ble_flood", 0);
}

void web_ble_record(web_ble_t *b, const web_jrec_t *r, long long now_ms) {
    (void)now_ms;
    if (!b || !b->dev) return;
    const char *t = web_jl_str(r, "type");
    if (!t) return;
    long long ts = web_jl_int(r, "ts", 0);
    pthread_mutex_lock(&b->mu);
    b->st.records++;
    if (!strcmp(t, "ble_device")) dev_apply(b, r, ts);
    else if (!strcmp(t, "ble_alert")) al_apply(b, r, ts);
    else if (!strcmp(t, "alert.resolve")) resolve_apply(b, r, ts);
    else if (!strcmp(t, "sensor_health")) sh_apply(b, r, ts);
    pthread_mutex_unlock(&b->mu);
}

/* ── the store's side ───────────────────────────────────────────────── */

static void dev_to_row(const web_ble_dev_t *d, web_store_bdev_t *o) {
    memset(o, 0, sizeof(*o));
    addr_text(d->addr, o->addr);
    o->addr_type = d->addr_type;
    snprintf(o->iface, sizeof(o->iface), "%s", IFACE[d->iface]);
    o->adapter = d->adapter;
    o->sampled = d->sampled;
    o->pdu_mask = d->pdu_mask;
    memcpy(o->name, d->name, sizeof(o->name));
    o->name_np = d->name_np;
    o->name_complete = d->name_complete;
    o->uuid16 = d->uuid16;
    o->mfr_id = d->mfr_id;
    o->mfr_subtype = d->mfr_subtype;
    o->svc_data_uuid16 = d->svc_data_uuid16;
    o->appearance = d->appearance;
    o->hid = d->hid;
    o->tx_power = d->tx_power;
    o->flags = d->flags;
    o->rssi = d->has_rssi ? d->rssi : -128;
    o->rssi_best = d->has_rssi ? d->rssi_best : -128;
    o->adv_count = d->adv_count > (unsigned long long)(1LL << 62) ? (1LL << 62)
                                                                   : (long long)d->adv_count;
    memcpy(o->watch_category, d->watch_category, sizeof(o->watch_category));
    o->ext_adv = d->ext_adv;
    o->primary_phy = d->primary_phy;
    o->secondary_phy = d->secondary_phy;
    o->adv_sid = d->adv_sid;
    o->first_seen = d->first_seen;
    o->last_seen = d->last_seen;
    o->est_dist_dm = d->est_valid ? d->est_dist_dm : -1;
    o->est_band = d->est_valid ? d->est_band : 0;
    o->est_trend = d->est_valid ? d->est_trend : 0;
    o->est_ptx = d->est_valid ? d->est_ptx : WEB_BLE_PTX_ASSUMED;
    o->pres_bucket = d->pres_bucket;
    o->pres_lo = (long long)d->pres[0];
    o->pres_hi = (long long)d->pres[1];
}

int web_ble_seed(web_ble_t *b, const web_store_bdev_t *r) {
    uint8_t addr[6];
    if (!b || !b->dev || !r || addr_bytes(r->addr, addr) != 0) return 0;
    if (!(r->addr_type == 255 || (r->addr_type >= 0 && r->addr_type <= 3))) return 0;
    int ifi = word_of(IFACE, WEB_BLE_IF_COUNT, r->iface, NULL);
    pthread_mutex_lock(&b->mu);
    web_ble_dev_t *d = dev_find(b, addr, r->addr_type, ifi);
    if (!d) {
        d = dev_slot(b);
        d->used = 1;
        memcpy(d->addr, addr, 6);
        d->addr_type = r->addr_type;
        d->iface = ifi;
        b->st.rows++;
    }
    d->adapter = r->adapter;
    d->sampled = r->sampled != 0;
    d->channel = -1;
    d->last_pdu = WEB_BLE_PDU_ADV;
    d->pdu_mask = r->pdu_mask & 127;
    /* The name is already in its display form; held to the same bound. */
    web_utf8_copy(d->name, WEB_BLE_NAME_MAX, r->name);
    d->name_np = r->name_np != 0;
    d->name_complete = r->name_complete != 0;
    d->uuid16 = r->uuid16 >= -1 && r->uuid16 <= 65535 ? r->uuid16 : -1;
    d->mfr_id = r->mfr_id >= -1 && r->mfr_id <= 65535 ? r->mfr_id : -1;
    d->mfr_subtype = r->mfr_subtype >= -1 && r->mfr_subtype <= 255 ? r->mfr_subtype : -1;
    d->svc_data_uuid16 = r->svc_data_uuid16 >= -1 && r->svc_data_uuid16 <= 65535 ? r->svc_data_uuid16 : -1;
    d->appearance = r->appearance >= -1 && r->appearance <= 65535 ? r->appearance : -1;
    d->hid = r->hid & 3;
    d->tx_power = r->tx_power >= -128 && r->tx_power <= 127 ? r->tx_power : -128;
    d->flags = r->flags >= -1 && r->flags <= 255 ? r->flags : -1;
    d->has_rssi = r->rssi > -128 && r->rssi <= 20;
    d->rssi = d->has_rssi ? r->rssi : 0;
    d->rssi_best = d->has_rssi && r->rssi_best > -128 && r->rssi_best <= 20 ? r->rssi_best : d->rssi;
    d->adv_count = r->adv_count > 0 ? (unsigned long long)r->adv_count : 0;
    if (cat_ok(r->watch_category)) snprintf(d->watch_category, sizeof(d->watch_category), "%s", r->watch_category);
    else d->watch_category[0] = '\0';
    d->ext_adv = r->ext_adv != 0;
    d->primary_phy = r->primary_phy >= 0 && r->primary_phy <= 4 ? r->primary_phy : 0;
    d->secondary_phy = r->secondary_phy >= 0 && r->secondary_phy <= 4 ? r->secondary_phy : 0;
    d->adv_sid = r->adv_sid >= -1 && r->adv_sid <= 15 ? r->adv_sid : -1;
    d->first_seen = r->first_seen > 0 ? r->first_seen : 0;
    d->last_seen = r->last_seen > 0 ? r->last_seen : 0;
    d->est_valid = r->est_dist_dm >= 0 && r->est_band > 0 && r->est_band < WEB_BLE_BAND_COUNT;
    d->est_dist_dm = d->est_valid ? r->est_dist_dm : -1;
    d->est_band = d->est_valid ? r->est_band : 0;
    d->est_trend = d->est_valid && r->est_trend >= 0 && r->est_trend < WEB_BLE_TREND_COUNT ? r->est_trend : 0;
    d->est_ptx = r->est_ptx >= 0 && r->est_ptx < WEB_BLE_PTX_COUNT ? r->est_ptx : WEB_BLE_PTX_ASSUMED;
    /* The strip as it was stored; a bucket from the future (a clock
     * stepped back) or a mask wider than the day is not taken. */
    if (r->pres_bucket > 0 && r->pres_bucket <= (d->last_seen / WEB_BLE_PRES_S) + 1) {
        d->pres_bucket = r->pres_bucket;
        d->pres[0] = (uint64_t)r->pres_lo;
        d->pres[1] = (uint64_t)r->pres_hi & (((uint64_t)1 << (WEB_BLE_PRES_N - 64)) - 1);
    } else {
        d->pres_bucket = 0;
        d->pres[0] = d->pres[1] = 0;
    }
    d->npts = 0;
    d->pt_head = 0;
    d->dirty = 0;
    d->touched = ++b->touch;
    b->st.seeded++;
    pthread_mutex_unlock(&b->mu);
    return 1;
}

static void al_to_row(const web_ble_alert_t *a, web_store_balert_t *o) {
    memset(o, 0, sizeof(*o));
    /* A seeded row's key is "#" and the hash the file holds (the key
     * itself was never stored): that hash again, never a hash of the
     * stand-in, or a resolve on a seeded row would write a second row
     * beside the standing one and the restart after would list both. */
    if (a->key[0] == '#' && strlen(a->key) == 17) snprintf(o->key_hash, sizeof(o->key_hash), "%s", a->key + 1);
    else web_ble_key_hash(a->key, o->key_hash);
    o->kind = a->kind;
    snprintf(o->alert, sizeof(o->alert), "%s", ALERT[a->alert]);
    snprintf(o->iface, sizeof(o->iface), "%s", IFACE[a->iface]);
    o->sampled = a->sampled;
    o->first_ts = a->first_ts;
    o->last_ts = a->last_ts;
    o->resolved_ts = a->standing ? -1 : a->resolved_ts;
    switch (a->kind) {
    case WEB_BLE_FIND_FLOOD:
        /* n0 id, n1 subtype, n2 window_s, n3 distinct, n4 total, n5
         * fresh, n6 the rate in tenths (al_json() prints one decimal),
         * n7 distinct_capped | window << 1; detail the citation line. */
        o->n[0] = a->id;
        o->n[1] = a->subtype;
        o->n[2] = a->window_s;
        o->n[3] = a->distinct;
        o->n[4] = a->total;
        o->n[5] = a->fresh;
        o->n[6] = (long long)floor(a->rate * 10 + 0.5);
        o->n[7] = (a->distinct_capped ? 1 : 0) | (a->window ? 2 : 0);
        o->rssi = a->has_rssi ? a->median_rssi : 0;
        snprintf(o->label, sizeof(o->label), "%s/%s", FAMILY[a->family], PDU[a->adv_type]);
        snprintf(o->detail, sizeof(o->detail), "%s", a->spam_source);
        break;
    case WEB_BLE_FIND_HID_OUI: {
        /* n0 addr_type, n1 hid, n2 appearance, n3 the address as its
         * 48-bit number (the drawer matches the finding on it). */
        long long ad = 0;
        for (int k = 0; k < 6; k++) ad = ad << 8 | a->addr[k];
        o->n[0] = a->addr_type;
        o->n[1] = a->hid;
        o->n[2] = a->appearance;
        o->n[3] = ad;
        snprintf(o->label, sizeof(o->label), "%s", OUI_TABLE[a->oui_table]);
        break;
    }
    case WEB_BLE_FIND_HID_ROTATE:
        o->n[0] = a->addrs;
        o->n[1] = a->window_s;
        o->n[2] = a->appearance;
        break;
    case WEB_BLE_FIND_WATCH:
        o->n[0] = a->addrs;
        o->n[1] = a->window_s;
        snprintf(o->label, sizeof(o->label), "%s", a->category);
        break;
    default:
        break;
    }
}

int web_ble_seed_alert(web_ble_t *b, const web_store_balert_t *r) {
    if (!b || !b->al || !r || strlen(r->key_hash) != 16) return 0;
    if (r->kind < 0 || r->kind >= WEB_BLE_FIND_COUNT) return 0;
    pthread_mutex_lock(&b->mu);
    /* The key itself was never stored: the hash stands in, and a later
     * record or resolve on the live key finds the row by it
     * (al_find_live); failing that, the standing rule (WEB_BLE_STAND_S
     * after last_ts) is what closes it. */
    char key[WEB_BLE_KEY_MAX + 1];
    snprintf(key, sizeof(key), "#%s", r->key_hash);
    web_ble_alert_t *a = al_find(b, key);
    if (!a) {
        a = al_slot(b);
        a->used = 1;
        snprintf(a->key, sizeof(a->key), "%s", key);
        b->st.alert_rows++;
    }
    a->kind = r->kind;
    a->alert = word_of(ALERT, WEB_BLE_ALERT_COUNT, r->alert, NULL);
    a->ty = -1;
    a->iface = word_of(IFACE, WEB_BLE_IF_COUNT, r->iface, NULL);
    a->sampled = r->sampled != 0;
    a->first_ts = r->first_ts;
    a->last_ts = r->last_ts;
    a->standing = r->resolved_ts < 0;
    a->resolved_ts = r->resolved_ts;
    switch (a->kind) {
    case WEB_BLE_FIND_FLOOD:
        a->id = (int)(r->n[0] & 0xffff);
        a->subtype = r->n[1] >= -1 && r->n[1] <= 255 ? (int)r->n[1] : -1;
        a->window_s = (int)(r->n[2] < 0 ? 0 : r->n[2] > 86400 ? 86400 : r->n[2]);
        a->distinct = r->n[3] < 0 ? 0 : r->n[3];
        a->total = r->n[4] < 0 ? 0 : r->n[4];
        a->fresh = r->n[5] < 0 ? 0 : r->n[5];
        a->rate = r->n[6] > 0 ? (double)r->n[6] / 10.0 : 0;
        a->distinct_capped = (r->n[7] & 1) != 0;
        a->window = (r->n[7] & 2) != 0;
        a->has_rssi = r->rssi != 0;
        a->median_rssi = r->rssi;
        /* sloth's own line, kept in its display form; held to it again. */
        web_utf8_copy(a->spam_source, WEB_BLE_DETAIL_MAX, r->detail);
        {
            const char *sl = strchr(r->label, '/');
            char fam[16];
            snprintf(fam, sizeof(fam), "%.*s", sl ? (int)(sl - r->label) : 0, r->label);
            a->family = word_of(FAMILY, 3, fam, NULL);
            a->adv_type = find_word(PDU, WEB_BLE_PDU_COUNT, sl ? sl + 1 : "");
            if (a->adv_type < 0) a->adv_type = WEB_BLE_PDU_ADV;
        }
        break;
    case WEB_BLE_FIND_HID_OUI:
        a->addr_type = (int)(r->n[0] & 0xff);
        a->hid = (int)(r->n[1] & 3);
        a->appearance = r->n[2] >= -1 && r->n[2] <= 65535 ? (int)r->n[2] : -1;
        a->oui_table = word_of(OUI_TABLE, 3, r->label, NULL);
        for (int k = 0; k < 6; k++) a->addr[k] = (uint8_t)((r->n[3] >> (8 * (5 - k))) & 0xff);
        break;
    case WEB_BLE_FIND_HID_ROTATE:
        a->addrs = r->n[0] < 0 ? 0 : r->n[0];
        a->window_s = (int)(r->n[1] < 0 ? 0 : r->n[1] > 86400 ? 86400 : r->n[1]);
        a->appearance = r->n[2] >= -1 && r->n[2] <= 65535 ? (int)r->n[2] : -1;
        break;
    case WEB_BLE_FIND_WATCH:
        a->addrs = r->n[0] < 0 ? 0 : r->n[0];
        a->window_s = (int)(r->n[1] < 0 ? 0 : r->n[1] > 86400 ? 86400 : r->n[1]);
        if (cat_ok(r->label))
            snprintf(a->category, sizeof(a->category), "%.*s", WEB_BLE_CAT_MAX, r->label);
        break;
    default:
        break;
    }
    a->dirty = 0;
    a->seq = ++b->seq;
    b->st.seeded_alerts++;
    pthread_mutex_unlock(&b->mu);
    return 1;
}

size_t web_ble_take(web_ble_t *b, web_store_bdev_t *out, size_t max) {
    if (!b || !b->dev || !b->store_on) return 0;
    size_t n = 0;
    pthread_mutex_lock(&b->mu);
    for (int i = 0; i < WEB_BLE_DEVICES && n < max; i++) {
        web_ble_dev_t *d = &b->dev[i];
        if (!d->used || !d->dirty) continue;
        dev_to_row(d, &out[n++]);
        d->dirty = 0;
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

size_t web_ble_take_alerts(web_ble_t *b, web_store_balert_t *out, size_t max) {
    if (!b || !b->al || !b->store_on) return 0;
    size_t n = 0;
    pthread_mutex_lock(&b->mu);
    for (int i = 0; i < WEB_BLE_ALERTS && n < max; i++) {
        web_ble_alert_t *a = &b->al[i];
        if (!a->used || !a->dirty) continue;
        al_to_row(a, &out[n++]);
        a->dirty = 0;
    }
    pthread_mutex_unlock(&b->mu);
    return n;
}

void web_ble_redirty(web_ble_t *b, const web_store_bdev_t *rows, size_t n,
                     const web_store_balert_t *alerts, size_t na) {
    if (!b || !b->dev || !b->store_on) return;
    pthread_mutex_lock(&b->mu);
    for (size_t i = 0; i < n; i++) {
        uint8_t addr[6];
        if (addr_bytes(rows[i].addr, addr) != 0) continue;
        web_ble_dev_t *d = dev_find(b, addr, rows[i].addr_type,
                                    word_of(IFACE, WEB_BLE_IF_COUNT, rows[i].iface, NULL));
        /* Gone since the take (evicted): the eviction already counted
         * it, and there is nothing left to write. */
        if (d && !d->dirty) { d->dirty = 1; b->st.redirtied++; }
    }
    for (size_t i = 0; i < na; i++)
        for (int k = 0; k < WEB_BLE_ALERTS; k++) {
            web_ble_alert_t *a = &b->al[k];
            if (!a->used || a->dirty) continue;
            web_store_balert_t o;
            al_to_row(a, &o);
            if (!strcmp(o.key_hash, alerts[i].key_hash)) { a->dirty = 1; b->st.redirtied++; break; }
        }
    pthread_mutex_unlock(&b->mu);
}

static int standing_now(const web_ble_alert_t *a, long long now_s) {
    return a->standing && (now_s <= 0 || now_s - a->last_ts <= WEB_BLE_STAND_S);
}

static void stats_locked(web_ble_t *b, web_ble_stats_t *out, long long now_s) {
    *out = b->st;
    out->hid = out->watch = out->standing = 0;
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        if (!b->dev[i].used) continue;
        if (b->dev[i].hid) out->hid++;
        if (b->dev[i].watch_category[0]) out->watch++;
    }
    for (int i = 0; i < WEB_BLE_ALERTS; i++)
        if (b->al[i].used && standing_now(&b->al[i], now_s)) out->standing++;
}

void web_ble_stats(web_ble_t *b, web_ble_stats_t *out) {
    memset(out, 0, sizeof(*out));
    if (!b || !b->dev) return;
    pthread_mutex_lock(&b->mu);
    stats_locked(b, out, 0);
    pthread_mutex_unlock(&b->mu);
}

void web_ble_restored(web_ble_t *b, char *out, size_t n) {
    web_ble_stats_t st;
    web_ble_stats(b, &st);
    snprintf(out, n, "%lu advertiser%s and %lu finding%s", st.seeded,
             st.seeded == 1 ? "" : "s", st.seeded_alerts, st.seeded_alerts == 1 ? "" : "s");
}

void web_ble_sensor(web_ble_t *b, web_ble_sh_t *out) {
    memset(out, 0, sizeof(*out));
    if (!b || !b->dev) return;
    pthread_mutex_lock(&b->mu);
    *out = b->sh;
    pthread_mutex_unlock(&b->mu);
}

/* ── JSON ───────────────────────────────────────────────────────────── */

static void jw_opt(web_jw_t *w, const char *k, long long v, long long none) {
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    if (v == none) web_jw_raw(w, "null"); else web_jw_int(w, v);
}

static void jw_name_of(web_jw_t *w, const char *k, const char *name) {
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    if (name) web_jw_str(w, name); else web_jw_raw(w, "null");
}

/* rf_distance.c metres_str(): "<1m", "Nm" rounded, ">1km". */
static void metres_str(int dm, char *out, size_t n) {
    double m = dm / 10.0;
    if (m < 1.0)        snprintf(out, n, "<1m");
    else if (m < 999.5) snprintf(out, n, "%dm", (int)(m + 0.5));
    else                snprintf(out, n, ">1km");
}

/* rf_dist_describe()'s metres: one decimal below 10 m, whole above. */
static void m_str(int dm, char *out, size_t n) {
    double m = dm / 10.0;
    if (m < 10.0) snprintf(out, n, "%.1f", m);
    else          snprintf(out, n, "%d", (int)(m + 0.5));
}

/* The row's advertising rate over its points: adv/s between the first
 * and the last, or -1 with fewer than two. */
static double dev_rate(const web_ble_dev_t *d) {
    if (d->npts < 2) return -1;
    const web_ble_pt_t *a = &d->pts[d->pt_head];
    const web_ble_pt_t *z = &d->pts[(d->pt_head + d->npts - 1) % WEB_BLE_PTS];
    if (z->ts <= a->ts || z->count < a->count) return -1;
    return (double)(z->count - a->count) / (double)(z->ts - a->ts);
}

static void dev_json(web_jw_t *w, const web_ble_dev_t *d, const web_btsig_tab_t *sig, int full) {
    char a[18], ch[2] = { web_ble_type_ch(d->addr_type), 0 };
    addr_text(d->addr, a);
    web_jw_raw(w, "{\"addr\":"); web_jw_str(w, a);
    web_jw_raw(w, ",\"addr_type\":"); web_jw_int(w, d->addr_type);
    web_jw_raw(w, ",\"type\":"); web_jw_str(w, ch);
    web_jw_raw(w, ",\"addr_kind\":"); web_jw_str(w, web_ble_addr_kind(d->addr, d->addr_type));
    web_jw_raw(w, ",\"sensor\":\"ble\",\"iface\":"); web_jw_str(w, IFACE[d->iface]);
    web_jw_raw(w, ",\"adapter\":"); web_jw_int(w, d->adapter);
    web_jw_raw(w, ",\"sampled\":"); web_jw_int(w, d->sampled);
    jw_opt(w, "channel", d->channel, -1);
    web_jw_raw(w, ",\"last_pdu\":"); web_jw_str(w, PDU[d->last_pdu]);
    web_jw_raw(w, ",\"pdu_mask\":"); web_jw_int(w, d->pdu_mask);
    web_jw_raw(w, ",\"pdus\":[");
    for (int i = 0, k = 0; i < 7; i++)
        if (d->pdu_mask & (1 << i)) { if (k++) web_jw_raw(w, ","); web_jw_str(w, PDU[i]); }
    web_jw_raw(w, "],\"name\":");
    if (d->name[0]) web_jw_str(w, d->name); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"name_np\":"); web_jw_raw(w, d->name_np ? "true" : "false");
    web_jw_raw(w, ",\"name_complete\":"); web_jw_int(w, d->name_complete);
    jw_opt(w, "uuid16", d->uuid16, -1);
    jw_name_of(w, "uuid16_name", d->uuid16 >= 0 ? web_btsig_service(sig, d->uuid16) : NULL);
    jw_opt(w, "mfr_id", d->mfr_id, -1);
    jw_name_of(w, "mfr_name", d->mfr_id >= 0 ? web_btsig_company(sig, d->mfr_id) : NULL);
    jw_opt(w, "mfr_subtype", d->mfr_subtype, -1);
    jw_opt(w, "svc_data_uuid16", d->svc_data_uuid16, -1);
    jw_name_of(w, "svc_data_name",
               d->svc_data_uuid16 >= 0 ? web_btsig_service(sig, d->svc_data_uuid16) : NULL);
    jw_opt(w, "appearance", d->appearance, -1);
    jw_name_of(w, "appearance_name",
               d->appearance >= 0 ? web_btsig_appearance(sig, d->appearance) : NULL);
    web_jw_raw(w, ",\"hid\":"); web_jw_int(w, d->hid);
    jw_opt(w, "tx_power", d->tx_power, -128);
    jw_opt(w, "flags", d->flags, -1);
    web_jw_raw(w, ",\"rssi\":");
    if (d->has_rssi) web_jw_int(w, d->rssi); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"rssi_best\":");
    if (d->has_rssi) web_jw_int(w, d->rssi_best); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"adv_count\":"); web_jw_int(w, (long long)d->adv_count);
    double rate = dev_rate(d);
    web_jw_raw(w, ",\"adv_rate\":");
    if (rate >= 0) { char rb[32]; snprintf(rb, sizeof(rb), "%.3f", rate); web_jw_raw(w, rb); }
    else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"watch_category\":");
    if (d->watch_category[0]) web_jw_str(w, d->watch_category); else web_jw_raw(w, "null");
    web_jw_raw(w, ",\"ext_adv\":"); web_jw_int(w, d->ext_adv);
    web_jw_raw(w, ",\"primary_phy\":"); web_jw_int(w, d->primary_phy);
    web_jw_raw(w, ",\"secondary_phy\":"); web_jw_int(w, d->secondary_phy);
    jw_opt(w, "adv_sid", d->adv_sid, -1);
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, d->first_seen);
    web_jw_raw(w, ",\"last_seen\":"); web_jw_int(w, d->last_seen);
    web_jw_raw(w, ",\"records\":"); web_jw_int(w, (long long)d->records);
    web_jw_raw(w, ",\"est\":");
    if (d->est_valid) {
        char ms[8], mm[12], cell[48], desc[96], mstr[16];
        snprintf(mstr, sizeof(mstr), "%d.%d", d->est_dist_dm / 10, d->est_dist_dm % 10);
        metres_str(d->est_dist_dm, ms, sizeof(ms));
        m_str(d->est_dist_dm, mm, sizeof(mm));
        int known = d->est_trend != WEB_BLE_TREND_UNKNOWN;
        /* rf_dist_cell()'s full form, unpadded: "~5m room →". */
        snprintf(cell, sizeof(cell), "~%s %s%s%s", ms, BAND_SHORT[d->est_band],
                 known ? " " : "", known ? TREND_GLYPH[d->est_trend] : "");
        /* rf_dist_describe() less what the stream does not carry (the
         * interval and the P_tx value). */
        snprintf(desc, sizeof(desc), "~%sm %s %s, Ptx %s", mm, BAND_SHORT[d->est_band],
                 TREND[d->est_trend], PTX_SHORT[d->est_ptx]);
        web_jw_raw(w, "{\"m\":"); web_jw_raw(w, mstr);
        web_jw_raw(w, ",\"band\":"); web_jw_str(w, BAND[d->est_band]);
        web_jw_raw(w, ",\"band_short\":"); web_jw_str(w, BAND_SHORT[d->est_band]);
        web_jw_raw(w, ",\"trend\":"); web_jw_str(w, TREND[d->est_trend]);
        web_jw_raw(w, ",\"glyph\":"); web_jw_str(w, TREND_GLYPH[d->est_trend]);
        web_jw_raw(w, ",\"ptx\":"); web_jw_str(w, PTX[d->est_ptx]);
        web_jw_raw(w, ",\"ptx_short\":"); web_jw_str(w, PTX_SHORT[d->est_ptx]);
        web_jw_raw(w, ",\"cell\":"); web_jw_str(w, cell);
        web_jw_raw(w, ",\"describe\":"); web_jw_str(w, desc);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    if (full) {
        /* The strip as 24 hex digits, most significant first: digit k's
         * low bit is bucket 4 * (23 - k) before the newest. */
        char hx[WEB_BLE_PRES_N / 4 + 1];
        for (int k = 0; k < WEB_BLE_PRES_N / 4; k++) {
            int lo = 4 * (WEB_BLE_PRES_N / 4 - 1 - k);
            uint64_t word = lo < 64 ? d->pres[0] : d->pres[1];
            hx[k] = "0123456789abcdef"[(word >> (lo % 64)) & 15];
        }
        hx[WEB_BLE_PRES_N / 4] = '\0';
        web_jw_raw(w, ",\"presence\":{\"bucket_s\":"); web_jw_int(w, WEB_BLE_PRES_S);
        web_jw_raw(w, ",\"n\":"); web_jw_int(w, WEB_BLE_PRES_N);
        web_jw_raw(w, ",\"newest\":"); web_jw_int(w, d->pres_bucket * WEB_BLE_PRES_S);
        web_jw_raw(w, ",\"bits\":"); web_jw_str(w, hx);
        web_jw_raw(w, "}");
        web_jw_raw(w, ",\"points\":[");
        for (int i = 0; i < d->npts; i++) {
            const web_ble_pt_t *p = &d->pts[(d->pt_head + i) % WEB_BLE_PTS];
            web_jw_raw(w, i ? ",[" : "[");
            web_jw_int(w, p->ts);
            web_jw_raw(w, ",");
            web_jw_int(w, (long long)p->count);
            web_jw_raw(w, "]");
        }
        web_jw_raw(w, "]");
    }
    web_jw_raw(w, "}");
}

static void al_json(web_jw_t *w, const web_ble_alert_t *a, long long now_s) {
    web_jw_raw(w, "{\"kind\":"); web_jw_str(w, KIND[a->kind]);
    web_jw_raw(w, ",\"alert\":"); web_jw_str(w, ALERT[a->alert]);
    web_jw_raw(w, ",\"iface\":"); web_jw_str(w, IFACE[a->iface]);
    web_jw_raw(w, ",\"sampled\":"); web_jw_int(w, a->sampled);
    web_jw_raw(w, ",\"standing\":"); web_jw_raw(w, standing_now(a, now_s) ? "true" : "false");
    web_jw_raw(w, ",\"first_ts\":"); web_jw_int(w, a->first_ts);
    web_jw_raw(w, ",\"last_ts\":"); web_jw_int(w, a->last_ts);
    web_jw_raw(w, ",\"resolved_ts\":");
    if (a->standing) web_jw_raw(w, "null"); else web_jw_int(w, a->resolved_ts);
    switch (a->kind) {
    case WEB_BLE_FIND_FLOOD: {
        char rb[32];
        snprintf(rb, sizeof(rb), "%.1f", a->rate);
        web_jw_raw(w, ",\"adv_type\":"); web_jw_str(w, PDU[a->adv_type]);
        web_jw_raw(w, ",\"family\":"); web_jw_str(w, FAMILY[a->family]);
        web_jw_raw(w, ",\"id\":"); web_jw_int(w, a->id);
        jw_opt(w, "subtype", a->subtype, -1);
        web_jw_raw(w, ",\"window\":"); web_jw_str(w, a->window ? "previous" : "current");
        web_jw_raw(w, ",\"window_s\":"); web_jw_int(w, a->window_s);
        web_jw_raw(w, ",\"distinct_addrs\":"); web_jw_int(w, a->distinct);
        web_jw_raw(w, ",\"distinct_capped\":"); web_jw_int(w, a->distinct_capped);
        web_jw_raw(w, ",\"fresh_addrs\":"); web_jw_int(w, a->fresh);
        web_jw_raw(w, ",\"total_adv\":"); web_jw_int(w, a->total);
        web_jw_raw(w, ",\"rate\":"); web_jw_raw(w, rb);
        web_jw_raw(w, ",\"median_rssi\":");
        if (a->has_rssi) web_jw_int(w, a->median_rssi); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"spam_source\":"); web_jw_str(w, a->spam_source);
        break;
    }
    case WEB_BLE_FIND_HID_OUI: {
        char ad[18];
        addr_text(a->addr, ad);
        web_jw_raw(w, ",\"addr\":"); web_jw_str(w, ad);
        web_jw_raw(w, ",\"addr_type\":"); web_jw_int(w, a->addr_type);
        web_jw_raw(w, ",\"hid\":"); web_jw_int(w, a->hid);
        jw_opt(w, "appearance", a->appearance, -1);
        web_jw_raw(w, ",\"oui_table\":"); web_jw_str(w, OUI_TABLE[a->oui_table]);
        break;
    }
    case WEB_BLE_FIND_HID_ROTATE:
        web_jw_raw(w, ",\"addrs\":"); web_jw_int(w, a->addrs);
        web_jw_raw(w, ",\"window_s\":"); web_jw_int(w, a->window_s);
        jw_opt(w, "appearance", a->appearance, -1);
        break;
    case WEB_BLE_FIND_WATCH:
        web_jw_raw(w, ",\"category\":");
        if (a->category[0]) web_jw_str(w, a->category); else web_jw_raw(w, "null");
        web_jw_raw(w, ",\"addrs\":"); web_jw_int(w, a->addrs);
        web_jw_raw(w, ",\"window_s\":"); web_jw_int(w, a->window_s);
        break;
    default:
        break;
    }
    web_jw_raw(w, "}");
}

/* ── the routes ─────────────────────────────────────────────────────── */

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *status_out) {
    *status_out = status;
    *len = web_series_error_json(reason, body, cap);
    return *len ? 0 : -1;
}

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    if (!s || !*s || strlen(s) > 11) return -1;
    long long v = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        v = v * 10 + (*s - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

/* One word a column of the page's table (owner ruling: every column
 * sorts). kind is the address in words, hws the three flags as the
 * TUI's cell orders them, mfr the company's SIG name. */
enum { BS_LAST = 0, BS_FIRST, BS_RSSI, BS_DIST, BS_ADV, BS_ADDR, BS_TYPE, BS_IFACE, BS_NAME,
       BS_KIND, BS_BEST, BS_RATE, BS_HWS, BS_PDUS, BS_WATCH, BS_MFR, BS_COUNT };
static const char *const SORT[BS_COUNT] = {
    "last", "first", "rssi", "dist", "adv", "addr", "type", "iface", "name",
    "kind", "best", "rate", "hws", "pdus", "watch", "mfr",
};

static double dev_rate(const web_ble_dev_t *d);
static int hws_of(const web_ble_dev_t *d) {
    return (d->hid ? 4 : 0) | (d->watch_category[0] ? 2 : 0) | (d->sampled ? 1 : 0);
}

static int g_sort, g_dir;
static long long g_now;

static int lower_ascii(int c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; }

static int ci_cmp(const char *a, const char *b) {
    for (;; a++, b++) {
        int x = lower_ascii((unsigned char)*a), y = lower_ascii((unsigned char)*b);
        if (x != y) return x < y ? -1 : 1;
        if (!x) return 0;
    }
}

/* The sort's key, an empty value last either way, then the address. */
static int by_sort(const void *pa, const void *pb) {
    const web_ble_dev_t *a = *(const web_ble_dev_t *const *)pa;
    const web_ble_dev_t *b = *(const web_ble_dev_t *const *)pb;
    int dir = g_dir == WEB_SORT_ASC ? 1 : g_dir == WEB_SORT_DESC ? -1 : 0;
    int r = 0, ea = 0, eb = 0;
    switch (g_sort) {
    case BS_LAST:  r = a->last_seen < b->last_seen ? -1 : a->last_seen > b->last_seen; if (!dir) dir = -1; break;
    case BS_FIRST: r = a->first_seen < b->first_seen ? -1 : a->first_seen > b->first_seen; if (!dir) dir = -1; break;
    case BS_RSSI:
        ea = !a->has_rssi; eb = !b->has_rssi;
        r = a->rssi < b->rssi ? -1 : a->rssi > b->rssi;
        if (!dir) dir = -1;
        break;
    case BS_DIST:
        ea = !a->est_valid; eb = !b->est_valid;
        r = a->est_dist_dm < b->est_dist_dm ? -1 : a->est_dist_dm > b->est_dist_dm;
        if (!dir) dir = 1;
        break;
    case BS_ADV:   r = a->adv_count < b->adv_count ? -1 : a->adv_count > b->adv_count; if (!dir) dir = -1; break;
    case BS_ADDR:  r = memcmp(a->addr, b->addr, 6); if (!dir) dir = 1; break;
    case BS_TYPE:  r = a->addr_type < b->addr_type ? -1 : a->addr_type > b->addr_type; if (!dir) dir = 1; break;
    case BS_IFACE: r = a->iface < b->iface ? -1 : a->iface > b->iface; if (!dir) dir = 1; break;
    case BS_NAME:
        ea = !a->name[0]; eb = !b->name[0];
        r = ci_cmp(a->name, b->name);
        if (!dir) dir = 1;
        break;
    case BS_KIND:
        r = strcmp(web_ble_addr_kind(a->addr, a->addr_type), web_ble_addr_kind(b->addr, b->addr_type));
        if (!dir) dir = 1;
        break;
    case BS_BEST:
        ea = !a->has_rssi; eb = !b->has_rssi;
        r = a->rssi_best < b->rssi_best ? -1 : a->rssi_best > b->rssi_best;
        if (!dir) dir = -1;
        break;
    case BS_RATE: {
        double x = dev_rate(a), y = dev_rate(b);
        ea = x < 0; eb = y < 0;
        r = x < y ? -1 : x > y;
        if (!dir) dir = -1;
        break;
    }
    case BS_HWS:   r = hws_of(a) - hws_of(b); if (!dir) dir = -1; break;
    case BS_PDUS:  r = a->pdu_mask - b->pdu_mask; if (!dir) dir = 1; break;
    case BS_WATCH:
        ea = !a->watch_category[0]; eb = !b->watch_category[0];
        r = strcmp(a->watch_category, b->watch_category);
        if (!dir) dir = 1;
        break;
    case BS_MFR: {
        const web_btsig_tab_t *sig = web_btsig_builtin();
        const char *x = a->mfr_id >= 0 ? web_btsig_company(sig, a->mfr_id) : NULL;
        const char *y = b->mfr_id >= 0 ? web_btsig_company(sig, b->mfr_id) : NULL;
        /* Three tiers, either direction: the companies the SIG table
         * names (by name), then the ids it does not name (by number),
         * then no company at all. Only the order inside a tier turns. */
        ea = a->mfr_id < 0 ? 2 : x ? 0 : 1;
        eb = b->mfr_id < 0 ? 2 : y ? 0 : 1;
        if (x && y) r = ci_cmp(x, y);
        else r = a->mfr_id < b->mfr_id ? -1 : a->mfr_id > b->mfr_id;
        if (!dir) dir = 1;
        break;
    }
    default: break;
    }
    if (ea != eb) return ea < eb ? -1 : 1;
    if (r) return r * dir;
    r = memcmp(a->addr, b->addr, 6);
    if (r) return r;
    if (a->addr_type != b->addr_type) return a->addr_type < b->addr_type ? -1 : 1;
    return a->iface - b->iface;
}

/* An ASCII case-insensitive substring. */
static int ci_has(const char *hay, const char *needle) {
    size_t n = strlen(needle);
    for (const char *p = hay; *p; p++) {
        size_t i = 0;
        while (i < n && p[i] && lower_ascii((unsigned char)p[i]) == lower_ascii((unsigned char)needle[i])) i++;
        if (i == n) return 1;
    }
    return 0;
}

/* q (printable ASCII, the parser's) as an address prefix, a name
 * substring or a category substring, ASCII case folded. */
static int dev_matches(const web_ble_dev_t *d, const char *q) {
    if (!q || !q[0]) return 1;
    char a[18], lq[WEB_PARAM_MAX + 1];
    size_t ql = strlen(q);
    for (size_t k = 0; k <= ql; k++) lq[k] = (char)lower_ascii((unsigned char)q[k]);
    addr_text(d->addr, a);
    if (!strncmp(a, lq, ql)) return 1;
    if (d->name[0] && ci_has(d->name, lq)) return 1;
    if (d->watch_category[0] && ci_has(d->watch_category, lq)) return 1;
    return 0;
}

int web_ble_devices_route(web_ble_t *b, const char *query, long long now_s,
                          int check_only, char *body, size_t cap, size_t *len,
                          int *status) {
    web_param_t ps[5] = { { "sort", "", 0 }, { "dir", "", 0 }, { "limit", "", 0 },
                          { "offset", "", 0 }, { "q", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 5, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    int sort = BS_LAST, dir = WEB_SORT_DEFAULT;
    if (ps[0].seen) {
        sort = -1;
        for (int i = 0; i < BS_COUNT; i++) if (!strcmp(ps[0].val, SORT[i])) sort = i;
        if (sort < 0) return answer_error(400, "bad_sort", body, cap, len, status);
    }
    if (ps[1].seen && (dir = web_sort_dir_find(ps[1].val)) < 0)
        return answer_error(400, "bad_dir", body, cap, len, status);
    long long limit = WEB_BLE_LIMIT, offset = 0;
    if (ps[2].seen && decimal(ps[2].val, 1, WEB_BLE_LIMIT_MAX, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, 0, WEB_BLE_DEVICES, &offset) != 0)
        return answer_error(400, "bad_offset", body, cap, len, status);
    /* The search is matched against an address, a display-form name and
     * a slug: printable ASCII, which the parser already made it. */
    const char *q = ps[4].seen ? ps[4].val : "";
    if (check_only) { *len = 0; *status = 200; return 0; }
    if (!b || !b->dev) return answer_error(503, "no_ble", body, cap, len, status);

    const web_btsig_tab_t *sig = web_btsig_builtin();
    const web_ble_dev_t **idx = calloc(WEB_BLE_DEVICES, sizeof(*idx));
    if (!idx) return -1;
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&b->mu);
    int n = 0, hid = 0, watch = 0;
    for (int i = 0; i < WEB_BLE_DEVICES; i++) {
        const web_ble_dev_t *d = &b->dev[i];
        if (!d->used) continue;
        if (d->hid) hid++;
        if (d->watch_category[0]) watch++;
        if (dev_matches(d, q)) idx[n++] = d;
    }
    g_sort = sort;
    g_dir = dir;
    qsort(idx, (size_t)n, sizeof(idx[0]), by_sort);
    web_ble_stats_t st;
    stats_locked(b, &st, now_s);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"sort\":"); web_jw_str(&w, SORT[sort]);
    web_jw_raw(&w, ",\"limit\":"); web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":"); web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, st.rows);
    web_jw_raw(&w, ",\"matched\":"); web_jw_int(&w, n);
    web_jw_raw(&w, ",\"hid\":"); web_jw_int(&w, hid);
    web_jw_raw(&w, ",\"watch\":"); web_jw_int(&w, watch);
    web_jw_raw(&w, ",\"standing\":"); web_jw_int(&w, st.standing);
    /* Not the TUI's "flood keys" (s->ble_flood_count, the flood
     * detector's tracked windows, one a manufacturer heard): the stream
     * does not carry that. This is the adv_flood findings standing now,
     * and the page labels it so. */
    web_jw_raw(&w, ",\"standing_floods\":");
    int floods = 0;
    for (int i = 0; i < WEB_BLE_ALERTS; i++)
        if (b->al[i].used && b->al[i].kind == WEB_BLE_FIND_FLOOD && standing_now(&b->al[i], now_s))
            floods++;
    web_jw_int(&w, floods);
    web_jw_raw(&w, ",\"evictions\":"); web_jw_int(&w, (long long)st.evictions);
    web_jw_raw(&w, ",\"sig\":"); web_jw_str(&w, sig ? sig->source : "none");
    web_jw_raw(&w, ",\"sensor\":{\"btmon_iface\":"); web_jw_str(&w, b->sh.btmon_iface);
    /* sloth's own live count (s->ble_device_count, the TUI's header
     * number and the rotation block's address count), null before a
     * sensor_health said it; "total" is slothweb's rows, which outlive
     * sloth's evictions and restarts. */
    web_jw_raw(&w, ",\"ble_devices\":");
    if (b->sh.seen) web_jw_int(&w, b->sh.ble_devices); else web_jw_raw(&w, "null");
    web_jw_raw(&w, ",\"btcap_iface\":"); web_jw_str(&w, b->sh.btcap_iface);
    web_jw_raw(&w, ",\"scan_mode\":"); web_jw_str(&w, b->sh.ble_scan_mode);
    web_jw_raw(&w, ",\"scan_filter\":"); web_jw_str(&w, b->sh.ble_scan_filter);
    web_jw_raw(&w, ",\"rot\":");
    if (b->sh.rot_present) {
        web_jw_raw(&w, "{\"hints\":"); web_jw_str(&w, b->sh.ble_rot_hints);
        web_jw_raw(&w, ",\"poisoned\":"); web_jw_str(&w, b->sh.ble_rot_poisoned);
        web_jw_raw(&w, ",\"seam_evictions\":"); web_jw_str(&w, b->sh.ble_rot_seam_evictions);
        web_jw_raw(&w, "}");
    } else {
        web_jw_raw(&w, "null");
    }
    web_jw_raw(&w, "},\"rows\":[");
    int shown = 0;
    for (long long i = offset; i < n && shown < limit; i++) {
        /* A row is at most about 1.5 KB with every name at its cut. */
        if (w.len + 2048 > cap) break;
        if (shown) web_jw_raw(&w, ",");
        dev_json(&w, idx[i], sig, 0);
        shown++;
    }
    int more = offset + shown < n;
    pthread_mutex_unlock(&b->mu);
    free(idx);
    web_jw_raw(&w, "],\"count\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":"); web_jw_raw(&w, more ? "true" : "false");
    web_jw_raw(&w, ",\"next_offset\":");
    if (more) web_jw_int(&w, offset + shown); else web_jw_raw(&w, "null");
    if (dir != WEB_SORT_DEFAULT) {
        web_jw_raw(&w, ",\"dir\":");
        web_jw_str(&w, dir == WEB_SORT_ASC ? "asc" : "desc");
    }
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

static int by_alert(const void *pa, const void *pb) {
    const web_ble_alert_t *a = *(const web_ble_alert_t *const *)pa;
    const web_ble_alert_t *b = *(const web_ble_alert_t *const *)pb;
    /* Standing first, then the latest change first. */
    int sa = standing_now(a, g_now), sb = standing_now(b, g_now);
    if (sa != sb) return sa ? -1 : 1;
    if (a->last_ts != b->last_ts) return a->last_ts > b->last_ts ? -1 : 1;
    return a->seq > b->seq ? -1 : a->seq < b->seq;
}

int web_ble_alerts_route(web_ble_t *b, const char *query, long long now_s,
                         int check_only, char *body, size_t cap, size_t *len,
                         int *status) {
    web_param_t ps[1] = { { "limit", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 1, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long limit = WEB_BLE_ALERTS;
    if (ps[0].seen && decimal(ps[0].val, 1, WEB_BLE_ALERTS, &limit) != 0)
        return answer_error(400, "bad_limit", body, cap, len, status);
    if (check_only) { *len = 0; *status = 200; return 0; }
    if (!b || !b->al) return answer_error(503, "no_ble", body, cap, len, status);
    const web_ble_alert_t *idx[WEB_BLE_ALERTS];
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&b->mu);
    int n = 0, standing = 0;
    for (int i = 0; i < WEB_BLE_ALERTS; i++) {
        const web_ble_alert_t *a = &b->al[i];
        if (!a->used) continue;
        int st = standing_now(a, now_s);
        if (!st && now_s > 0 && now_s - (a->resolved_ts > 0 ? a->resolved_ts : a->last_ts) > WEB_BLE_RESOLVED_S)
            continue;
        standing += st;
        idx[n++] = a;
    }
    /* The comparator's clock (one HTTP thread, under the lock). */
    g_now = now_s;
    qsort(idx, (size_t)n, sizeof(idx[0]), by_alert);
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"standing\":"); web_jw_int(&w, standing);
    web_jw_raw(&w, ",\"rows\":[");
    int shown = 0;
    for (int i = 0; i < n && shown < limit; i++) {
        if (w.len + 1024 > cap) break;
        if (shown) web_jw_raw(&w, ",");
        al_json(&w, idx[i], now_s);
        shown++;
    }
    pthread_mutex_unlock(&b->mu);
    web_jw_raw(&w, "],\"count\":"); web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"more\":"); web_jw_raw(&w, shown < n ? "true" : "false");
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

int web_ble_device_route(web_ble_t *b, const char *path_addr, const char *query,
                         long long now_s, int check_only, char *body, size_t cap,
                         size_t *len, int *status) {
    uint8_t addr[6];
    /* The segment is percent-encoded in the path; the colons may be
     * %3A, as the device route's are. */
    char dec[64];
    size_t o = 0;
    for (const char *p = path_addr; *p && o + 1 < sizeof(dec); p++) {
        if (*p == '%' && hexv((unsigned char)p[1]) >= 0 && hexv((unsigned char)p[2]) >= 0) {
            dec[o++] = (char)(hexv((unsigned char)p[1]) << 4 | hexv((unsigned char)p[2]));
            p += 2;
        } else {
            dec[o++] = *p;
        }
    }
    dec[o] = '\0';
    if (addr_bytes(dec, addr) != 0) return answer_error(400, "bad_mac", body, cap, len, status);
    web_param_t ps[2] = { { "type", "", 0 }, { "iface", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 2, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    long long type = -1;
    if (ps[0].seen && (decimal(ps[0].val, 0, 255, &type) != 0 || (type > 3 && type != 255)))
        return answer_error(400, "bad_type", body, cap, len, status);
    int iface = -1;
    if (ps[1].seen) {
        for (int i = 0; i < WEB_BLE_IF_COUNT; i++) if (!strcmp(ps[1].val, IFACE[i])) iface = i;
        if (iface < 0) return answer_error(400, "bad_iface", body, cap, len, status);
    }
    if (check_only) { *len = 0; *status = 200; return 0; }
    if (!b || !b->dev) return answer_error(503, "no_ble", body, cap, len, status);
    const web_btsig_tab_t *sig = web_btsig_builtin();
    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&b->mu);
    /* Every row of the address (each sensor's), the asked-for one first. */
    web_jw_raw(&w, "{\"now\":"); web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"rows\":[");
    int n = 0;
    for (int pass = 0; pass < 2; pass++)
        for (int i = 0; i < WEB_BLE_DEVICES; i++) {
            const web_ble_dev_t *d = &b->dev[i];
            if (!d->used || memcmp(d->addr, addr, 6)) continue;
            int asked = (type < 0 || d->addr_type == type) && (iface < 0 || d->iface == iface);
            if ((pass == 0) != asked) continue;
            if (w.len + 3072 > cap) break;
            if (n++) web_jw_raw(&w, ",");
            dev_json(&w, d, sig, 1);
        }
    /* The findings that name this address: a hid_oui finding's addr. */
    web_jw_raw(&w, "],\"alerts\":[");
    int na = 0;
    for (int i = 0; i < WEB_BLE_ALERTS; i++) {
        const web_ble_alert_t *a = &b->al[i];
        if (!a->used || a->kind != WEB_BLE_FIND_HID_OUI || memcmp(a->addr, addr, 6)) continue;
        if (w.len + 1024 > cap) break;
        if (na++) web_jw_raw(&w, ",");
        al_json(&w, a, now_s);
    }
    pthread_mutex_unlock(&b->mu);
    web_jw_raw(&w, "],\"count\":"); web_jw_int(&w, n);
    web_jw_raw(&w, "}\n");
    if (w.overflow) return -1;
    *len = w.len;
    *status = n ? 200 : 404;
    return 0;
}

/* ── /api/live and /api/health ──────────────────────────────────────── */

void web_ble_live_json(web_ble_t *b, web_jw_t *w, long long now_s) {
    if (!b || !b->dev) { web_jw_raw(w, "null"); return; }
    pthread_mutex_lock(&b->mu);
    const web_ble_sh_t *s = &b->sh;
    web_ble_stats_t st;
    stats_locked(b, &st, now_s);
    web_jw_raw(w, "{\"configured\":");
    web_jw_raw(w, s->seen && (s->btmon_iface[0] || s->btcap_iface[0]) ? "true" : "false");
    web_jw_raw(w, ",\"seen\":"); web_jw_raw(w, s->seen ? "true" : "false");
    web_jw_raw(w, ",\"rows\":"); web_jw_int(w, st.rows);
    web_jw_raw(w, ",\"hid\":"); web_jw_int(w, st.hid);
    web_jw_raw(w, ",\"watch\":"); web_jw_int(w, st.watch);
    web_jw_raw(w, ",\"standing\":"); web_jw_int(w, st.standing);
    web_jw_raw(w, ",\"btmon_iface\":"); web_jw_str(w, s->btmon_iface);
    web_jw_raw(w, ",\"btmon_open\":"); web_jw_int(w, s->btmon_open);
    web_jw_raw(w, ",\"btmon_running\":"); web_jw_int(w, s->btmon_running);
    web_jw_raw(w, ",\"btmon_exit\":"); web_jw_str(w, s->btmon_exit);
    web_jw_raw(w, ",\"btmon_stale_secs\":"); web_jw_int(w, s->btmon_stale_secs);
    web_jw_raw(w, ",\"ble_controllers\":"); web_jw_int(w, s->ble_controllers);
    web_jw_raw(w, ",\"ble_devices\":"); web_jw_int(w, s->ble_devices);
    web_jw_raw(w, ",\"ble_adv_reports\":"); web_jw_int(w, s->ble_adv_reports);
    web_jw_raw(w, ",\"ble_scan_mode\":"); web_jw_str(w, s->ble_scan_mode);
    web_jw_raw(w, ",\"ble_scan_filter\":"); web_jw_str(w, s->ble_scan_filter);
    web_jw_raw(w, ",\"ble_scan_enabled\":"); web_jw_int(w, s->ble_scan_enabled);
    web_jw_raw(w, ",\"ble_own_tx\":"); web_jw_str(w, s->ble_own_tx);
    web_jw_raw(w, ",\"ble_own_tx_kind\":"); web_jw_str(w, s->ble_own_tx_kind);
    web_jw_raw(w, ",\"btcap_iface\":"); web_jw_str(w, s->btcap_iface);
    web_jw_raw(w, ",\"btcap_state\":"); web_jw_str(w, s->btcap_state);
    web_jw_raw(w, ",\"btcap_sampling\":"); web_jw_str(w, s->btcap_sampling);
    web_jw_raw(w, ",\"rot\":");
    if (s->rot_present) {
        web_jw_raw(w, "{\"hints\":"); web_jw_str(w, s->ble_rot_hints);
        web_jw_raw(w, ",\"poisoned\":"); web_jw_str(w, s->ble_rot_poisoned);
        web_jw_raw(w, ",\"seam_evictions\":"); web_jw_str(w, s->ble_rot_seam_evictions);
        web_jw_raw(w, "}");
    } else {
        web_jw_raw(w, "null");
    }
    web_jw_raw(w, "}");
    pthread_mutex_unlock(&b->mu);
}

void web_ble_health_json(web_ble_t *b, web_jw_t *w) {
    if (!b || !b->dev) { web_jw_raw(w, "null"); return; }
    web_ble_stats_t st;
    web_ble_sh_t sh;
    web_ble_stats(b, &st);
    web_ble_sensor(b, &sh);
    const web_btsig_tab_t *sig = web_btsig_builtin();
    web_jw_raw(w, "{\"rows\":");            web_jw_int(w, st.rows);
    web_jw_raw(w, ",\"cap\":");             web_jw_int(w, WEB_BLE_DEVICES);
    web_jw_raw(w, ",\"alert_rows\":");      web_jw_int(w, st.alert_rows);
    web_jw_raw(w, ",\"alert_cap\":");       web_jw_int(w, WEB_BLE_ALERTS);
    web_jw_raw(w, ",\"records\":");         web_jw_int(w, (long long)st.records);
    web_jw_raw(w, ",\"device_records\":");  web_jw_int(w, (long long)st.device_records);
    web_jw_raw(w, ",\"alert_records\":");   web_jw_int(w, (long long)st.alert_records);
    web_jw_raw(w, ",\"resolves\":");        web_jw_int(w, (long long)st.resolves);
    web_jw_raw(w, ",\"evictions\":");       web_jw_int(w, (long long)st.evictions);
    web_jw_raw(w, ",\"evicted_dirty\":");   web_jw_int(w, (long long)st.evicted_dirty);
    web_jw_raw(w, ",\"alert_evictions\":"); web_jw_int(w, (long long)st.alert_evictions);
    web_jw_raw(w, ",\"other_iface\":");     web_jw_int(w, (long long)st.other_iface);
    web_jw_raw(w, ",\"other_word\":");      web_jw_int(w, (long long)st.other_word);
    web_jw_raw(w, ",\"name_escaped\":");    web_jw_int(w, (long long)st.name_escaped);
    web_jw_raw(w, ",\"bad_records\":");     web_jw_int(w, (long long)st.bad_records);
    web_jw_raw(w, ",\"seeded\":");          web_jw_int(w, (long long)st.seeded);
    web_jw_raw(w, ",\"seeded_alerts\":");   web_jw_int(w, (long long)st.seeded_alerts);
    web_jw_raw(w, ",\"redirtied\":");       web_jw_int(w, (long long)st.redirtied);
    web_jw_raw(w, ",\"sensor_seen\":");     web_jw_raw(w, sh.seen ? "true" : "false");
    web_jw_raw(w, ",\"sig\":");             web_jw_str(w, sig ? sig->source : "none");
    web_jw_raw(w, ",\"sig_counts\":{\"company\":"); web_jw_int(w, sig ? (long long)sig->ncompany : 0);
    web_jw_raw(w, ",\"service\":");         web_jw_int(w, sig ? (long long)sig->nservice : 0);
    web_jw_raw(w, ",\"appearance\":");      web_jw_int(w, sig ? (long long)sig->nappearance : 0);
    web_jw_raw(w, "}}");
}
