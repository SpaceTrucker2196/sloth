#include "web_lure.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_series.h"

/* Contract and bounds: web_lure.h. */

int web_lure_init(web_lure_t *l) {
    memset(l, 0, sizeof(*l));
    return pthread_mutex_init(&l->mu, NULL) == 0 ? 0 : -1;
}

void web_lure_destroy(web_lure_t *l) {
    pthread_mutex_destroy(&l->mu);
}

static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Exactly "xx:xx:xx:xx:xx:xx", either case: the form sloth writes. */
static int mac_parse(const char *s, uint8_t out[6]) {
    if (!s || strlen(s) != 17) return -1;
    for (int i = 0; i < 6; i++) {
        int hi = hexv(s[i * 3]), lo = hexv(s[i * 3 + 1]);
        if (hi < 0 || lo < 0 || (i < 5 && s[i * 3 + 2] != ':')) return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return 0;
}

static int jint(const web_jrec_t *r, const char *k, long long lo, long long hi,
                long long *v) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *v = f->i;
    return 1;
}

static int jcount(const web_jrec_t *r, const char *k, long long *v) {
    return jint(r, k, 0, WEB_LURE_COUNT_MAX, v);
}

/* A string member of at most max_cp code points and max_oct octets
 * (the decoder has already refused one that is not UTF-8). */
static int jtext(const web_jrec_t *r, const char *k, size_t max_cp,
                 size_t max_oct, char *out) {
    const char *s = web_jl_str(r, k);
    if (!s) return 0;
    size_t n = strlen(s), cp = 0;
    if (n > max_oct) return 0;
    for (size_t i = 0; i < n; i++)
        if (((unsigned char)s[i] & 0xC0) != 0x80) cp++;
    if (cp > max_cp) return 0;
    memcpy(out, s, n + 1);
    return 1;
}

static int kind_of(const char *t) {
    if (!t) return -1;
    if (!strcmp(t, "karma_suspect"))   return WEB_LURE_K_KARMA;
    if (!strcmp(t, "harvest_station")) return WEB_LURE_K_STA;
    if (!strcmp(t, "harvest_chain"))   return WEB_LURE_K_CHAIN;
    return -1;
}

static web_lure_row_t *table(web_lure_t *l, int k, int *n) {
    switch (k) {
    case WEB_LURE_K_KARMA: *n = WEB_LURE_KARMA; return l->karma;
    case WEB_LURE_K_STA:   *n = WEB_LURE_STA;   return l->sta;
    default:               *n = WEB_LURE_CHAIN; return l->chain;
    }
}

/* The row's members into t; 0 when every one is present and in bounds. */
static int parse(int k, const web_jrec_t *r, web_lure_row_t *t) {
    long long ts;
    if (!jint(r, "ts", 0, 1LL << 40, &ts)) return -1;
    t->ts = ts;
    if (k == WEB_LURE_K_KARMA) {
        long long col;
        if (!jcount(r, "ssids", &t->ssids) || !jcount(r, "ie_postures", &t->ie_postures) ||
            !jint(r, "ie_collapsed", 0, 1, &col) || !jcount(r, "forged", &t->forged) ||
            !jcount(r, "forge_stations", &t->forge_stations) ||
            !jcount(r, "pnl_best", &t->pnl_best) ||
            !jint(r, "lure_chain", 0, 1, &t->lure_chain) || !jcount(r, "score", &t->score) ||
            !jtext(r, "top_ssid", 32, WEB_LURE_SSID_MAX, t->top_ssid) ||
            !jtext(r, "tool", WEB_LURE_TOOL_MAX, WEB_LURE_TOOL_MAX, t->tool) ||
            !jint(r, "last_seen", 0, 1LL << 40, &t->last_seen))
            return -1;
        t->ie_collapsed = col;
        return 0;
    }
    if (!jint(r, "first_seen", 0, 1LL << 40, &t->first_seen) ||
        !jint(r, "last_seen", 0, 1LL << 40, &t->last_seen) ||
        !jcount(r, "dropped", &t->dropped))
        return -1;
    if (k == WEB_LURE_K_STA)
        return jcount(r, "asked", &t->asked) && jcount(r, "m1_bssids", &t->m1_bssids) &&
               jcount(r, "unanswered", &t->unanswered) &&
               jcount(r, "unanswered_kde", &t->unanswered_kde) &&
               jcount(r, "answered", &t->answered) ? 0 : -1;
    return jcount(r, "victims", &t->victims) &&
           jcount(r, "disconnects", &t->disconnects) ? 0 : -1;
}

/* sensor_health's "MAJOR.MINOR.PATCH", each 1..4 digits. */
static int ver_parse(const char *s, int v[3]) {
    if (!s) return -1;
    for (int i = 0; i < 3; i++) {
        int n = 0, d = 0;
        while (*s >= '0' && *s <= '9' && d < 4) { n = n * 10 + (*s++ - '0'); d++; }
        if (!d || (i < 2 && *s++ != '.')) return -1;
        v[i] = n;
    }
    return *s ? -1 : 0;
}

void web_lure_record(web_lure_t *l, const web_jrec_t *r, long long now_ms) {
    const char *ty = web_jl_str(r, "type");
    if (!l || !ty) return;
    if (!strcmp(ty, "sensor_health")) {
        int v[3];
        const char *s = web_jl_str(r, "jsonl_version");
        pthread_mutex_lock(&l->mu);
        if (!s) {
            /* Before 1.0.0 the stream carried no version: such a sloth
             * writes none of these. */
            l->ver_seen = 1;
            l->ver[0] = l->ver[1] = l->ver[2] = 0;
        } else if (ver_parse(s, v) == 0) {
            l->ver_seen = 1;
            memcpy(l->ver, v, sizeof(v));
        }
        pthread_mutex_unlock(&l->mu);
        return;
    }
    int k = kind_of(ty);
    if (k < 0) return;
    static web_lure_row_t t;     /* the record's worth; under l->mu */
    uint8_t mac[6];
    const char *st = web_jl_str(r, "state");
    pthread_mutex_lock(&l->mu);
    l->records++;
    if (mac_parse(web_jl_str(r, k == WEB_LURE_K_STA ? "sta" : "bssid"), mac) != 0 || !st ||
        (strcmp(st, "live") && strcmp(st, "gone"))) {
        l->rejected++;
        pthread_mutex_unlock(&l->mu);
        return;
    }
    int n;
    web_lure_row_t *tab = table(l, k, &n), *row = NULL, *free_row = NULL;
    for (int i = 0; i < n; i++) {
        if (tab[i].used && !memcmp(tab[i].mac, mac, 6)) { row = &tab[i]; break; }
        if (!tab[i].used && !free_row) free_row = &tab[i];
    }
    if (!strcmp(st, "gone")) {
        if (row) { memset(row, 0, sizeof(*row)); l->gone++; }
        pthread_mutex_unlock(&l->mu);
        return;
    }
    memset(&t, 0, sizeof(t));
    if (parse(k, r, &t) != 0) {
        l->rejected++;
        pthread_mutex_unlock(&l->mu);
        return;
    }
    web_lure_row_t *dst = row ? row : free_row;
    /* Past sloth's own table size: a stale row (a sloth that restarted
     * without it) may be holding a slot, so one is reclaimed before the
     * record is refused. */
    for (int i = 0; i < n && !dst; i++)
        if (now_ms - tab[i].rx_ms > WEB_LURE_STALE_MS) dst = &tab[i];
    if (!dst) {
        l->overflow++;
    } else {
        *dst = t;
        dst->used = 1;
        memcpy(dst->mac, mac, 6);
        dst->rx_ms = now_ms;
    }
    pthread_mutex_unlock(&l->mu);
}

int web_lure_reported(web_lure_t *l) {
    if (!l) return -1;
    pthread_mutex_lock(&l->mu);
    int ans = !l->ver_seen ? -1
            : (l->ver[0] > 1 || (l->ver[0] == 1 && l->ver[1] >= 3));
    pthread_mutex_unlock(&l->mu);
    return ans;
}

static int answer_error(int status, const char *reason, char *body, size_t cap,
                        size_t *len, int *status_out) {
    *status_out = status;
    *len = web_series_error_json(reason, body, cap);
    return *len ? 0 : -1;
}

static void mac_jw(web_jw_t *w, const uint8_t m[6]) {
    static const char hx[] = "0123456789abcdef";
    char s[18];
    for (int i = 0; i < 6; i++) {
        s[i * 3] = hx[m[i] >> 4];
        s[i * 3 + 1] = hx[m[i] & 15];
        s[i * 3 + 2] = i < 5 ? ':' : '\0';
    }
    web_jw_str(w, s);
}

static void kv(web_jw_t *w, const char *k, long long v) {
    web_jw_raw(w, ",");
    web_jw_key(w, k);
    web_jw_int(w, v);
}

static void row_json(web_jw_t *w, int k, const web_lure_row_t *x, long long now_ms) {
    web_jw_raw(w, "{");
    web_jw_key(w, k == WEB_LURE_K_STA ? "sta" : "bssid");
    mac_jw(w, x->mac);
    kv(w, "ts", x->ts);
    kv(w, "age_s", (now_ms - x->rx_ms) / 1000);
    if (k == WEB_LURE_K_KARMA) {
        kv(w, "ssids", x->ssids);
        kv(w, "ie_postures", x->ie_postures);
        web_jw_raw(w, ",\"ie_collapsed\":");
        web_jw_raw(w, x->ie_collapsed ? "true" : "false");
        kv(w, "forged", x->forged);
        kv(w, "forge_stations", x->forge_stations);
        kv(w, "pnl_best", x->pnl_best);
        web_jw_raw(w, ",\"lure_chain\":");
        web_jw_raw(w, x->lure_chain ? "true" : "false");
        kv(w, "score", x->score);
        web_jw_raw(w, ",\"top_ssid\":");
        web_jw_str(w, x->top_ssid);
        web_jw_raw(w, ",\"tool\":");
        web_jw_str(w, x->tool);
    } else if (k == WEB_LURE_K_STA) {
        kv(w, "asked", x->asked);
        kv(w, "m1_bssids", x->m1_bssids);
        kv(w, "unanswered", x->unanswered);
        kv(w, "unanswered_kde", x->unanswered_kde);
        kv(w, "answered", x->answered);
        kv(w, "dropped", x->dropped);
        kv(w, "first_seen", x->first_seen);
    } else {
        kv(w, "victims", x->victims);
        kv(w, "disconnects", x->disconnects);
        kv(w, "dropped", x->dropped);
        kv(w, "first_seen", x->first_seen);
    }
    kv(w, "last_seen", x->last_seen);
    web_jw_raw(w, "}");
}

/* The ranking key: the score for a KARMA row, the unanswered M1s for a
 * station, the victims for a chain; newest first among equals. */
static long long rank(int k, const web_lure_row_t *x) {
    return k == WEB_LURE_K_KARMA ? x->score : k == WEB_LURE_K_STA ? x->unanswered : x->victims;
}

static int g_sort_kind;
static int cmp_rows(const void *a, const void *b) {
    const web_lure_row_t *x = *(const web_lure_row_t *const *)a;
    const web_lure_row_t *y = *(const web_lure_row_t *const *)b;
    long long rx = rank(g_sort_kind, x), ry = rank(g_sort_kind, y);
    if (rx != ry) return rx > ry ? -1 : 1;
    if (x->last_seen != y->last_seen) return x->last_seen > y->last_seen ? -1 : 1;
    return memcmp(x->mac, y->mac, 6);
}

static const char *const LIST_NAME[WEB_LURE_KINDS] = { "karma", "stations", "chains" };

int web_lure_route(web_lure_t *l, const char *query, long long now_s,
                   long long now_ms, int none_here, char *body, size_t cap,
                   size_t *len, int *status) {
    char err[48];
    if (web_params_parse(query, NULL, 0, err, sizeof(err)) != 0)
        return answer_error(400, err, body, cap, len, status);
    if (!l) return answer_error(503, "no_lures", body, cap, len, status);
    if (none_here) { *status = 200; *len = 1; return 0; }
    int reported = web_lure_reported(l);

    web_jw_t w;
    web_jw_init(&w, body, cap);
    pthread_mutex_lock(&l->mu);
    web_jw_raw(&w, "{\"now\":");
    web_jw_int(&w, now_s);
    web_jw_raw(&w, ",\"reported\":");
    web_jw_raw(&w, reported < 0 ? "null" : reported ? "true" : "false");
    web_jw_raw(&w, ",\"jsonl_version\":");
    if (l->ver_seen && (l->ver[0] || l->ver[1] || l->ver[2])) {
        char v[16];
        snprintf(v, sizeof(v), "%d.%d.%d", l->ver[0], l->ver[1], l->ver[2]);
        web_jw_str(&w, v);
    } else {
        web_jw_raw(&w, "null");
    }
    int stale = 0;
    for (int k = 0; k < WEB_LURE_KINDS; k++) {
        int n, m = 0;
        web_lure_row_t *tab = table(l, k, &n);
        const web_lure_row_t *idx[WEB_LURE_KARMA];
        for (int i = 0; i < n; i++) {
            if (!tab[i].used) continue;
            if (now_ms - tab[i].rx_ms > WEB_LURE_STALE_MS) { stale++; continue; }
            idx[m++] = &tab[i];
        }
        g_sort_kind = k;
        if (m > 1) qsort(idx, (size_t)m, sizeof(idx[0]), cmp_rows);
        web_jw_raw(&w, ",");
        web_jw_key(&w, LIST_NAME[k]);
        web_jw_raw(&w, "[");
        for (int i = 0; i < m; i++) {
            if (i) web_jw_raw(&w, ",");
            row_json(&w, k, idx[i], now_ms);
        }
        web_jw_raw(&w, "]");
    }
    kv(&w, "stale", stale);
    kv(&w, "records", (long long)l->records);
    kv(&w, "rejected", (long long)l->rejected);
    kv(&w, "overflow", (long long)l->overflow);
    web_jw_raw(&w, "}\n");
    pthread_mutex_unlock(&l->mu);
    if (w.overflow) return -1;
    *len = w.len;
    *status = 200;
    return 0;
}

size_t web_lure_out_of_scope_json(char *body, size_t cap) {
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"out_of_scope\":true,\"reason\":");
    web_jw_str(&w, "KARMA and key-harvest findings are the passive monitor radio's; "
                   "the host's own interfaces carried none");
    web_jw_raw(&w, "}\n");
    return w.overflow ? 0 : w.len;
}
