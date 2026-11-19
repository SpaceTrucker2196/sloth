#include "web_own.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Contract and bounds: web_own.h. */

static web_own_t *g_bound;

int web_own_init(web_own_t *o) {
    memset(o, 0, sizeof(*o));
    return pthread_mutex_init(&o->mu, NULL) == 0 ? 0 : -1;
}

void web_own_destroy(web_own_t *o) {
    if (g_bound == o) g_bound = NULL;
    pthread_mutex_destroy(&o->mu);
}

void web_own_bind(web_own_t *o) { g_bound = o; }

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

static int jint(const web_jrec_t *r, const char *k, long long lo, long long hi, long long *v) {
    const web_jfield_t *f = web_jl_get(r, k);
    if (!f || f->kind != WEB_J_INT || f->i < lo || f->i > hi) return 0;
    *v = f->i;
    return 1;
}

/* Built in a scratch copy and kept only whole: a malformed record
 * leaves the last good roster in place. */
static int parse(const web_jrec_t *r, web_own_t *t) {
    long long ns, nb, km;
    char key[24];
    if (!jint(r, "ssids", 0, WEB_OWN_SSIDS, &ns) || !jint(r, "bssids", 0, WEB_OWN_BSSIDS, &nb) ||
        !jint(r, "known_macs", 0, WEB_OWN_KNOWN_MAX, &km))
        return -1;
    for (int i = 0; i < (int)ns; i++) {
        snprintf(key, sizeof(key), "ssid_%d", i);
        const char *s = web_jl_str(r, key);
        size_t n = s ? strlen(s) : 0;
        if (n == 0) return -1;
        /* Over 32 octets decoded only from bytes that were not UTF-8
         * (each written as U+FFFD, three octets): designated, and equal
         * to no text sloth.db holds. Kept as a designation that matches
         * nothing (length 0), never cut to a prefix that might. */
        if (n > 32) { t->ssid[i][0] = '\0'; t->ssid_len[i] = 0; continue; }
        memcpy(t->ssid[i], s, n);
        t->ssid[i][n] = '\0';
        t->ssid_len[i] = n;
    }
    for (int i = 0; i < (int)nb; i++) {
        snprintf(key, sizeof(key), "bssid_%d", i);
        if (mac_parse(web_jl_str(r, key), t->bssid[i]) != 0) return -1;
    }
    t->nssid = (int)ns;
    t->nbssid = (int)nb;
    t->known_macs = km;
    return 0;
}

/* ── the joined network (#234) ────────────────────────────────────────── */

/* The slot for b in the BSSID table: its own, else an empty one, else
 * the one heard longest ago. */
static web_own_net_t *net_slot(web_own_t *o, const uint8_t b[6]) {
    int old = 0;
    for (int i = 0; i < o->nnet; i++) {
        if (!memcmp(o->net[i].b, b, 6)) return &o->net[i];
        if (o->net[i].ms < o->net[old].ms) old = i;
    }
    if (o->nnet < WEB_OWN_JOIN_NETS) return &o->net[o->nnet++];
    return &o->net[old];
}

static web_own_cli_t *cli_slot(web_own_t *o, const uint8_t sta[6]) {
    int old = 0;
    for (int i = 0; i < o->ncli; i++) {
        if (!memcmp(o->cli[i].sta, sta, 6)) return &o->cli[i];
        if (o->cli[i].ms < o->cli[old].ms) old = i;
    }
    if (o->ncli < WEB_OWN_JOIN_CLIENTS) return &o->cli[o->ncli++];
    return &o->cli[old];
}

/* The records the joined network is learned from; under o->mu. */
static void join_learn(web_own_t *o, const char *ty, const web_jrec_t *r, long long now_ms) {
    uint8_t a[6], b[6];
    if (!strcmp(ty, "wifi_sta")) {
        if (mac_parse(web_jl_str(r, "mac"), a) != 0) return;
        memcpy(o->join_bssid, a, 6);
        o->join_have = 1;
        o->join_ms = now_ms;
    } else if (!strcmp(ty, "wifi_ap") || !strcmp(ty, "beacon")) {
        const char *ss = web_jl_str(r, "ssid");
        size_t n = ss ? strlen(ss) : 0;
        /* A hidden SSID names no network; one over 32 octets is not an
         * SSID sloth.db could hold. */
        if (n == 0 || n > 32 || mac_parse(web_jl_str(r, "bssid"), b) != 0) return;
        web_own_net_t *e = net_slot(o, b);
        memcpy(e->b, b, 6);
        memcpy(e->ssid, ss, n + 1);
        e->n = n;
        e->ms = now_ms;
    } else if (!strcmp(ty, "assoc") || !strcmp(ty, "eapol") ||
               !strcmp(ty, "wifi_assoc_req") || !strcmp(ty, "btm_request")) {
        if (mac_parse(web_jl_str(r, "sta_mac"), a) != 0 ||
            mac_parse(web_jl_str(r, "bssid"), b) != 0 || !memcmp(a, b, 6))
            return;
        web_own_cli_t *e = cli_slot(o, a);
        memcpy(e->sta, a, 6);
        memcpy(e->ap, b, 6);
        e->ms = now_ms;
    }
}

static int in_set(const uint8_t (*set)[6], int n, const uint8_t m[6]) {
    for (int i = 0; i < n; i++)
        if (!memcmp(set[i], m, 6)) return 1;
    return 0;
}

int web_own_join_at(web_own_join_t *j, long long now_ms) {
    memset(j, 0, sizeof(*j));
    web_own_t *o = g_bound;
    if (!o) return 0;
    pthread_mutex_lock(&o->mu);
    if (o->join_have && now_ms - o->join_ms <= WEB_OWN_JOIN_STALE_MS) {
        j->have = 1;
        memcpy(j->b[j->nb++], o->join_bssid, 6);
        for (int i = 0; i < o->nnet; i++)
            if (!memcmp(o->net[i].b, o->join_bssid, 6)) {
                j->ssid_len = o->net[i].n;
                memcpy(j->ssid, o->net[i].ssid, o->net[i].n + 1);
            }
        /* Every BSSID that advertises the SSID: the network's other APs
         * and bands. */
        for (int i = 0; j->ssid_len && i < o->nnet && j->nb < WEB_OWN_JOIN_BSSIDS; i++)
            if (o->net[i].n == j->ssid_len && !memcmp(o->net[i].ssid, j->ssid, j->ssid_len) &&
                !in_set((const uint8_t (*)[6])j->b, j->nb, o->net[i].b))
                memcpy(j->b[j->nb++], o->net[i].b, 6);
        for (int i = 0; i < o->ncli && j->nc < WEB_OWN_JOIN_CLIENTS; i++)
            if (in_set((const uint8_t (*)[6])j->b, j->nb, o->cli[i].ap))
                memcpy(j->c[j->nc++], o->cli[i].sta, 6);
    }
    pthread_mutex_unlock(&o->mu);
    return j->have;
}

int web_own_join_for(const web_scope_ctx_t *sc, web_own_join_t *j) {
    if (!sc || sc->scope != WEB_SCOPE_MONITOR) {
        memset(j, 0, sizeof(*j));
        return 0;
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return web_own_join_at(j, (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int web_own_join_mac(const web_own_join_t *j, const char *mac) {
    uint8_t m[6];
    if (!j || !j->have || mac_parse(mac, m) != 0) return 0;
    return in_set((const uint8_t (*)[6])j->b, j->nb, m) ||
           in_set((const uint8_t (*)[6])j->c, j->nc, m);
}

int web_own_join_macb(const web_own_join_t *j, const uint8_t m[6]) {
    if (!j || !j->have || !m) return 0;
    return in_set((const uint8_t (*)[6])j->b, j->nb, m) ||
           in_set((const uint8_t (*)[6])j->c, j->nc, m);
}

int web_own_join_ssid(const web_own_join_t *j, const char *ssid, size_t n) {
    return j && j->have && j->ssid_len && ssid && n == j->ssid_len &&
           !memcmp(ssid, j->ssid, n);
}

int web_own_join_rec(const web_own_join_t *j, const web_jrec_t *r) {
    static const char *const K[] = { "bssid", "sta_mac", "mac", "src", "dst", NULL };
    if (!j || !j->have || !r) return 0;
    for (int k = 0; K[k]; k++)
        if (web_own_join_mac(j, web_jl_str(r, K[k]))) return 1;
    const char *ss = web_jl_str(r, "ssid");
    return ss && web_own_join_ssid(j, ss, strlen(ss));
}

void web_own_join_jw(web_jw_t *w, const web_own_join_t *j) {
    if (!j || !j->have) return;
    web_jw_raw(w, ",\"own_hidden\":");
    web_jw_int(w, (long long)j->hidden);
}

void web_own_record(web_own_t *o, const web_jrec_t *r, long long now_ms) {
    const char *ty = web_jl_str(r, "type");
    if (!o || !ty) return;
    if (strcmp(ty, "ownership")) {
        pthread_mutex_lock(&o->mu);
        join_learn(o, ty, r, now_ms);
        pthread_mutex_unlock(&o->mu);
        return;
    }
    static web_own_t t;          /* the record's worth; under o->mu */
    pthread_mutex_lock(&o->mu);
    o->records++;
    memset(t.ssid, 0, sizeof(t.ssid));
    memset(t.ssid_len, 0, sizeof(t.ssid_len));
    memset(t.bssid, 0, sizeof(t.bssid));
    if (parse(r, &t) != 0) {
        o->rejected++;
    } else {
        o->seen = 1;
        o->ts = web_jl_int(r, "ts", 0);
        o->rx_ms = now_ms;
        o->nssid = t.nssid;
        o->nbssid = t.nbssid;
        o->known_macs = t.known_macs;
        memcpy(o->ssid, t.ssid, sizeof(o->ssid));
        memcpy(o->ssid_len, t.ssid_len, sizeof(o->ssid_len));
        memcpy(o->bssid, t.bssid, sizeof(o->bssid));
    }
    pthread_mutex_unlock(&o->mu);
}

int web_own_ssid(const char *ssid, size_t n) {
    web_own_t *o = g_bound;
    if (!o) return -1;
    int ans = -1;
    pthread_mutex_lock(&o->mu);
    if (o->seen) {
        ans = 0;
        for (int i = 0; ssid && n > 0 && i < o->nssid && !ans; i++)
            if (o->ssid_len[i] == n && !memcmp(o->ssid[i], ssid, n)) ans = 1;
    }
    pthread_mutex_unlock(&o->mu);
    return ans;
}

int web_own_bssid(const char *bssid) {
    web_own_t *o = g_bound;
    if (!o) return -1;
    uint8_t b[6];
    int ok = mac_parse(bssid, b) == 0, ans = -1;
    pthread_mutex_lock(&o->mu);
    if (o->seen) {
        ans = 0;
        for (int i = 0; ok && i < o->nbssid && !ans; i++)
            if (!memcmp(o->bssid[i], b, 6)) ans = 1;
    }
    pthread_mutex_unlock(&o->mu);
    return ans;
}

int web_own_ssid_count(void) {
    web_own_t *o = g_bound;
    if (!o) return -1;
    pthread_mutex_lock(&o->mu);
    int n = o->seen ? o->nssid : -1;
    pthread_mutex_unlock(&o->mu);
    return n;
}

void web_own_jw(web_jw_t *w, int answer) {
    web_jw_raw(w, answer < 0 ? "null" : answer ? "true" : "false");
}
