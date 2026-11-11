#include "web_own.h"

#include <stdio.h>
#include <string.h>

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

void web_own_record(web_own_t *o, const web_jrec_t *r, long long now_ms) {
    const char *ty = web_jl_str(r, "type");
    if (!o || !ty || strcmp(ty, "ownership")) return;
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
