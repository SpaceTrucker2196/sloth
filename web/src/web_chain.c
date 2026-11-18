#include "web_chain.h"

#include <stdlib.h>
#include <string.h>

#include "web_metrics.h"

int web_chain_init(web_chain_t *c) {
    memset(c, 0, sizeof(*c));
    c->pairs = calloc(WEB_CHAIN_PAIRS, sizeof(*c->pairs));
    if (!c->pairs) return -1;
    pthread_mutex_init(&c->mu, NULL);
    return 0;
}

void web_chain_destroy(web_chain_t *c) {
    if (!c->pairs) return;
    pthread_mutex_destroy(&c->mu);
    free(c->pairs);
    c->pairs = NULL;
}

/* A 0/1 member: 1 only for the integer 1, so a string "1" or a 2 is not
 * a link sloth made. */
static int one(const web_jrec_t *r, const char *k) {
    return web_jl_int(r, k, 0) == 1;
}

static void apply(web_chain_t *c, const web_jrec_t *r) {
    char real[WEB_KEY_MAX + 1], twin[WEB_KEY_MAX + 1];
    const char *a = web_jl_str(r, "real_bssid"), *b = web_jl_str(r, "twin_bssid");
    long long ts = web_jl_int(r, "ts", 0);
    if (!a || !b || web_key_mac(a, real) != 0 || web_key_mac(b, twin) != 0 ||
        !strcmp(real, twin) || ts <= 0) {
        c->rejected++;
        return;
    }
    c->records++;
    const char *lo = strcmp(real, twin) < 0 ? real : twin;
    const char *hi = lo == real ? twin : real;
    int i, old = -1;
    for (i = 0; i < c->n; i++)
        if (!strcmp(c->pairs[i].lo, lo) && !strcmp(c->pairs[i].hi, hi)) break;
    if (i == c->n) {
        if (c->n < WEB_CHAIN_PAIRS) {
            i = c->n++;
        } else {
            /* Full: the least recently reported pair makes room. */
            for (int j = 0; j < c->n; j++)
                if (old < 0 || c->pairs[j].last_ts < c->pairs[old].last_ts) old = j;
            i = old;
            c->evictions++;
        }
        memset(&c->pairs[i], 0, sizeof(c->pairs[i]));
        memcpy(c->pairs[i].lo, lo, strlen(lo) + 1);
        memcpy(c->pairs[i].hi, hi, strlen(hi) + 1);
        c->pairs[i].first_ts = ts;
        c->pairs[i].confidence = -1;
    }
    web_chain_pair_t *p = &c->pairs[i];
    memcpy(p->real, real, sizeof(p->real));
    memcpy(p->twin, twin, sizeof(p->twin));
    if (ts < p->first_ts) p->first_ts = ts;
    if (ts > p->last_ts) p->last_ts = ts;
    if (one(r, "attack_in_progress") && (!p->taint_ts || ts < p->taint_ts)) p->taint_ts = ts;
    p->attributed = one(r, "attributed");
    if (p->attributed && (!p->attr_ts || ts < p->attr_ts)) p->attr_ts = ts;
    long long cf = web_jl_int(r, "confidence", -1);
    p->confidence = cf >= 0 && cf <= 100 ? (int)cf : -1;
    p->records++;
    if (!c->since || ts < c->since) c->since = ts;
}

void web_chain_record(web_chain_t *c, const web_jrec_t *r) {
    if (!c || !c->pairs) return;
    const char *t = web_jl_str(r, "type");
    if (!t || strcmp(t, "twin_episode") != 0) return;
    pthread_mutex_lock(&c->mu);
    apply(c, r);
    pthread_mutex_unlock(&c->mu);
}

static int by_first(const void *x, const void *y) {
    const web_chain_pair_t *a = x, *b = y;
    if (a->first_ts != b->first_ts) return a->first_ts < b->first_ts ? -1 : 1;
    return strcmp(a->lo, b->lo);
}

int web_chain_links(web_chain_t *c, const char *bssid, long long from,
                    long long to, web_chain_pair_t *out, int max,
                    long long *since) {
    *since = 0;
    if (!c || !c->pairs || !bssid || max <= 0) return 0;
    int n = 0;
    pthread_mutex_lock(&c->mu);
    *since = c->since;
    for (int i = 0; i < c->n && n < max; i++) {
        const web_chain_pair_t *p = &c->pairs[i];
        if (strcmp(p->lo, bssid) != 0 && strcmp(p->hi, bssid) != 0) continue;
        if (p->last_ts < from || p->first_ts >= to) continue;
        out[n++] = *p;
    }
    pthread_mutex_unlock(&c->mu);
    qsort(out, (size_t)n, sizeof(*out), by_first);
    return n;
}

long long web_chain_since(web_chain_t *c) {
    if (!c || !c->pairs) return 0;
    pthread_mutex_lock(&c->mu);
    long long s = c->since;
    pthread_mutex_unlock(&c->mu);
    return s;
}
