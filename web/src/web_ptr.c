#include "web_ptr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_metrics.h"

static unsigned hash(const char *k) {
    unsigned h = 2166136261u;
    for (const unsigned char *p = (const unsigned char *)k; *p; p++) {
        h ^= *p;
        h *= 16777619u;
    }
    return h;
}

int web_ptr_init(web_ptr_t *p, int cap) {
    memset(p, 0, sizeof(*p));
    if (cap < 1) cap = 1;
    p->cap = cap;
    p->nhead = 1;
    while (p->nhead < cap * 2) p->nhead <<= 1;
    p->e = calloc((size_t)cap, sizeof(*p->e));
    p->head = malloc((size_t)p->nhead * sizeof(*p->head));
    if (!p->e || !p->head) {
        free(p->e);
        free(p->head);
        p->e = NULL;
        p->head = NULL;
        return -1;
    }
    for (int i = 0; i < p->nhead; i++) p->head[i] = -1;
    pthread_mutex_init(&p->mu, NULL);
    p->st.cap = cap;
    return 0;
}

void web_ptr_destroy(web_ptr_t *p) {
    if (!p->e) return;
    free(p->e);
    free(p->head);
    p->e = NULL;
    p->head = NULL;
    pthread_mutex_destroy(&p->mu);
}

static int find_locked(web_ptr_t *p, const char *ip) {
    for (int i = p->head[hash(ip) & (unsigned)(p->nhead - 1)]; i >= 0;
         i = p->e[i].next)
        if (!strcmp(p->e[i].ip, ip)) return i;
    return -1;
}

static void unlink_locked(web_ptr_t *p, int i) {
    int *pp = &p->head[hash(p->e[i].ip) & (unsigned)(p->nhead - 1)];
    while (*pp >= 0 && *pp != i) pp = &p->e[*pp].next;
    if (*pp == i) *pp = p->e[i].next;
}

/* The slot for ip, made if absent: a free one, else the least recently
 * seen (counted). */
static int slot_locked(web_ptr_t *p, const char *ip) {
    int i = find_locked(p, ip);
    if (i >= 0) return i;
    int free_i = -1, old = -1;
    for (int k = 0; k < p->cap; k++) {
        if (!p->e[k].used) { free_i = k; break; }
        if (old < 0 || p->e[k].last_seen < p->e[old].last_seen) old = k;
    }
    if (free_i < 0) {
        unlink_locked(p, old);
        p->st.evictions++;
        p->n--;
        free_i = old;
    }
    web_ptr_ent_t *e = &p->e[free_i];
    memset(e, 0, sizeof(*e));
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->used = 1;
    unsigned h = hash(ip) & (unsigned)(p->nhead - 1);
    e->next = p->head[h];
    p->head[h] = free_i;
    p->n++;
    return free_i;
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int ends_ci(const char *s, size_t n, const char *suf) {
    size_t k = strlen(suf);
    if (n < k) return 0;
    for (size_t i = 0; i < k; i++) {
        int c = (unsigned char)s[n - k + i];
        if (c >= 'A' && c <= 'Z') c += 32;
        if (c != suf[i]) return 0;
    }
    return 1;
}

int web_ptr_qname_ip(const char *qname, char *out) {
    if (!qname) return -1;
    size_t n = strnlen(qname, 128);
    if (n >= 128) return -1;
    if (n && qname[n - 1] == '.') n--;
    char tmp[64];
    if (ends_ci(qname, n, ".in-addr.arpa")) {
        size_t m = n - 13;
        /* Four labels of 1..3 digits, reversed. */
        const char *lab[4];
        size_t len[4];
        int k = 0;
        size_t st = 0;
        for (size_t i = 0; i <= m; i++) {
            if (i == m || qname[i] == '.') {
                if (k >= 4 || i == st || i - st > 3) return -1;
                lab[k] = qname + st;
                len[k] = i - st;
                k++;
                st = i + 1;
            } else if (qname[i] < '0' || qname[i] > '9') {
                return -1;
            }
        }
        if (k != 4) return -1;
        snprintf(tmp, sizeof(tmp), "%.*s.%.*s.%.*s.%.*s",
                 (int)len[3], lab[3], (int)len[2], lab[2],
                 (int)len[1], lab[1], (int)len[0], lab[0]);
        return web_key_ip(tmp, out);
    }
    if (ends_ci(qname, n, ".ip6.arpa")) {
        /* 32 single hex nibbles, least significant first. */
        if (n - 9 != 63) return -1;
        unsigned char nib[32];
        for (int i = 0; i < 32; i++) {
            int v = hexv((unsigned char)qname[i * 2]);
            if (v < 0 || (i < 31 && qname[i * 2 + 1] != '.')) return -1;
            nib[31 - i] = (unsigned char)v;
        }
        size_t o = 0;
        for (int g = 0; g < 8; g++) {
            o += (size_t)snprintf(tmp + o, sizeof(tmp) - o, g ? ":%x%x%x%x" : "%x%x%x%x",
                                  nib[g * 4], nib[g * 4 + 1], nib[g * 4 + 2],
                                  nib[g * 4 + 3]);
        }
        return web_key_ip(tmp, out);
    }
    return -1;
}

/* A host name: 1..WEB_PTR_NAME_MAX bytes of letters, digits, '-', '_'
 * and '.', not an address, not NXDOMAIN. A trailing dot is dropped. */
static int name_ok(const char *s, char *out) {
    size_t n = strnlen(s, WEB_PTR_NAME_MAX + 2);
    if (n && s[n - 1] == '.') n--;
    if (n == 0 || n > WEB_PTR_NAME_MAX) return -1;
    for (size_t i = 0; i < n; i++) {
        int c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'))
            return -1;
    }
    memcpy(out, s, n);
    out[n] = '\0';
    if (!strcmp(out, "NXDOMAIN")) return -1;
    char c[WEB_KEY_MAX + 1];
    if (web_key_ip(out, c) == 0) return -1;
    return 0;
}

void web_ptr_record(web_ptr_t *p, const char *qtype, long long is_resp,
                    const char *qname, const char *answer, long long now_s) {
    if (!p || !p->e || !qtype || strcmp(qtype, "PTR") != 0 || is_resp != 1)
        return;
    char ip[WEB_KEY_MAX + 1], name[WEB_PTR_NAME_MAX + 1];
    pthread_mutex_lock(&p->mu);
    p->st.seen++;
    if (!answer || !answer[0]) {
        p->st.empty++;
    } else if (web_ptr_qname_ip(qname, ip) != 0 || name_ok(answer, name) != 0) {
        p->st.refused++;
    } else {
        int i = slot_locked(p, ip);
        web_ptr_ent_t *e = &p->e[i];
        if (strcmp(e->name, name) != 0) {
            snprintf(e->name, sizeof(e->name), "%s", name);
            e->first_seen = now_s;
            p->st.stored++;
        }
        e->last_seen = now_s;
        e->dirty = 1;
    }
    pthread_mutex_unlock(&p->mu);
}

int web_ptr_get(web_ptr_t *p, const char *ip, char *name, long long *t) {
    if (!p || !p->e || !ip) return 0;
    pthread_mutex_lock(&p->mu);
    int i = find_locked(p, ip);
    if (i >= 0) {
        snprintf(name, WEB_PTR_NAME_MAX + 1, "%s", p->e[i].name);
        if (t) *t = p->e[i].last_seen;
    }
    pthread_mutex_unlock(&p->mu);
    return i >= 0;
}

int web_ptr_take_dirty(web_ptr_t *p, web_store_ptr_t *out, int max) {
    int n = 0;
    pthread_mutex_lock(&p->mu);
    for (int i = 0; i < p->cap && n < max; i++) {
        web_ptr_ent_t *e = &p->e[i];
        if (!e->used || !e->dirty) continue;
        snprintf(out[n].ip, sizeof(out[n].ip), "%s", e->ip);
        snprintf(out[n].name, sizeof(out[n].name), "%s", e->name);
        out[n].first_seen = e->first_seen;
        out[n].last_seen = e->last_seen;
        e->dirty = 0;
        n++;
    }
    pthread_mutex_unlock(&p->mu);
    return n;
}

void web_ptr_redirty(web_ptr_t *p, const web_store_ptr_t *r, int n) {
    pthread_mutex_lock(&p->mu);
    for (int k = 0; k < n; k++) {
        int i = find_locked(p, r[k].ip);
        if (i >= 0) p->e[i].dirty = 1;
    }
    pthread_mutex_unlock(&p->mu);
}

void web_ptr_load_row(void *ctx, const web_store_ptr_t *r) {
    web_ptr_t *p = ctx;
    char name[WEB_PTR_NAME_MAX + 1];
    if (name_ok(r->name, name) != 0) return;
    pthread_mutex_lock(&p->mu);
    int i = slot_locked(p, r->ip);
    web_ptr_ent_t *e = &p->e[i];
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->first_seen = r->first_seen;
    e->last_seen = r->last_seen;
    e->dirty = 0;
    pthread_mutex_unlock(&p->mu);
}

void web_ptr_note_persist(web_ptr_t *p, int ok, long long db_evicted) {
    pthread_mutex_lock(&p->mu);
    if (!ok) p->st.persist_errors++;
    if (db_evicted > 0) p->st.db_evictions += (unsigned long)db_evicted;
    pthread_mutex_unlock(&p->mu);
}

void web_ptr_stats(web_ptr_t *p, web_ptr_stats_t *out) {
    if (!p || !p->e) { memset(out, 0, sizeof(*out)); return; }
    pthread_mutex_lock(&p->mu);
    *out = p->st;
    out->n = p->n;
    out->cap = p->cap;
    pthread_mutex_unlock(&p->mu);
}
