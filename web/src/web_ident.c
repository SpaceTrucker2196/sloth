#include "web_ident.h"

#include "web_ptr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_json.h"
#include "web_metrics.h"

static unsigned hash_s(const char *k) {
    unsigned h = 5381;
    for (const unsigned char *p = (const unsigned char *)k; *p; p++)
        h = h * 33u + *p;
    return h;
}

static int table_heads(int cap, int **head, int *nhead) {
    *nhead = 1;
    while (*nhead < cap * 2) *nhead <<= 1;
    *head = malloc((size_t)*nhead * sizeof(**head));
    if (!*head) return -1;
    for (int i = 0; i < *nhead; i++) (*head)[i] = -1;
    return 0;
}

int web_ident_init(web_ident_t *id, int mac_cap, int ip_cap) {
    memset(id, 0, sizeof(*id));
    if (mac_cap < 1) mac_cap = 1;
    if (ip_cap < 1) ip_cap = 1;
    pthread_mutex_init(&id->mu, NULL);
    id->mac_cap = mac_cap;
    id->ip_cap = ip_cap;
    id->mac = calloc((size_t)mac_cap, sizeof(*id->mac));
    id->ip = calloc((size_t)ip_cap, sizeof(*id->ip));
    id->q = calloc(WEB_ID_QSLOTS, sizeof(*id->q));
    if (!id->mac || !id->ip || !id->q ||
        table_heads(mac_cap, &id->mac_head, &id->mac_nhead) != 0 ||
        table_heads(ip_cap, &id->ip_head, &id->ip_nhead) != 0) {
        web_ident_destroy(id);
        return -1;
    }
    return 0;
}

void web_ident_destroy(web_ident_t *id) {
    free(id->mac); free(id->ip); free(id->q);
    free(id->mac_head); free(id->ip_head);
    id->mac = NULL; id->ip = NULL; id->q = NULL;
    id->mac_head = id->ip_head = NULL;
}

/* ── the two tables ──────────────────────────────────────────────────── */

static web_id_mac_t *mac_get(web_ident_t *id, const char *mac, long long now) {
    unsigned h = hash_s(mac) & (unsigned)(id->mac_nhead - 1);
    for (int i = id->mac_head[h]; i >= 0; i = id->mac[i].next)
        if (!strcmp(id->mac[i].mac, mac)) {
            id->mac[i].last_seen = now;
            return &id->mac[i];
        }
    int slot = -1;
    if (id->mac_n < id->mac_cap) {
        for (int i = 0; i < id->mac_cap; i++)
            if (!id->mac[i].used) { slot = i; break; }
        id->mac_n++;
    } else {
        slot = 0;
        for (int i = 1; i < id->mac_cap; i++)
            if (id->mac[i].last_seen < id->mac[slot].last_seen) slot = i;
        unsigned oh = hash_s(id->mac[slot].mac) & (unsigned)(id->mac_nhead - 1);
        int *pp = &id->mac_head[oh];
        while (*pp >= 0 && *pp != slot) pp = &id->mac[*pp].next;
        if (*pp == slot) *pp = id->mac[slot].next;
        id->st.mac_evictions++;
    }
    web_id_mac_t *e = &id->mac[slot];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    snprintf(e->mac, sizeof(e->mac), "%s", mac);
    e->last_seen = now;
    e->first_seen = -1;
    e->ip_t = -1;
    e->dhcp.t = -1;
    /* The locally administered bit, which is sloth's mac_random. */
    unsigned o = (unsigned)strtoul(mac, NULL, 16);
    e->random = (o & 0x02) ? 1 : 0;
    e->next = id->mac_head[h];
    id->mac_head[h] = slot;
    return e;
}

static web_id_ip_t *ip_get(web_ident_t *id, const char *ip, long long now) {
    unsigned h = hash_s(ip) & (unsigned)(id->ip_nhead - 1);
    for (int i = id->ip_head[h]; i >= 0; i = id->ip[i].next)
        if (!strcmp(id->ip[i].ip, ip)) {
            id->ip[i].last_seen = now;
            return &id->ip[i];
        }
    int slot = -1;
    if (id->ip_n < id->ip_cap) {
        for (int i = 0; i < id->ip_cap; i++)
            if (!id->ip[i].used) { slot = i; break; }
        id->ip_n++;
    } else {
        slot = 0;
        for (int i = 1; i < id->ip_cap; i++)
            if (id->ip[i].last_seen < id->ip[slot].last_seen) slot = i;
        unsigned oh = hash_s(id->ip[slot].ip) & (unsigned)(id->ip_nhead - 1);
        int *pp = &id->ip_head[oh];
        while (*pp >= 0 && *pp != slot) pp = &id->ip[*pp].next;
        if (*pp == slot) *pp = id->ip[slot].next;
        id->st.ip_evictions++;
    }
    web_id_ip_t *e = &id->ip[slot];
    memset(e, 0, sizeof(*e));
    e->used = 1;
    snprintf(e->ip, sizeof(e->ip), "%s", ip);
    e->last_seen = now;
    e->mac_t = -1;
    for (int s = 0; s < WEB_ID_SRC_COUNT; s++) e->name[s].t = -1;
    for (int k = 0; k < WEB_ID_DNS_MINUTES; k++) e->dns_t[k] = -1;
    e->next = id->ip_head[h];
    id->ip_head[h] = slot;
    return e;
}

static void set_name(web_id_name_t *n, const char *s, size_t max, long long now) {
    if (!s || !s[0]) return;
    web_utf8_copy(n->name, max, s);
    n->t = now;
}

static void bind(web_ident_t *id, const char *mac, const char *ip, long long now) {
    web_id_mac_t *m = mac_get(id, mac, now);
    snprintf(m->ip, sizeof(m->ip), "%s", ip);
    m->ip_t = now;
    web_id_ip_t *p = ip_get(id, ip, now);
    snprintf(p->mac, sizeof(p->mac), "%s", mac);
    p->mac_t = now;
}

static void first(web_ident_t *id, const char *macs, long long fs,
                  const char *src, long long now) {
    char mac[WEB_KEY_MAX + 1];
    if (web_key_mac(macs, mac) != 0) return;
    web_id_mac_t *m = mac_get(id, mac, now);
    if (fs <= 0) return;
    if (m->first_seen < 0 || fs < m->first_seen) {
        m->first_seen = fs;
        snprintf(m->first_src, sizeof(m->first_src), "%s", src);
    }
}

/* ── DNS by client ───────────────────────────────────────────────────── */

static uint64_t qhash(const char *q) {
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)q; *p; p++) {
        unsigned c = *p;
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h ? h : 1;
}

static web_id_ip_t *dns_row(web_ident_t *id, const char *ip, long long now,
                            int *slot) {
    web_id_ip_t *p = ip_get(id, ip, now);
    long long minute = now - now % 60;
    int k = (int)((now / 60) % WEB_ID_DNS_MINUTES);
    if (k < 0) k += WEB_ID_DNS_MINUTES;
    if (p->dns_t[k] != minute) {
        p->dns_t[k] = minute;
        p->dns_q[k] = p->dns_nx[k] = 0;
    }
    *slot = k;
    return p;
}

static void dns_record(web_ident_t *id, const web_jrec_t *r, long long now) {
    char ip[WEB_KEY_MAX + 1];
    if (web_key_ip(web_jl_str(r, "src"), ip) != 0) return;
    const char *qn = web_jl_str(r, "qname");
    if (!qn || !qn[0]) return;
    uint64_t h = qhash(qn);
    web_id_query_t *s = &id->q[h & (WEB_ID_QSLOTS - 1)];
    long long resp = web_jl_int(r, "is_resp", -1);
    if (resp == 0) {
        int k;
        web_id_ip_t *p = dns_row(id, ip, now, &k);
        if (p->dns_q[k] < UINT32_MAX) p->dns_q[k]++;
        if (s->h && s->h != h && now - s->t <= WEB_ID_DNS_MATCH_S)
            id->st.query_overwrites++;
        s->h = h;
        s->t = now;
        snprintf(s->client, sizeof(s->client), "%s", ip);
        return;
    }
    const char *ans = web_jl_str(r, "answer");
    if (resp != 1 || !ans || strcmp(ans, "NXDOMAIN")) return;
    if (s->h != h || now - s->t > WEB_ID_DNS_MATCH_S || now < s->t) {
        id->st.dns_unmatched++;
        return;
    }
    int k;
    web_id_ip_t *p = dns_row(id, s->client, now, &k);
    if (p->dns_nx[k] < UINT32_MAX) p->dns_nx[k]++;
    id->st.dns_matched++;
    s->h = 0;
}

/* ── records ─────────────────────────────────────────────────────────── */

void web_ident_record(web_ident_t *id, const web_jrec_t *r, long long now) {
    const char *t = web_jl_str(r, "type");
    if (!t || !id) return;
    char mac[WEB_KEY_MAX + 1], ip[WEB_KEY_MAX + 1];
    pthread_mutex_lock(&id->mu);
    if (!strcmp(t, "probe_client")) {
        first(id, web_jl_str(r, "mac"), web_jl_int(r, "first_seen", -1),
              "probe_client", now);
    } else if (!strcmp(t, "pnl_client")) {
        first(id, web_jl_str(r, "mac"), web_jl_int(r, "first_seen", -1),
              "pnl_client", now);
    } else if (!strcmp(t, "assoc")) {
        first(id, web_jl_str(r, "sta_mac"), web_jl_int(r, "first_seen", -1),
              "assoc", now);
    } else if (!strcmp(t, "arp")) {
        if (web_key_mac(web_jl_str(r, "mac"), mac) == 0 &&
            web_key_ip(web_jl_str(r, "ip"), ip) == 0)
            bind(id, mac, ip, now);
    } else if (!strcmp(t, "device")) {
        if (web_key_mac(web_jl_str(r, "mac"), mac) == 0) {
            if (web_key_ip(web_jl_str(r, "ip"), ip) == 0) bind(id, mac, ip, now);
            web_id_mac_t *m = mac_get(id, mac, now);
            set_name(&m->dhcp, web_jl_str(r, "hostname"), WEB_ID_NAME_MAX, now);
        }
    } else if (!strcmp(t, "dhcp_lease")) {
        if (web_key_ip(web_jl_str(r, "ip"), ip) == 0) {
            const char *hn = web_jl_str(r, "hostname");
            if (hn && hn[0])
                set_name(&ip_get(id, ip, now)->name[WEB_ID_SRC_DHCP], hn,
                         WEB_ID_NAME_MAX, now);
        }
    } else if (!strcmp(t, "mdns_service")) {
        if (web_key_ip(web_jl_str(r, "ip"), ip) == 0) {
            const char *hn = web_jl_str(r, "host");
            if (hn && hn[0])
                set_name(&ip_get(id, ip, now)->name[WEB_ID_SRC_MDNS], hn,
                         WEB_ID_NAME_MAX, now);
        }
    } else if (!strcmp(t, "nbns_name")) {
        long long sfx = web_jl_int(r, "suffix", -1);
        if ((sfx == 0x00 || sfx == 0x20) &&
            web_key_ip(web_jl_str(r, "ip"), ip) == 0) {
            const char *nm = web_jl_str(r, "name");
            if (nm && nm[0])
                set_name(&ip_get(id, ip, now)->name[WEB_ID_SRC_NBNS], nm,
                         WEB_ID_NBNS_MAX, now);
        }
    } else if (!strcmp(t, "dns")) {
        dns_record(id, r, now);
        if (id->ptr)
            web_ptr_record(id->ptr, web_jl_str(r, "qtype"),
                           web_jl_int(r, "is_resp", -1),
                           web_jl_str(r, "qname"), web_jl_str(r, "answer"),
                           now);
    }
    pthread_mutex_unlock(&id->mu);
}

void web_ident_stats(web_ident_t *id, web_id_stats_t *out) {
    pthread_mutex_lock(&id->mu);
    *out = id->st;
    out->macs = id->mac_n;
    out->mac_cap = id->mac_cap;
    out->ips = id->ip_n;
    out->ip_cap = id->ip_cap;
    pthread_mutex_unlock(&id->mu);
}

void web_ident_norm(const char *name, char *out) {
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)name;
         *p && o < WEB_ID_NAME_MAX; p++) {
        unsigned c = *p;
        if (c == '.') break;
        if (c >= 'A' && c <= 'Z') c += 32;
        out[o++] = (char)c;
    }
    /* NetBIOS pads with spaces. */
    while (o > 0 && out[o - 1] == ' ') o--;
    out[o] = '\0';
}

const char *web_ident_src_name(int src) {
    switch (src) {
    case WEB_ID_SRC_DHCP: return "dhcp";
    case WEB_ID_SRC_MDNS: return "mdns";
    case WEB_ID_SRC_NBNS: return "nbns";
    default:              return "?";
    }
}

/* ── readers ─────────────────────────────────────────────────────────── */

static int fresh(long long t, long long now) {
    return t >= 0 && now - t <= WEB_ID_TTL_S;
}

int web_ident_firsts(web_ident_t *id, long long since, web_id_new_t *out,
                     int max) {
    int n = 0;
    pthread_mutex_lock(&id->mu);
    for (int i = 0; i < id->mac_cap; i++) {
        const web_id_mac_t *m = &id->mac[i];
        if (!m->used || m->random || m->first_seen < 0 ||
            m->first_seen < since)
            continue;
        if (n < max) {
            snprintf(out[n].mac, sizeof(out[n].mac), "%s", m->mac);
            out[n].first_seen = m->first_seen;
            snprintf(out[n].src, sizeof(out[n].src), "%s", m->first_src);
        }
        n++;
    }
    pthread_mutex_unlock(&id->mu);
    return n;
}

static web_id_ip_t *ip_find(web_ident_t *id, const char *ip) {
    unsigned h = hash_s(ip) & (unsigned)(id->ip_nhead - 1);
    for (int i = id->ip_head[h]; i >= 0; i = id->ip[i].next)
        if (!strcmp(id->ip[i].ip, ip)) return &id->ip[i];
    return NULL;
}

/* One row into out[*n] while there is room; counted either way. A name
 * with nothing left in normal form is not a row. */
static void put_named(web_id_named_t *out, int max, int *n,
                      const web_id_mac_t *m, const char *name, int src) {
    char norm[WEB_ID_NAME_MAX + 1];
    web_ident_norm(name, norm);
    if (!norm[0]) return;
    if (*n < max) {
        web_id_named_t *o = &out[*n];
        snprintf(o->mac, sizeof(o->mac), "%s", m->mac);
        snprintf(o->name, sizeof(o->name), "%s", name);
        memcpy(o->norm, norm, sizeof(o->norm));
        o->src = src;
        o->random = m->random;
    }
    (*n)++;
}

int web_ident_named(web_ident_t *id, long long now, web_id_named_t *out,
                    int max) {
    int n = 0;
    pthread_mutex_lock(&id->mu);
    for (int i = 0; i < id->mac_cap; i++) {
        const web_id_mac_t *m = &id->mac[i];
        if (!m->used) continue;
        if (fresh(m->dhcp.t, now))
            put_named(out, max, &n, m, m->dhcp.name, WEB_ID_SRC_DHCP);
        if (!fresh(m->ip_t, now) || !m->ip[0]) continue;
        const web_id_ip_t *p = ip_find(id, m->ip);
        if (!p || strcmp(p->mac, m->mac) || !fresh(p->mac_t, now)) continue;
        for (int s = WEB_ID_SRC_DHCP; s <= WEB_ID_SRC_MDNS; s++) {
            if (!fresh(p->name[s].t, now)) continue;
            /* The device's own copy of its lease hostname is the same
             * name from the same source: once is enough. */
            if (s == WEB_ID_SRC_DHCP && fresh(m->dhcp.t, now) &&
                !strcmp(m->dhcp.name, p->name[s].name))
                continue;
            put_named(out, max, &n, m, p->name[s].name, s);
        }
    }
    pthread_mutex_unlock(&id->mu);
    return n;
}

int web_ident_ip_names(web_ident_t *id, long long now, web_id_names_t *out,
                       int max) {
    int n = 0;
    pthread_mutex_lock(&id->mu);
    for (int i = 0; i < id->ip_cap; i++) {
        const web_id_ip_t *p = &id->ip[i];
        if (!p->used) continue;
        int have = 0;
        for (int s = 0; s < WEB_ID_SRC_COUNT; s++)
            if (fresh(p->name[s].t, now)) have++;
        if (have < 2) continue;
        if (n < max) {
            snprintf(out[n].ip, sizeof(out[n].ip), "%s", p->ip);
            for (int s = 0; s < WEB_ID_SRC_COUNT; s++)
                snprintf(out[n].name[s], sizeof(out[n].name[s]), "%s",
                         fresh(p->name[s].t, now) ? p->name[s].name : "");
        }
        n++;
    }
    pthread_mutex_unlock(&id->mu);
    return n;
}

int web_ident_dns(web_ident_t *id, long long to, web_id_dns_t *out, int max) {
    int n = 0;
    long long from = to - (long long)WEB_ID_DNS_MINUTES * 60;
    pthread_mutex_lock(&id->mu);
    for (int i = 0; i < id->ip_cap; i++) {
        const web_id_ip_t *p = &id->ip[i];
        if (!p->used) continue;
        uint32_t q = 0, nx = 0;
        for (int k = 0; k < WEB_ID_DNS_MINUTES; k++) {
            if (p->dns_t[k] < from || p->dns_t[k] >= to) continue;
            q += p->dns_q[k];
            nx += p->dns_nx[k];
        }
        if (!q && !nx) continue;
        if (n < max) {
            snprintf(out[n].ip, sizeof(out[n].ip), "%s", p->ip);
            out[n].q = q;
            out[n].nx = nx;
        }
        n++;
    }
    pthread_mutex_unlock(&id->mu);
    return n;
}

void web_ident_set_ptr(web_ident_t *id, struct web_ptr *p) {
    pthread_mutex_lock(&id->mu);
    id->ptr = p;
    pthread_mutex_unlock(&id->mu);
}

static const web_id_mac_t *mac_find(web_ident_t *id, const char *mac) {
    unsigned h = hash_s(mac) & (unsigned)(id->mac_nhead - 1);
    for (int i = id->mac_head[h]; i >= 0; i = id->mac[i].next)
        if (!strcmp(id->mac[i].mac, mac)) return &id->mac[i];
    return NULL;
}

int web_ident_ip_info(web_ident_t *id, const char *ip, long long now_s,
                      char *mac, web_id_name_t names[WEB_ID_SRC_COUNT]) {
    mac[0] = '\0';
    for (int s = 0; s < WEB_ID_SRC_COUNT; s++) {
        names[s].name[0] = '\0';
        names[s].t = -1;
    }
    if (!id || !ip) return 0;
    pthread_mutex_lock(&id->mu);
    const web_id_ip_t *p = ip_find(id, ip);
    if (p) {
        snprintf(mac, WEB_KEY_MAX + 1, "%s", p->mac);
        for (int s = 0; s < WEB_ID_SRC_COUNT; s++)
            if (fresh(p->name[s].t, now_s)) names[s] = p->name[s];
    }
    pthread_mutex_unlock(&id->mu);
    return p != NULL;
}

int web_ident_mac_info(web_ident_t *id, const char *mac, long long now_s,
                       char *ip, web_id_name_t *dhcp, long long *first_seen) {
    ip[0] = '\0';
    dhcp->name[0] = '\0';
    dhcp->t = -1;
    *first_seen = -1;
    if (!id || !mac) return 0;
    pthread_mutex_lock(&id->mu);
    const web_id_mac_t *m = mac_find(id, mac);
    if (m) {
        snprintf(ip, WEB_KEY_MAX + 1, "%s", m->ip);
        if (fresh(m->dhcp.t, now_s)) *dhcp = m->dhcp;
        *first_seen = m->first_seen;
    }
    pthread_mutex_unlock(&id->mu);
    return m != NULL;
}
