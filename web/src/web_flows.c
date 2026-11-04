#include "web_flows.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_history.h"
#include "web_json.h"
#include "web_metrics.h"
#include "web_series.h"

static int decimal(const char *s, long long lo, long long hi, long long *out) {
    size_t n = strlen(s);
    if (n == 0 || n > 11) return -1;
    long long v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v < lo || v > hi) return -1;
    *out = v;
    return 0;
}

static void jw_text_or_null(web_jw_t *w, const char *s) {
    if (s && s[0]) web_jw_str(w, s);
    else web_jw_raw(w, "null");
}

static int is_smb1(const web_sdb_flow_t *f) {
    return f->proto == WEB_FP_SMB && !strcmp(f->xtext, "SMB1");
}

static int answer(web_jw_t *w, size_t *len, int *status) {
    if (w->overflow) return -1;
    *len = w->len;
    *status = 200;
    return 0;
}

/* ── /api/flows ─────────────────────────────────────────────────────── */

typedef struct {
    web_jw_t *w;
    size_t    cap;
    int       n, cut;
} fl_t;

/* A row is at most two texts of WEB_SDB_TEXT_MAX bytes escaped, six
 * counters and four more numbers of 20 digits, and the names. */
#define FLOW_JSON_MAX (2 * WEB_SDB_TEXT_MAX * WEB_JW_EXPAND + 16 * WEB_JW_EXPAND + 400)

static void flow_json(web_jw_t *w, const web_sdb_flow_t *f) {
    const web_sdb_ftab_t *t = &web_sdb_ftab[f->proto];
    web_jw_raw(w, "{\"src\":");     jw_text_or_null(w, f->src);
    web_jw_raw(w, ",\"dst\":");     jw_text_or_null(w, f->dst);
    web_jw_raw(w, ",\"counts\":[");
    for (int i = 0; i < f->ncols; i++) {
        if (i) web_jw_raw(w, ",");
        web_jw_int(w, f->n[i] > 0 ? f->n[i] : 0);
    }
    web_jw_raw(w, "],\"total\":");  web_jw_int(w, f->total > 0 ? f->total : 0);
    if (t->xint) {
        web_jw_raw(w, ",");
        web_jw_key(w, t->xint);
        if (f->has_xint) web_jw_int(w, f->xint); else web_jw_raw(w, "null");
    }
    if (t->xtext) {
        web_jw_raw(w, ",");
        web_jw_key(w, t->xtext);
        jw_text_or_null(w, f->xtext);
    }
    if (f->proto == WEB_FP_SMB)
        web_jw_raw(w, is_smb1(f) ? ",\"smb1\":true" : ",\"smb1\":false");
    web_jw_raw(w, ",\"first_seen\":"); web_jw_int(w, f->first_seen);
    web_jw_raw(w, ",\"last_seen\":");  web_jw_int(w, f->last_seen);
    web_jw_raw(w, "}");
}

static int emit_row(void *ctx, const web_sdb_flow_t *f) {
    fl_t *l = ctx;
    if (l->w->len + FLOW_JSON_MAX + 96 > l->cap) { l->cut = 1; return 1; }
    if (l->n++) web_jw_raw(l->w, ",");
    flow_json(l->w, f);
    return 0;
}

static const char *const SORTS[WEB_FLOWS_SORT_COUNT] = { "last", "total", "src",
                                                          "dst", "first" };

static int withheld(const char *v, char *body, size_t cap, size_t *len,
                    int *status) {
    if (strcmp(v, "mqtt")) return 0;
    return web_hist_error(400, "proto_withheld",
                          "mqtt_flows holds MQTT usernames; slothweb never "
                          "reads that table", body, cap, len, status) == 0
           ? 1 : -1;
}

int web_flows_route(const web_m4_t *m, const char *query, long long now_s,
                    char *body, size_t cap, size_t *len, int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    web_param_t ps[8] = {
        { "proto", "", 0 }, { "from", "", 0 }, { "to", "", 0 }, { "ip", "", 0 },
        { "sort", "", 0 }, { "limit", "", 0 }, { "offset", "", 0 },
        { "dir", "", 0 },
    };
    char err[48];
    if (web_params_parse(query, ps, 8, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    if (!ps[0].seen)
        return web_hist_error(400, "missing_proto", NULL, body, cap, len, status);
    int wh = withheld(ps[0].val, body, cap, len, status);
    if (wh) return wh > 0 ? 0 : -1;
    int proto = web_sdb_ftab_find(ps[0].val);
    if (proto < 0)
        return web_hist_error(400, "unknown_proto", NULL, body, cap, len, status);
    long long from, to, limit = WEB_FLOWS_LIMIT, offset = 0;
    const char *why;
    if (web_hist_range(ps[1].seen ? ps[1].val : NULL, ps[2].seen ? ps[2].val : NULL,
                       now_s, &from, &to, &why) != 0)
        return web_hist_error(400, why, NULL, body, cap, len, status);
    char ip[WEB_KEY_MAX + 1];
    if (ps[3].seen && web_key_ip(ps[3].val, ip) != 0)
        return web_hist_error(400, "bad_ip", NULL, body, cap, len, status);
    int sort = WEB_FLOWS_SORT_LAST;
    if (ps[4].seen) {
        for (sort = 0; sort < WEB_FLOWS_SORT_COUNT; sort++)
            if (!strcmp(SORTS[sort], ps[4].val)) break;
        if (sort == WEB_FLOWS_SORT_COUNT)
            return web_hist_error(400, "bad_sort", NULL, body, cap, len, status);
    }
    int dir = WEB_SORT_DEFAULT;
    if (ps[7].seen && (dir = web_sort_dir_find(ps[7].val)) < 0)
        return web_hist_error(400, "bad_dir", NULL, body, cap, len, status);
    if (ps[5].seen && decimal(ps[5].val, 1, WEB_FLOWS_LIMIT_MAX, &limit) != 0)
        return web_hist_error(400, "bad_limit", NULL, body, cap, len, status);
    if (ps[6].seen && decimal(ps[6].val, 0, WEB_FLOWS_OFFSET_MAX, &offset) != 0)
        return web_hist_error(400, "bad_offset", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) return o > 0 ? 0 : -1;
    const web_sdb_ftab_t *t = &web_sdb_ftab[proto];
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"proto\":");  web_jw_str(&w, t->name);
    web_jw_raw(&w, ",\"table\":");  web_jw_str(&w, t->table);
    web_jw_raw(&w, ",\"from\":");   web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");     web_jw_int(&w, to);
    web_jw_raw(&w, ",\"ip\":");     jw_text_or_null(&w, ps[3].seen ? ip : NULL);
    web_jw_raw(&w, ",\"sort\":");   web_jw_str(&w, SORTS[sort]);
    web_jw_raw(&w, ",\"limit\":");  web_jw_int(&w, limit);
    web_jw_raw(&w, ",\"offset\":"); web_jw_int(&w, offset);
    web_jw_raw(&w, ",\"per_source\":"); web_jw_raw(&w, t->dst ? "false" : "true");
    web_jw_raw(&w, ",\"columns\":[");
    for (int i = 0; t->cols[i]; i++) {
        if (i) web_jw_raw(&w, ",");
        web_jw_str(&w, t->cols[i]);
    }
    web_jw_raw(&w, "],\"withheld\":"); jw_text_or_null(&w, t->withheld);
    web_jw_raw(&w, ",\"rows\":[");
    fl_t l = { &w, cap, 0, 0 };
    int present = 0;
    long long total = 0;
    int got = web_sdb_flows(&c, proto, from, to, ps[3].seen ? ip : NULL,
                            WEB_SORT_PACK(sort, dir), limit, offset, emit_row, &l,
                            &present, &total);
    if (got < 0) return web_hist_read_failed(&c, body, cap, len, status);
    web_slothdb_close(&c);
    web_jw_raw(&w, "],\"present\":"); web_jw_raw(&w, present ? "true" : "false");
    web_jw_raw(&w, ",\"count\":");    web_jw_int(&w, l.n);
    web_jw_raw(&w, ",\"total\":");    web_jw_int(&w, total);
    web_jw_raw(&w, ",\"more\":");
    web_jw_raw(&w, l.cut || offset + l.n < total ? "true" : "false");
    /* Only when asked for: an answer without dir is as it always was. */
    if (dir != WEB_SORT_DEFAULT)
        web_jw_raw(&w, dir == WEB_SORT_ASC ? ",\"dir\":\"asc\"" : ",\"dir\":\"desc\"");
    web_jw_raw(&w, "}\n");
    return answer(&w, len, status);
}

/* ── /api/flows/graph ───────────────────────────────────────────────── */

typedef struct {
    char      id[WEB_SDB_TEXT_MAX + 1];
    long long total;
    int       keep, slot;
} node_t;

typedef struct {
    web_sdb_flow_t *e;
    int             n, max;
} pairs_t;

static int take_pair(void *ctx, const web_sdb_flow_t *f) {
    pairs_t *p = ctx;
    if (p->n >= p->max) return 1;
    p->e[p->n++] = *f;
    return 0;
}

static int node_find(node_t *nd, int n, const char *id) {
    for (int i = 0; i < n; i++)
        if (!strcmp(nd[i].id, id)) return i;
    return -1;
}

static int node_add(node_t *nd, int *n, const char *id, long long v) {
    int i = node_find(nd, *n, id);
    if (i < 0) {
        i = (*n)++;
        memset(&nd[i], 0, sizeof(nd[i]));
        snprintf(nd[i].id, sizeof(nd[i].id), "%s", id);
    }
    if (v > 0) nd[i].total += v;
    return i;
}

/* Busiest first, then by address, so the diagram's order is stable. */
static int node_cmp(const void *a, const void *b) {
    const node_t *x = a, *y = b;
    if (x->total != y->total) return x->total < y->total ? 1 : -1;
    return strcmp(x->id, y->id);
}

/* The tail both forms end with: the per-source tables, and each tab's
 * rows and total in the range for the tab strip. */
static void tabs_json(web_jw_t *w, const web_sdb_fsum_t *sum) {
    web_jw_raw(w, ",\"per_source\":[\"ldap\",\"kerb\"],\"tabs\":{");
    for (int k = 0; k < WEB_FP_KINDS; k++) {
        if (k) web_jw_raw(w, ",");
        web_jw_key(w, web_sdb_ftab[k].name);
        if (sum->tabs[k][0] < 0) { web_jw_raw(w, "null"); continue; }
        web_jw_raw(w, "{\"rows\":");   web_jw_int(w, sum->tabs[k][0]);
        web_jw_raw(w, ",\"total\":");  web_jw_int(w, sum->tabs[k][1]);
        web_jw_raw(w, "}");
    }
    web_jw_raw(w, ",\"mqtt\":\"withheld\"}}\n");
}

/* ── the matrix form (#171 V4, F11) ─────────────────────────────────── */

/* Address order: IPv4 by its four bytes, then IPv6 by its sixteen, then
 * anything else by its text, so the rows and columns read as the
 * address plan does and a subnet's members sit together. */
typedef struct {
    int           fam;        /* 0 IPv4, 1 IPv6, 2 neither */
    unsigned char b[16];
} akey_t;

static void addr_key(const char *id, akey_t *k) {
    memset(k, 0, sizeof(*k));
    if (inet_pton(AF_INET, id, k->b) == 1) k->fam = 0;
    else if (inet_pton(AF_INET6, id, k->b) == 1) k->fam = 1;
    else k->fam = 2;
}

static int addr_cmp(const char *a, const char *b) {
    akey_t x, y;
    addr_key(a, &x);
    addr_key(b, &y);
    if (x.fam != y.fam) return x.fam - y.fam;
    if (x.fam < 2) {
        int c = memcmp(x.b, y.b, x.fam ? 16 : 4);
        if (c) return c;
    }
    return strcmp(a, b);
}

static int node_addr_cmp(const void *a, const void *b) {
    return addr_cmp(((const node_t *)a)->id, ((const node_t *)b)->id);
}

/* The subnet an address is grouped in: its /24 for IPv4, its /64 for
 * IPv6, and the text itself for anything else (one row, its own group).
 * out holds WEB_SDB_TEXT_MAX + 8. */
static void group_of(const char *id, char *out, size_t sz) {
    akey_t k;
    addr_key(id, &k);
    char a[INET6_ADDRSTRLEN];
    if (k.fam == 0) {
        k.b[3] = 0;
        if (inet_ntop(AF_INET, k.b, a, sizeof(a))) { snprintf(out, sz, "%s/24", a); return; }
    } else if (k.fam == 1) {
        memset(k.b + 8, 0, 8);
        if (inet_ntop(AF_INET6, k.b, a, sizeof(a))) { snprintf(out, sz, "%s/64", a); return; }
    }
    snprintf(out, sz, "%s", id);
}

typedef struct {
    int       s, d;
    long long total;
    unsigned  protos;         /* bit per WEB_FP_* */
    int       smb1;
} mcell_t;

static int mcell_cmp(const void *a, const void *b) {
    const mcell_t *x = a, *y = b;
    if (x->s != y->s) return x->s - y->s;
    return x->d - y->d;
}

static int node_index(const node_t *nd, int n, const char *id) {
    for (int i = 0; i < n; i++) if (!strcmp(nd[i].id, id)) return i;
    return -1;
}

/* The same pairs as the chord, drawn as a source by destination matrix:
 * no endpoint folded by rank (only the pairs past `edges` are), both
 * axes in address order with each endpoint's subnet group, and the
 * cells merged by pair, each with its total, the protocols it carries
 * and whether one was an SMB1 session. */
static int matrix_answer(const pairs_t *p, const web_sdb_fsum_t *sum, long long from,
                         long long to, long long ne, char *body, size_t cap,
                         size_t *len, int *status) {
    node_t *src = calloc((size_t)p->n + 1, sizeof(node_t));
    node_t *dst = calloc((size_t)p->n + 1, sizeof(node_t));
    node_t *all = calloc(2 * (size_t)p->n + 1, sizeof(node_t));
    mcell_t *cell = calloc((size_t)p->n + 1, sizeof(mcell_t));
    if (!src || !dst || !all || !cell) { free(src); free(dst); free(all); free(cell); return -1; }
    int ns = 0, nd = 0, na = 0, nc = 0;
    long long shown_total = 0, max = 0;
    for (int i = 0; i < p->n; i++) {
        long long v = p->e[i].total > 0 ? p->e[i].total : 0;
        node_add(src, &ns, p->e[i].src, v);
        node_add(dst, &nd, p->e[i].dst, v);
        node_add(all, &na, p->e[i].src, v);
        node_add(all, &na, p->e[i].dst, v);
        shown_total += v;
    }
    qsort(src, (size_t)ns, sizeof(*src), node_addr_cmp);
    qsort(dst, (size_t)nd, sizeof(*dst), node_addr_cmp);
    qsort(all, (size_t)na, sizeof(*all), node_addr_cmp);
    /* Groups in address order over both axes: the endpoints sorted, a
     * new group wherever the subnet changes. slot holds an endpoint's. */
    char (*grp)[WEB_SDB_TEXT_MAX + 8] = calloc((size_t)na + 1, sizeof(*grp));
    if (!grp) { free(src); free(dst); free(all); free(cell); return -1; }
    int ng = 0;
    for (int i = 0; i < na; i++) {
        char g[WEB_SDB_TEXT_MAX + 8];
        group_of(all[i].id, g, sizeof(g));
        if (!ng || strcmp(grp[ng - 1], g) != 0) snprintf(grp[ng++], sizeof(grp[0]), "%s", g);
        all[i].slot = ng - 1;
    }
    for (int i = 0; i < p->n; i++) {
        int s = node_index(src, ns, p->e[i].src), d = node_index(dst, nd, p->e[i].dst), k;
        for (k = 0; k < nc; k++) if (cell[k].s == s && cell[k].d == d) break;
        if (k == nc) { cell[nc].s = s; cell[nc].d = d; nc++; }
        cell[k].total += p->e[i].total > 0 ? p->e[i].total : 0;
        cell[k].protos |= 1u << p->e[i].proto;
        if (is_smb1(&p->e[i])) cell[k].smb1 = 1;
        if (cell[k].total > max) max = cell[k].total;
    }
    qsort(cell, (size_t)nc, sizeof(*cell), mcell_cmp);
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"from\":");  web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");    web_jw_int(&w, to);
    web_jw_raw(&w, ",\"form\":\"matrix\",\"max_edges\":"); web_jw_int(&w, ne);
    web_jw_raw(&w, ",\"groups\":[");
    for (int i = 0; i < ng; i++) {
        web_jw_raw(&w, i ? ",{\"id\":" : "{\"id\":");
        web_jw_str(&w, grp[i]);
        web_jw_raw(&w, "}");
    }
    const node_t *ax[2] = { src, dst };
    const int axn[2] = { ns, nd };
    static const char *const AXK[2] = { "],\"srcs\":[", "],\"dsts\":[" };
    for (int a = 0; a < 2; a++) {
        web_jw_raw(&w, AXK[a]);
        for (int i = 0; i < axn[a]; i++) {
            int gi = all[node_index(all, na, ax[a][i].id)].slot;
            web_jw_raw(&w, i ? ",{\"id\":" : "{\"id\":");
            web_jw_str(&w, ax[a][i].id);
            web_jw_raw(&w, ",\"group\":"); web_jw_int(&w, gi);
            web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, ax[a][i].total);
            web_jw_raw(&w, "}");
        }
    }
    web_jw_raw(&w, "],\"cells\":[");
    for (int i = 0; i < nc; i++) {
        web_jw_raw(&w, i ? ",{\"s\":" : "{\"s\":");
        web_jw_int(&w, cell[i].s);
        web_jw_raw(&w, ",\"d\":");     web_jw_int(&w, cell[i].d);
        web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, cell[i].total);
        web_jw_raw(&w, ",\"protos\":[");
        int np = 0;
        for (int k = 0; k < WEB_FP_KINDS; k++) {
            if (!(cell[i].protos & (1u << k))) continue;
            if (np++) web_jw_raw(&w, ",");
            web_jw_str(&w, web_sdb_ftab[k].name);
        }
        web_jw_raw(&w, "]");
        if (cell[i].smb1) web_jw_raw(&w, ",\"smb1\":true");
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"max\":"); web_jw_int(&w, max);
    web_jw_raw(&w, ",\"fold\":{\"pairs\":"); web_jw_int(&w, sum->pair_rows);
    web_jw_raw(&w, ",\"pairs_shown\":");  web_jw_int(&w, p->n);
    web_jw_raw(&w, ",\"pairs_folded\":"); web_jw_int(&w, sum->pair_rows - p->n);
    web_jw_raw(&w, ",\"flows\":");        web_jw_int(&w, sum->pair_total);
    web_jw_raw(&w, ",\"flows_shown\":");  web_jw_int(&w, shown_total);
    web_jw_raw(&w, ",\"flows_folded\":"); web_jw_int(&w, sum->pair_total - shown_total);
    web_jw_raw(&w, ",\"nodes\":");        web_jw_int(&w, sum->nodes);
    web_jw_raw(&w, ",\"nodes_shown\":");  web_jw_int(&w, na);
    web_jw_raw(&w, ",\"nodes_folded\":"); web_jw_int(&w, sum->nodes - na);
    web_jw_raw(&w, "}");
    tabs_json(&w, sum);
    free(src); free(dst); free(all); free(cell); free(grp);
    return answer(&w, len, status);
}

int web_flows_graph_route(const web_m4_t *m, const char *query,
                          long long now_s, char *body, size_t cap,
                          size_t *len, int *status) {
    if (!web_hist_configured(m)) return web_hist_no_db(body, cap, len, status);
    web_param_t ps[5] = { { "from", "", 0 }, { "to", "", 0 }, { "nodes", "", 0 },
                          { "edges", "", 0 }, { "form", "", 0 } };
    char err[48];
    if (web_params_parse(query, ps, 5, err, sizeof(err)) != 0)
        return web_hist_error(400, err, NULL, body, cap, len, status);
    int matrix = 0;
    if (ps[4].seen) {
        if (!strcmp(ps[4].val, "matrix")) matrix = 1;
        else if (strcmp(ps[4].val, "chord") != 0)
            return web_hist_error(400, "bad_form", NULL, body, cap, len, status);
    }
    /* The matrix folds no endpoint by rank, so a node count is the
     * chord's alone: said, rather than quietly ignored. */
    if (matrix && ps[2].seen)
        return web_hist_error(400, "nodes_not_in_matrix", NULL, body, cap, len, status);
    long long from, to, nn = WEB_FLOWS_NODES, ne = WEB_FLOWS_EDGES;
    const char *why;
    if (web_hist_range(ps[0].seen ? ps[0].val : NULL, ps[1].seen ? ps[1].val : NULL,
                       now_s, &from, &to, &why) != 0)
        return web_hist_error(400, why, NULL, body, cap, len, status);
    if (ps[2].seen && decimal(ps[2].val, WEB_FLOWS_NODES_MIN, WEB_FLOWS_NODES_MAX, &nn) != 0)
        return web_hist_error(400, "bad_nodes", NULL, body, cap, len, status);
    if (ps[3].seen && decimal(ps[3].val, 1, WEB_FLOWS_EDGES_MAX, &ne) != 0)
        return web_hist_error(400, "bad_edges", NULL, body, cap, len, status);
    WEB_M4_CHECKED(m, len, status);
    pairs_t p = { calloc(WEB_FLOWS_EDGES_MAX, sizeof(web_sdb_flow_t)), 0, (int)ne };
    node_t *nd = calloc(2 * WEB_FLOWS_EDGES_MAX, sizeof(node_t));
    if (!p.e || !nd) { free(p.e); free(nd); return -1; }
    web_sdb_conn_t c;
    int o = web_hist_open(m, &c, now_s, body, cap, len, status);
    if (o) { free(p.e); free(nd); return o > 0 ? 0 : -1; }
    web_sdb_fsum_t sum;
    if (web_sdb_flow_pairs(&c, from, to, (int)ne, take_pair, &p, &sum) != 0) {
        free(p.e); free(nd);
        return web_hist_read_failed(&c, body, cap, len, status);
    }
    web_slothdb_close(&c);
    if (matrix) {
        int rc = matrix_answer(&p, &sum, from, to, ne, body, cap, len, status);
        free(p.e);
        free(nd);
        return rc;
    }

    /* The endpoints of the pairs read, weighted by their totals; the
     * busiest nn kept. */
    int n = 0;
    for (int i = 0; i < p.n; i++) {
        node_add(nd, &n, p.e[i].src, p.e[i].total);
        node_add(nd, &n, p.e[i].dst, p.e[i].total);
    }
    qsort(nd, (size_t)n, sizeof(*nd), node_cmp);
    int kept = 0;
    for (int i = 0; i < n; i++) {
        nd[i].keep = i < nn;
        nd[i].slot = nd[i].keep ? kept++ : -1;
    }
    web_jw_t w;
    web_jw_init(&w, body, cap);
    web_jw_raw(&w, "{\"from\":");  web_jw_int(&w, from);
    web_jw_raw(&w, ",\"to\":");    web_jw_int(&w, to);
    web_jw_raw(&w, ",\"max_nodes\":"); web_jw_int(&w, nn);
    web_jw_raw(&w, ",\"max_edges\":"); web_jw_int(&w, ne);
    web_jw_raw(&w, ",\"nodes\":[");
    for (int i = 0; i < kept; i++) {
        web_jw_raw(&w, i ? ",{\"id\":" : "{\"id\":");
        web_jw_str(&w, nd[i].id);
        web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, nd[i].total);
        web_jw_raw(&w, "}");
    }
    web_jw_raw(&w, "],\"edges\":[");
    int shown = 0;
    long long shown_total = 0;
    for (int i = 0; i < p.n; i++) {
        int a = node_find(nd, n, p.e[i].src), b = node_find(nd, n, p.e[i].dst);
        if (a < 0 || b < 0 || !nd[a].keep || !nd[b].keep) continue;
        web_jw_raw(&w, shown++ ? ",{\"s\":" : "{\"s\":");
        web_jw_int(&w, nd[a].slot);
        web_jw_raw(&w, ",\"d\":");     web_jw_int(&w, nd[b].slot);
        web_jw_raw(&w, ",\"proto\":"); web_jw_str(&w, web_sdb_ftab[p.e[i].proto].name);
        web_jw_raw(&w, ",\"total\":"); web_jw_int(&w, p.e[i].total > 0 ? p.e[i].total : 0);
        if (is_smb1(&p.e[i])) web_jw_raw(&w, ",\"smb1\":true");
        web_jw_raw(&w, "}");
        if (p.e[i].total > 0) shown_total += p.e[i].total;
    }
    web_jw_raw(&w, "],\"fold\":{\"pairs\":");  web_jw_int(&w, sum.pair_rows);
    web_jw_raw(&w, ",\"pairs_shown\":");  web_jw_int(&w, shown);
    web_jw_raw(&w, ",\"pairs_folded\":"); web_jw_int(&w, sum.pair_rows - shown);
    web_jw_raw(&w, ",\"flows\":");        web_jw_int(&w, sum.pair_total);
    web_jw_raw(&w, ",\"flows_shown\":");  web_jw_int(&w, shown_total);
    web_jw_raw(&w, ",\"flows_folded\":"); web_jw_int(&w, sum.pair_total - shown_total);
    web_jw_raw(&w, ",\"nodes\":");        web_jw_int(&w, sum.nodes);
    web_jw_raw(&w, ",\"nodes_shown\":");  web_jw_int(&w, kept);
    web_jw_raw(&w, ",\"nodes_folded\":"); web_jw_int(&w, sum.nodes - kept);
    web_jw_raw(&w, "}");
    tabs_json(&w, &sum);
    free(p.e);
    free(nd);
    return answer(&w, len, status);
}
